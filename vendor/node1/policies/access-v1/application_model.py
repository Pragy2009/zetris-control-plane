"""Validate lab-inspired policy data and compile its conditions into pinned Rego.

This is a build-time compiler, not a second authorization engine. Live decisions
stay in OPA. Resource kinds remain constrained by the gateway route registry.
"""
import copy
import ipaddress
import json
import math
import re

KINDS = {"workspace", "developer_app", "admin_console", "diagnostics", "file",
         "document", "export", "tenant_users", "policy", "session",
         "simulation_control", "simulation_probe"}
MAX_SESSION_SECONDS = 86400  # Also bounds gateway replay-state retention.
FIELDS = {
    "identity.subject": ("input.principal.subject", "string", []),
    "identity.roles": ("input.principal.roles", "list", []),
    "identity.kind": ("input.principal.kind", "string", []),
    "identity.acr": ("input.principal.acr", "string", []),
    "identity.auth_age_seconds": ("input.now - session_anchor", "number", ["session_anchor > 0"]),
    "resource.action": ("input.resource.action", "string", []),
    "risk.level": ("input.risk.level", "string", []),
    "risk.score": ("input.risk.score", "number", []),
    "risk.age_seconds": ("input.now - input.risk.updated_at", "number", ["input.risk.updated_at > 0"]),
    "context.source_ip": ("input.context.source_ip", "string", []),
    "context.client_type": ("input.context.client_type", "string", []),
    "device.managed": ("input.device.managed", "boolean", ["verified_device"]),
    "device.age_seconds": ("input.now - input.device.observed_at", "number", ["verified_device"]),
}


def strict_load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("non-finite JSON number: " + value)
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique, parse_constant=invalid)


def hostname(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("invalid application hostname")
    value = value.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")):
            raise ValueError("application hostname must be ASCII DNS or IP")
    return value


def selector(value, app_host):
    if not isinstance(value, str):
        raise ValueError("application destination must be a string")
    if value == "$APP_HOST":
        value = app_host
    if "/" in value:
        network = ipaddress.ip_network(value, strict=True)
        return {"kind":"cidr", "value":str(network), "rank":1000000 + network.prefixlen * 1000}
    if value.startswith("*."):
        suffix = hostname(value[2:])
        try:
            ipaddress.ip_address(suffix)
        except ValueError:
            return {"kind":"wildcard", "value":"." + suffix, "rank":2000000 + len(suffix.split(".")) * 1000}
        raise ValueError("wildcard requires a DNS suffix")
    return {"kind":"exact", "value":hostname(value), "rank":3000000}


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,79}", value):
        raise ValueError("invalid policy identifier")
    return value


def string_list(values, *, nonempty=False):
    if (not isinstance(values, list) or len(values) > 256 or (nonempty and not values)
            or any(not isinstance(v, str) or not v for v in values)
            or len(set(values)) != len(values)):
        raise ValueError("expected unique nonempty string entries")
    return values


def timeouts(value):
    if (not isinstance(value, dict) or set(value) != {"reauth_seconds", "idle_seconds", "max_session_seconds"}
            or any(type(v) is not int or not 1 <= v <= MAX_SESSION_SECONDS for v in value.values())):
        raise ValueError("timeouts must contain three integer durations in 1..86400 seconds")


def field_spec(name):
    if not isinstance(name, str):
        raise ValueError("condition field must be a string")
    if name in FIELDS:
        return FIELDS[name]
    if isinstance(name, str) and re.fullmatch(r"device\.checks\.[A-Za-z0-9_-]{1,80}", name):
        key = name.split(".")[-1]
        return "input.device.checks[" + json.dumps(key) + "]", "boolean", ["verified_device"]
    raise ValueError("unsupported/untrusted condition field: " + str(name))


class Compiler:
    def __init__(self):
        self.rules = []
        self.nodes = 0

    def condition(self, node, depth=0):
        if depth > 8 or not isinstance(node, dict) or self.nodes >= 2048:
            raise ValueError("condition nesting/size exceeds limit")
        index = self.nodes
        self.nodes += 1
        name = "application_condition_" + str(index)
        if set(node) in ({"all"}, {"any"}):
            children = next(iter(node.values()))
            if not isinstance(children, list) or not 1 <= len(children) <= 64:
                raise ValueError("condition group requires 1..64 children")
            compiled = [self.condition(child, depth+1) for child in children]
            if "all" in node:
                self.rules.append(name + " { " + "; ".join(c[0] for c in compiled) + " }")
            else:
                self.rules.extend(name + " { " + c[0] + " }" for c in compiled)
            return name, sum((c[1] for c in compiled), [])
        if set(node) != {"field", "op", "value"}:
            raise ValueError("condition requires field/op/value or all/any")
        field, op, expected = node["field"], node["op"], node["value"]
        actual, kind, prerequisites = field_spec(field)
        if kind == "number":
            valid = op in ("lte", "gte") and type(expected) in (int,float) and math.isfinite(expected) and expected >= 0
        elif kind == "boolean":
            valid = op == "eq" and type(expected) is bool
        elif kind == "list":
            valid = op == "contains_any" and bool(string_list(expected, nonempty=True))
        else:
            valid = ((op == "eq" and isinstance(expected, str))
                     or (op == "in" and bool(string_list(expected, nonempty=True)))
                     or (op == "cidr" and field == "context.source_ip" and bool(string_list(expected, nonempty=True))))
        if not valid:
            raise ValueError("condition operator/value does not match field type")
        encoded = json.dumps(expected, allow_nan=False)
        checks = list(prerequisites)
        checks += ["value := " + actual, "is_" + {"number":"number", "boolean":"boolean", "string":"string", "list":"array"}[kind] + "(value)"]
        if op == "eq": checks.append("value == " + encoded)
        elif op == "in": checks.append("value == " + encoded + "[_]")
        elif op == "contains_any": checks.append("value[_] == " + encoded + "[_]")
        elif op == "cidr":
            for network in expected:
                ipaddress.ip_network(network, strict=True)
            checks.append("net.cidr_contains(" + encoded + "[_], value)")
        else: checks.append("value " + ("<=" if op == "lte" else ">=") + " " + encoded)
        self.rules.append(name + " { " + "; ".join(checks) + " }")
        self.rules.append(name + "_matched = true { " + name + " } else = false")
        trace = '{"field":' + json.dumps(field) + ',"op":' + json.dumps(op) + ',"matched":' + name + '_matched}'
        anchors = {"device.age_seconds":"input.device.observed_at", "risk.age_seconds":"input.risk.updated_at", "identity.auth_age_seconds":"session_anchor"}
        if field in anchors:
            # Consider all rule/timeout boundaries, including earlier rules that
            # may start matching later. Conservative bounds never overstate TTL.
            self.rules.append("application_context_deadlines[deadline] { " + "; ".join(prerequisites + ["deadline := floor(" + anchors[field] + " + " + encoded + ")", "deadline >= input.now"]) + " }")
        if field.startswith("device."):
            self.rules.append("application_context_deadlines[deadline] { verified_device; deadline := input.device.expires_at; deadline >= input.now }")
        return name, [trace]


def compile_model(document, app_host):
    model = copy.deepcopy(document)
    if not isinstance(model, dict) or set(model) != {"model_version", "applications", "access_rules", "timeout_rules", "default_timeouts"} or type(model["model_version"]) is not int or model["model_version"] != 1:
        raise ValueError("unsupported application model or top-level fields")
    hostname(app_host)
    apps = model["applications"]
    if not isinstance(apps, list) or not 1 <= len(apps) <= 64:
        raise ValueError("application count must be in 1..64")
    ids, groups = set(), set()
    for app in apps:
        if not isinstance(app, dict) or set(app) != {"id", "resource_kinds", "destinations", "ports", "protocol", "groups"}:
            raise ValueError("invalid application fields")
        app_id = identifier(app["id"])
        if app_id in ids: raise ValueError("duplicate application ID")
        ids.add(app_id)
        if set(string_list(app["resource_kinds"], nonempty=True)) - KINDS:
            raise ValueError("unknown gateway resource kind")
        groups.update(string_list(app["groups"]))
        ports = app["ports"]
        if not isinstance(ports,list) or not 1 <= len(ports) <= 256 or any(type(p) is not int or not 1 <= p <= 65535 for p in ports) or len(set(ports)) != len(ports):
            raise ValueError("ports must be unique integers in 1..65535")
        if app["protocol"] not in ("tcp","udp"): raise ValueError("invalid application protocol")
        destinations = string_list(app.pop("destinations"), nonempty=True)
        app["selectors"] = [selector(value, app_host) for value in destinations]
    timeouts(model["default_timeouts"])
    compiler = Compiler()
    for family in ("access", "timeout"):
        key = family + "_rules"
        rules = model[key]
        if not isinstance(rules, list) or len(rules) > 128:
            raise ValueError("rule count exceeds limit")
        seen, priorities = set(), set()
        for rule in rules:
            required = {"id", "priority", "enabled", "applications", "application_groups", "action" if family == "access" else "timeouts"}
            if not isinstance(rule,dict) or set(rule) - (required|{"when"}) or required - set(rule):
                raise ValueError("invalid rule fields")
            rule_id = identifier(rule["id"])
            if rule_id in seen or type(rule["priority"]) is not int or rule["priority"] in priorities:
                raise ValueError("duplicate rule ID or invalid/duplicate priority")
            seen.add(rule_id); priorities.add(rule["priority"])
            if type(rule["enabled"]) is not bool: raise ValueError("enabled must be boolean")
            selected = string_list(rule["applications"])
            selected_groups = string_list(rule["application_groups"])
            if not selected and not selected_groups or set(selected)-ids or set(selected_groups)-groups:
                raise ValueError("empty or unknown rule application/group selectors")
            if family == "access":
                if rule["action"] not in ("allow","deny"): raise ValueError("invalid rule action")
            else: timeouts(rule["timeouts"])
        rules.sort(key=lambda r:r["priority"])
        for i, rule in enumerate(rules):
            if "when" in rule:
                name, trace = compiler.condition(rule.pop("when"))
                compiler.rules.append(f"application_{family}_condition({i}) {{ {name} }}")
            else:
                trace = []
                compiler.rules.append(f"application_{family}_condition({i}) {{ true }}")
            compiler.rules.append(f"application_{family}_condition_trace({i}) = [" + ",".join(trace) + "]")
        # Define a typed empty function for an empty rule family.
        if not rules:
            compiler.rules += [f'application_{family}_condition(i) {{ i == -1 }}', f'application_{family}_condition_trace(i) = [] {{ i == -1 }}']
    compiler.rules.append("application_context_deadlines[deadline] { deadline := input.now; false }")
    return model, "\n".join(compiler.rules) + "\n"
