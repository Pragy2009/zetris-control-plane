#!/usr/bin/env python3
"""Install tenant-owned default-deny mesh rules. Preview is the default.

Groups bind connector/control enrollment roles. No peers, keys, routes or
identity providers are created. Unrelated enabled policies are rejected.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("netbird_provider", ROOT / "scripts/configure-netbird-keycloak.py")
provider = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provider)


class AccessError(RuntimeError):
    """Credential-free diagnostic."""


def group_names(tenant):
    return {role: "Zetris " + tenant["id"] + " " + role for role in ("connectors", "control")}


def group_ids(values):
    return [value["id"] if isinstance(value, dict) else value for value in (values or [])]


def normalized(policy):
    result = {key: policy.get(key) for key in ("name", "description", "enabled")}
    result["source_posture_checks"] = policy.get("source_posture_checks") or []
    result["rules"] = []
    for rule in policy.get("rules", []):
        item = {key: rule.get(key) for key in ("name", "description", "enabled", "action", "bidirectional", "protocol")}
        for key in ("sources", "destinations"):
            item[key] = sorted(group_ids(rule.get(key)))
        item["ports"] = sorted(rule.get("ports") or [])
        for key in ("port_ranges", "sourceResource", "destinationResource", "authorized_groups"):
            if rule.get(key):
                item[key] = rule[key]
        result["rules"].append(item)
    return result


def policies(tenant, groups, all_id):
    description = "zetris.mesh.v1:" + tenant["id"]
    result = []
    for name, source, destination, ports in (
        ("shared APIs", groups["connectors"], groups["control"], ["50051", "50553", "8443"]),
        ("application", all_id, groups["connectors"], ["443"]),
    ):
        label = "Zetris " + tenant["id"] + " " + name
        result.append({"name": label, "description": description, "enabled": True, "source_posture_checks": [],
            "rules": [{"name": name, "description": description, "enabled": True, "action": "accept",
                "bidirectional": False, "protocol": "tcp", "ports": ports,
                "sources": [source], "destinations": [destination]}]})
    return result


def builtin_default(policy, all_id):
    rules = policy.get("rules") or []
    if policy.get("name") != "Default" or len(rules) != 1 or policy.get("source_posture_checks"):
        return False
    rule = rules[0]
    return (rule.get("name") == "Default" and rule.get("enabled") is True
        and rule.get("action") == "accept" and rule.get("bidirectional") is True and rule.get("protocol") == "all"
        and group_ids(rule.get("sources")) == [all_id] and group_ids(rule.get("destinations")) == [all_id]
        and not any(rule.get(key) for key in ("ports", "port_ranges", "sourceResource", "destinationResource", "authorized_groups")))


def configure(tenant, origin, token, request, *, disable_default=False):
    if not provider.inspect_provider(tenant, origin, token, request):
        raise AccessError("The exact Keycloak provider must be installed first")
    existing_groups = request("/api/groups", token=token)
    existing_policies = request("/api/policies", token=token)
    if request("/api/routes", token=token) or request("/api/networks", token=token):
        raise AccessError("Existing network routes require a separate isolation review")
    all_groups = [item for item in existing_groups if item.get("name") == "All"]
    if len(all_groups) != 1:
        raise AccessError("Expected exactly one built-in All group")
    all_id = all_groups[0]["id"]
    names = group_names(tenant)
    owned = {}
    for role, name in names.items():
        matches = [item for item in existing_groups if item.get("name") == name]
        if len(matches) > 1 or any(item.get("resources") or item.get("issued", "api") != "api" for item in matches):
            raise AccessError("Conflicting managed enrollment group exists")
        if matches:
            owned[role] = matches[0]["id"]
    labels = {"Zetris " + tenant["id"] + " " + name for name in ("shared APIs", "application")}
    if any(sum(item.get("name") == name for item in existing_policies) > 1 for name in labels):
        raise AccessError("Duplicate managed policy exists; no network rule was changed")
    defaults = []
    for policy in existing_policies:
        if policy.get("name") in labels:
            if len(owned) != 2:
                raise AccessError("Managed policy exists without its complete group ownership")
            desired = next(item for item in policies(tenant, owned, all_id) if item["name"] == policy["name"])
            if normalized(policy) != normalized(desired):
                raise AccessError("Managed policy drift detected; no network rule was replaced")
        elif policy.get("enabled"):
            if not builtin_default(policy, all_id) or not disable_default:
                raise AccessError("Enabled broad/custom policy exists; review the explicit default-policy transition")
            defaults.append(policy)
    if len(defaults) > 1:
        raise AccessError("Multiple default policies require inspection")
    # Close broad access first. Subsequent partial failure is default-deny.
    for policy in defaults:
        body = normalized(policy)
        body["enabled"] = False
        request("/api/policies/" + policy["id"], method="PUT", body=body, token=token)
        installed = request("/api/policies", token=token)
        matches = [item for item in installed if item.get("id") == policy["id"]]
        if len(matches) != 1 or normalized(matches[0]) != body:
            raise AccessError("Default-policy disable was not verified; no managed access was added")
    for role, name in names.items():
        if role not in owned:
            created = request("/api/groups", method="POST", body={"name": name, "peers": []}, token=token)
            owned[role] = created["id"]
    for desired in policies(tenant, owned, all_id):
        matches = [item for item in existing_policies if item.get("name") == desired["name"]]
        if len(matches) > 1:
            raise AccessError("Duplicate managed policy exists")
        if not matches:
            request("/api/policies", method="POST", body=desired, token=token)
    installed = request("/api/policies", token=token)
    active = [item for item in installed if item.get("enabled")]
    expected = policies(tenant, owned, all_id)
    if len(active) != len(expected) or any(
            sum(normalized(item) == normalized(wanted) for item in active) != 1 for wanted in expected):
        raise AccessError("Network-rule read-back differs; inspect the default-deny transition")
    return owned


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=ROOT / "config/tenants.json")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--disable-default", action="store_true", help="Disable only the recognized unmodified built-in allow-all policy")
    parser.add_argument("--token-ref", default="env:NETBIRD_ADMIN_TOKEN")
    parser.add_argument("--ca", type=Path)
    args = parser.parse_args(argv)
    tenant = next((item for item in provider.render.registry.load_registry(args.registry) if item["id"] == args.tenant), None)
    if tenant is None:
        raise AccessError("Requested tenant is absent")
    if not args.apply:
        print(json.dumps({"dry_run": True, "tenant": tenant["id"], "groups": group_names(tenant),
            "rules": ["connectors -> control: TCP 50051,50553,8443", "All -> connectors: TCP 443"],
            "default_policy_transition": args.disable_default}, indent=2))
        return 0
    if not provider.render.registry.SECRET_REF.fullmatch(args.token_ref):
        raise AccessError("Administrator token must use an environment reference")
    token = os.environ.get(args.token_ref.split(":", 1)[1], "")
    if not token:
        raise AccessError("Tenant administrator token is required")
    origin = provider.render.origin_for(tenant)
    configure(tenant, origin, token, provider.requester(origin, args.ca), disable_default=args.disable_default)
    print("Owned tenant mesh rules verified; enroll gateway/connector keys into their respective groups")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AccessError, provider.ProviderError, provider.render.registry.RegistryError) as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        raise SystemExit("Mesh access setup failed: " + type(error).__name__ + "; details withheld") from None
