# zetris-access-policy: v1
# Rego v0 syntax for the repository's pinned OPA 0.63.0.
package ztna

import future.keywords.every

config := {"host": "app.ztna.sc.deeptrustxai.com", "issuer": "https://auth.ztna.sc.deeptrustxai.com/realms/ztna", "mfa_acrs": ["urn:zetris:acr:mfa"], "mfa_max_age_seconds": 300, "risk_max_age_seconds": 600, "role_client": "node2-app-connector", "simulator_subject": "", "tenant": "ztna", "version": "access-v1.1.0"}

permissions := {
  "workspace": {"view": ["viewer", "developer", "tenant_admin"]},
  "developer_app": {"view": ["developer", "tenant_admin"]},
  "admin_console": {"view": ["tenant_admin"]},
  "diagnostics": {"view": ["platform_operator"]},
  "file": {"view": ["developer", "tenant_admin"], "download": ["developer", "tenant_admin"]},
  "document": {"view": ["viewer", "developer", "tenant_admin"], "edit": ["developer", "tenant_admin"], "delete": ["tenant_admin"]},
  "export": {"export": ["tenant_admin"]},
  "tenant_users": {"admin": ["tenant_admin"]},
  "policy": {"admin": ["platform_operator"]},
  "session": {"unblock": ["tenant_admin"]},
  "simulation_control": {"manage": ["tenant_admin"]}
}

valid_contract {
  input.schema_version == 1
  input.principal.verified == true
  is_string(input.principal.subject)
  input.principal.subject != ""
  is_string(input.principal.session)
  input.principal.session != ""
  input.principal.tenant == config.tenant
  input.principal.issuer == config.issuer
  input.principal.role_client == config.role_client
  input.principal.kind == {"human", "simulator"}[_]
  is_array(input.principal.roles)
  every role in input.principal.roles { is_string(role) }
  is_number(input.now)
  input.now > 0
  is_number(input.principal.expires_at)
  input.principal.expires_at > input.now
  is_number(input.principal.not_before)
  input.principal.not_before <= input.now
  is_number(input.principal.auth_time)
  is_string(input.principal.acr)
  input.http.host == config.host
  input.http.port == "443"
  input.http.protocol == "tcp"
  is_string(input.http.path)
  is_string(input.http.method)
  is_boolean(input.resource.supported)
  is_string(input.resource.kind)
  is_string(input.resource.id)
  input.resource.id != ""
  is_string(input.resource.action)
  input.resource.tenant == config.tenant
  is_boolean(input.risk.available)
  is_boolean(input.risk.blocked)
  input.risk.subject == input.principal.subject
  input.risk.session == input.principal.session
  is_number(input.risk.updated_at)
  input.risk.updated_at >= 0
  input.risk.updated_at <= input.now + 30
  is_number(input.risk.score)
  input.risk.score >= 0
  input.risk.score <= 100
  input.risk.level == {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[_]
  risk_consistent
  method_permitted
}

risk_consistent { input.risk.level == "UNKNOWN"; input.risk.updated_at == 0; input.risk.score == 100 }
risk_consistent { input.risk.level == "LOW"; input.risk.score >= 70; input.risk.updated_at > 0 }
risk_consistent { input.risk.level == "MEDIUM"; input.risk.score >= 50; input.risk.score < 70; input.risk.updated_at > 0 }
risk_consistent { input.risk.level == "HIGH"; input.risk.score >= 25; input.risk.score < 50; input.risk.updated_at > 0 }
risk_consistent { input.risk.level == "CRITICAL"; input.risk.score < 25; input.risk.updated_at > 0 }

method_permitted { input.resource.action == {"view", "download"}[_]; input.http.method == {"GET", "HEAD"}[_] }
method_permitted { input.resource.action == "edit"; input.http.method == {"POST", "PUT", "PATCH"}[_] }
method_permitted { input.resource.action == "delete"; input.http.method == "DELETE" }
method_permitted { input.resource.action == {"export", "unblock"}[_]; input.http.method == "POST" }
method_permitted { input.resource.action == "admin"; input.http.method == {"POST", "PUT", "PATCH", "DELETE"}[_] }
method_permitted { input.resource.action == "manage"; input.http.method == {"GET", "HEAD", "POST"}[_] }
method_permitted { input.resource.action == "probe"; input.http.method == {"GET", "POST"}[_] }

is_simulator {
  config.simulator_subject != ""
  input.principal.subject == config.simulator_subject
  input.principal.authorized_party == "zetris-risk-simulator"
  input.principal.username == "service-account-zetris-risk-simulator"
  input.principal.kind == "simulator"
}

role_permitted {
  input.principal.kind == "human"
  input.principal.subject != config.simulator_subject
  required := permissions[input.resource.kind][input.resource.action]
  input.principal.roles[_] == required[_]
}
role_permitted {
  is_simulator
  input.resource.kind == "simulation_probe"
  input.resource.action == "probe"
}

low_impact_read {
  input.resource.kind == "workspace"
  input.resource.action == "view"
}
low_impact_read {
  is_simulator
  input.resource.kind == "simulation_probe"
}

fresh_risk {
  input.risk.updated_at > 0
  input.risk.updated_at <= input.now + 30
  input.now - input.risk.updated_at <= config.risk_max_age_seconds
  input.risk.level != "UNKNOWN"
}

privileged {
  input.resource.kind == {"admin_console", "diagnostics", "file", "export", "tenant_users", "policy", "session", "simulation_control"}[_]
}
privileged {
  input.resource.kind == "document"
  input.resource.action == "delete"
}

recent_mfa {
  input.principal.acr == config.mfa_acrs[_]
  input.principal.auth_time > 0
  input.principal.auth_time <= input.now
  input.now - input.principal.auth_time <= config.mfa_max_age_seconds
}

approval_required {
  input.resource.kind == {"export", "tenant_users", "policy", "session"}[_]
}
approval_required {
  input.resource.kind == "document"
  input.resource.action == "delete"
}

valid_approval {
  input.approval.verified == true
  input.approval.id != ""
  input.approval.tenant == input.principal.tenant
  input.approval.subject == input.principal.subject
  input.approval.session == input.principal.session
  input.approval.resource == input.resource.id
  input.approval.action == input.resource.action
  input.approval.approved_by != ""
  input.approval.approved_by != input.principal.subject
  input.approval.issued_at <= input.now
  input.approval.expires_at > input.now
  input.approval.expires_at - input.approval.issued_at <= 300
}

object_permitted {
  input.resource.kind != "document"
}
object_permitted {
  input.resource.kind == "document"
  input.resource.owner_subject == input.principal.subject
}
object_permitted {
  input.resource.kind == "document"
  input.principal.roles[_] == "tenant_admin"
}

violations["invalid_or_untrusted_context"] { not valid_contract }
violations["unsupported_resource_or_action"] { not input.resource.supported }
violations["permission_denied"] { not role_permitted }
violations["object_access_denied"] { not object_permitted }
violations["risk_service_unavailable"] { input.risk.available != true }
violations["session_blocked"] { input.risk.blocked == true }
violations["critical_risk"] { input.risk.level == "CRITICAL" }
violations["fresh_risk_required"] { not low_impact_read; not fresh_risk }
violations["high_risk_restricted"] { not low_impact_read; input.risk.level == "HIGH" }
violations["low_risk_required"] { privileged; input.risk.level != "LOW" }
violations["recent_mfa_required"] { privileged; not recent_mfa }
violations["bound_approval_required"] { approval_required; not valid_approval }

default allow = false
allow { count(violations) == 0 }

# Application authoring layer. Mandatory Zetris violations remain independent.
application_policy := {"access_rules": [{"action": "allow", "application_groups": [], "applications": ["simulation-probes"], "enabled": true, "id": "bound-simulator-probes", "priority": 10}, {"action": "allow", "application_groups": ["tenant-http"], "applications": [], "enabled": true, "id": "human-application-access", "priority": 100}], "applications": [{"groups": ["tenant-http"], "id": "workspace", "ports": [443], "protocol": "tcp", "resource_kinds": ["workspace"], "selectors": [{"kind": "exact", "rank": 3000000, "value": "app.ztna.sc.deeptrustxai.com"}]}, {"groups": ["tenant-http"], "id": "developer-app", "ports": [443], "protocol": "tcp", "resource_kinds": ["developer_app"], "selectors": [{"kind": "exact", "rank": 3000000, "value": "app.ztna.sc.deeptrustxai.com"}]}, {"groups": ["tenant-http", "privileged"], "id": "admin-console", "ports": [443], "protocol": "tcp", "resource_kinds": ["admin_console"], "selectors": [{"kind": "exact", "rank": 3000000, "value": "app.ztna.sc.deeptrustxai.com"}]}, {"groups": ["tenant-http", "privileged"], "id": "diagnostics", "ports": [443], "protocol": "tcp", "resource_kinds": ["diagnostics"], "selectors": [{"kind": "exact", "rank": 3000000, "value": "app.ztna.sc.deeptrustxai.com"}]}, {"groups": ["tenant-http", "privileged"], "id": "files", "ports": [443], "protocol": "tcp", "resource_kinds": ["file"], "selectors": [{"kind": "exact", "rank": 3000000, "value": "app.ztna.sc.deeptrustxai.com"}]}, {"groups": ["tenant-http", "privileged"], "id": "demo-control", "ports": [443], "protocol": "tcp", "resource_kinds": ["simulation_control"], "selectors": [{"kind": "exact", "rank": 3000000, "value": "app.ztna.sc.deeptrustxai.com"}]}, {"groups": ["synthetic"], "id": "simulation-probes", "ports": [443], "protocol": "tcp", "resource_kinds": ["simulation_probe"], "selectors": [{"kind": "exact", "rank": 3000000, "value": "app.ztna.sc.deeptrustxai.com"}]}, {"groups": ["tenant-http"], "id": "documents-contract", "ports": [443], "protocol": "tcp", "resource_kinds": ["document"], "selectors": [{"kind": "exact", "rank": 3000000, "value": "app.ztna.sc.deeptrustxai.com"}]}, {"groups": ["tenant-http", "privileged"], "id": "administration-contract", "ports": [443], "protocol": "tcp", "resource_kinds": ["export", "tenant_users", "policy", "session"], "selectors": [{"kind": "exact", "rank": 3000000, "value": "app.ztna.sc.deeptrustxai.com"}]}], "default_timeouts": {"idle_seconds": 900, "max_session_seconds": 3600, "reauth_seconds": 28800}, "model_version": 1, "timeout_rules": [{"application_groups": ["privileged"], "applications": [], "enabled": true, "id": "privileged-short-session", "priority": 10, "timeouts": {"idle_seconds": 120, "max_session_seconds": 900, "reauth_seconds": 900}}, {"application_groups": [], "applications": ["documents-contract"], "enabled": true, "id": "document-delete-short-session", "priority": 20, "timeouts": {"idle_seconds": 120, "max_session_seconds": 900, "reauth_seconds": 900}}]}

verified_device {
  input.device.verified == true
  input.device.tenant == input.principal.tenant
  input.device.subject == input.principal.subject
  input.device.session == input.principal.session
  is_number(input.device.observed_at)
  input.device.observed_at > 0
  input.device.observed_at <= input.now
  is_number(input.device.expires_at)
  input.device.expires_at > input.now
}

session_anchor = anchor {
  input.principal.kind == "human"
  anchor := input.principal.auth_time
  anchor > 0
} else = anchor {
  input.principal.kind == "simulator"
  anchor := input.principal.issued_at
  anchor > 0
} else = 0

application_selector_matches(selector) { selector.kind == "exact"; input.http.host == selector.value }
application_selector_matches(selector) { selector.kind == "wildcard"; endswith(input.http.host, selector.value) }
application_selector_matches(selector) { selector.kind == "cidr"; net.cidr_contains(selector.value, input.http.host) }

application_candidates[candidate] {
  app := application_policy.applications[_]
  app.resource_kinds[_] == input.resource.kind
  app.protocol == input.http.protocol
  app.ports[_] == to_number(input.http.port)
  selector := app.selectors[_]
  application_selector_matches(selector)
  candidate := {"id":app.id, "rank":selector.rank + 1000 - count(app.ports)}
}
application_winners[id] {
  best := max({c.rank | c := application_candidates[_]})
  candidate := application_candidates[_]
  candidate.rank == best
  id := candidate.id
}
selected_application = app {
  count(application_winners) == 1
  app := application_policy.applications[_]
  application_winners[app.id]
}
selected_application_id = id { id := selected_application.id } else = "unresolved"

application_targets(rule) { rule.applications[_] == selected_application.id }
application_targets(rule) { rule.application_groups[_] == selected_application.groups[_] }

selected_access_index = i {
  matches := {index |
    rule := application_policy.access_rules[index]
    rule.enabled
    application_targets(rule)
    application_access_condition(index)
  }
  i := min(matches)
} else = -1
selected_access_rule = application_policy.access_rules[selected_access_index]
selected_access_rule_id = id { id := selected_access_rule.id } else = "none"

selected_timeout_index = i {
  matches := {index |
    rule := application_policy.timeout_rules[index]
    rule.enabled
    application_targets(rule)
    application_timeout_condition(index)
  }
  i := min(matches)
} else = -1
selected_timeout_rule_id = id { id := application_policy.timeout_rules[selected_timeout_index].id } else = "default"
session_constraints = limits { limits := application_policy.timeout_rules[selected_timeout_index].timeouts } else = application_policy.default_timeouts

application_access_result(i) = "disabled" { not application_policy.access_rules[i].enabled
} else = "different_application" { not application_targets(application_policy.access_rules[i])
} else = "conditions_not_met" { not application_access_condition(i)
} else = "matched" { selected_access_index == i
} else = "not_reached"
application_timeout_result(i) = "disabled" { not application_policy.timeout_rules[i].enabled
} else = "different_application" { not application_targets(application_policy.timeout_rules[i])
} else = "conditions_not_met" { not application_timeout_condition(i)
} else = "matched" { selected_timeout_index == i
} else = "not_reached"

application_access_trace := [{"stage":"access", "rule":rule.id, "priority":rule.priority, "result":application_access_result(i), "conditions":application_access_condition_trace(i)} | rule := application_policy.access_rules[i]]
application_timeout_trace := [{"stage":"timeout", "rule":rule.id, "priority":rule.priority, "result":application_timeout_result(i), "conditions":application_timeout_condition_trace(i)} | rule := application_policy.timeout_rules[i]]
application_trace := array.concat(application_access_trace, application_timeout_trace)

violations["unknown_application"] { count(application_winners) == 0 }
violations["ambiguous_application"] { count(application_winners) > 1 }
violations["application_access_denied"] { not selected_access_rule.action == "allow" }
violations["reauthentication_required"] { session_anchor <= 0 }
violations["reauthentication_required"] { session_anchor > input.now }
violations["reauthentication_required"] { input.now - session_anchor >= session_constraints.reauth_seconds }
violations["maximum_session_expired"] { input.now - session_anchor >= session_constraints.max_session_seconds }

reauthentication_reasons := {"reauthentication_required", "maximum_session_expired", "recent_mfa_required"}
decision_action = "allow" { allow
} else = "reauthenticate" { count(violations) > 0; count(violations - reauthentication_reasons) == 0
} else = "deny"

# Advisory re-evaluation bound only. Every request still rechecks live risk.
# Includes temporal conditions in earlier, currently unmatched rules as well.
application_recheck_deadlines[d] { d := input.principal.expires_at }
application_recheck_deadlines[d] { d := session_anchor + session_constraints.reauth_seconds }
application_recheck_deadlines[d] { d := session_anchor + session_constraints.max_session_seconds }
application_recheck_deadlines[d] { d := application_context_deadlines[_] }
application_recheck_deadlines[d] { not low_impact_read; d := input.risk.updated_at + config.risk_max_age_seconds }
application_recheck_deadlines[d] { privileged; d := input.principal.auth_time + config.mfa_max_age_seconds }
application_valid_until = deadline { allow; deadline := min(application_recheck_deadlines) } else = 0

application_condition_0 { value := input.principal.kind; is_string(value); value == "simulator" }
application_condition_0_matched = true { application_condition_0 } else = false
application_access_condition(0) { application_condition_0 }
application_access_condition_trace(0) = [{"field":"identity.kind","op":"eq","matched":application_condition_0_matched}]
application_condition_2 { value := input.principal.kind; is_string(value); value == "human" }
application_condition_2_matched = true { application_condition_2 } else = false
application_condition_3 { value := input.principal.roles; is_array(value); value[_] == ["viewer", "developer", "tenant_admin", "platform_operator"][_] }
application_condition_3_matched = true { application_condition_3 } else = false
application_condition_1 { application_condition_2; application_condition_3 }
application_access_condition(1) { application_condition_1 }
application_access_condition_trace(1) = [{"field":"identity.kind","op":"eq","matched":application_condition_2_matched},{"field":"identity.roles","op":"contains_any","matched":application_condition_3_matched}]
application_timeout_condition(0) { true }
application_timeout_condition_trace(0) = []
application_condition_4 { value := input.resource.action; is_string(value); value == "delete" }
application_condition_4_matched = true { application_condition_4 } else = false
application_timeout_condition(1) { application_condition_4 }
application_timeout_condition_trace(1) = [{"field":"resource.action","op":"eq","matched":application_condition_4_matched}]
application_context_deadlines[deadline] { deadline := input.now; false }



decision := {
  "allow": allow,
  "action": decision_action,
  "reasons": sort([reason | reason := violations[_]]),
  "policy_version": config.version,
  "application_id": selected_application_id,
  "access_rule_id": selected_access_rule_id,
  "timeout_rule_id": selected_timeout_rule_id,
  "session_constraints": session_constraints,
  "decision_valid_until": application_valid_until,
  "trace": application_trace
}
