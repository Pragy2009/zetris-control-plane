package access_v1_test

import future.keywords.every

now := 2000000000
base := {
  "schema_version": 1, "now": now,
  "principal": {"verified": true, "subject": "user-1", "session": "session-1", "tenant": "ztna", "issuer": "https://auth.ztna.sc.deeptrustxai.com/realms/ztna", "role_client": "node2-app-connector", "roles": ["viewer"], "kind": "human", "username": "alice", "authorized_party": "node2-app-connector", "expires_at": now+3600, "not_before": 0, "issued_at": now-30, "auth_time": now-30, "acr": "urn:zetris:acr:mfa"},
  "http": {"host": "app.ztna.sc.deeptrustxai.com", "port":"443", "protocol":"tcp", "path": "/juice/", "method": "GET"},
  "context": {"client_type":"envoy_http", "source_ip":"127.0.0.1"},
  "device": {"verified":false},
  "resource": {"tenant": "ztna", "id": "fixture-resource", "kind": "workspace", "action": "view", "supported": true, "owner_subject": "user-1"},
  "risk": {"available": true, "blocked": false, "subject": "user-1", "session": "session-1", "score": 100, "level": "LOW", "updated_at": now-10},
  "approval": {"verified": true, "id": "approval-1", "tenant": "ztna", "subject": "user-1", "session": "session-1", "resource": "fixture-resource", "action": "view", "approved_by": "operator-2", "issued_at": now-30, "expires_at": now+120}
}

matrix := [
  ["workspace", "view", "GET", ["viewer", "developer", "tenant_admin"]],
  ["developer_app", "view", "GET", ["developer", "tenant_admin"]],
  ["admin_console", "view", "GET", ["tenant_admin"]],
  ["diagnostics", "view", "GET", ["platform_operator"]],
  ["file", "download", "GET", ["developer", "tenant_admin"]],
  ["file", "view", "GET", ["developer", "tenant_admin"]],
  ["simulation_control", "manage", "POST", ["tenant_admin"]],
  ["document", "view", "GET", ["viewer", "developer", "tenant_admin"]],
  ["document", "edit", "PATCH", ["developer", "tenant_admin"]],
  ["document", "delete", "DELETE", ["tenant_admin"]],
  ["export", "export", "POST", ["tenant_admin"]],
  ["tenant_users", "admin", "POST", ["tenant_admin"]],
  ["policy", "admin", "PUT", ["platform_operator"]],
  ["session", "unblock", "POST", ["tenant_admin"]]
]

has_role(roles, role) = true { roles[_] == role } else = false

test_role_action_matrix_both_tenants {
  every row in matrix {
    every role in ["viewer", "developer", "tenant_admin", "platform_operator", "admin", "unknown"] {
      expected := has_role(row[3], role)
      first := data.ztna.decision with input as base with input.principal.roles as [role] with input.resource.kind as row[0] with input.resource.action as row[1] with input.approval.action as row[1] with input.http.method as row[2]
      first.allow == expected
      second := data.ztna_tenant_2.decision with input as base with input.principal.roles as [role] with input.principal.tenant as "ztna-tenant-2" with input.principal.issuer as "https://auth.ztna.sc.deeptrustxai.com/realms/ztna-tenant-2" with input.http.host as "tenant2-app.ztna.sc.deeptrustxai.com" with input.resource.tenant as "ztna-tenant-2" with input.approval.tenant as "ztna-tenant-2" with input.resource.kind as row[0] with input.resource.action as row[1] with input.approval.action as row[1] with input.http.method as row[2]
      second.allow == expected
    }
  }
}

test_missing_and_unverified_context_deny {
  every request in [{}, {"schema_version": 1}, {"principal": {"verified": true}}] {
    result := data.ztna.decision with input as request
    not result.allow
    result.reasons[_] == "invalid_or_untrusted_context"
  }
  result := data.ztna.decision with input as base with input.principal.verified as false
  not result.allow
}

test_cross_tenant_and_host_deny_even_for_operator {
  every host in ["tenant2-app.ztna.sc.deeptrustxai.com", "app.ztna.sc.deeptrustxai.com.evil.test", "", "localhost"] {
    result := data.ztna.decision with input as base with input.http.host as host with input.principal.roles as ["tenant_admin", "platform_operator"]
    not result.allow
  }
  tenant := data.ztna.decision with input as base with input.principal.tenant as "ztna-tenant-2"
  not tenant.allow
  resource := data.ztna.decision with input as base with input.resource.tenant as "ztna-tenant-2"
  not resource.allow
  issuer := data.ztna.decision with input as base with input.principal.issuer as "https://attacker.invalid/realms/ztna"
  not issuer.allow
}

test_expired_future_and_mismatched_session_deny {
  expired := data.ztna.decision with input as base with input.principal.expires_at as now
  not expired.allow
  future := data.ztna.decision with input as base with input.principal.not_before as now+1
  not future.allow
  subject := data.ztna.decision with input as base with input.risk.subject as "another-user"
  not subject.allow
  session := data.ztna.decision with input as base with input.risk.session as "another-session"
  not session.allow
}

test_blocks_and_critical_override_every_role {
  every role in ["viewer", "developer", "tenant_admin", "platform_operator"] {
    blocked := data.ztna.decision with input as base with input.principal.roles as [role] with input.risk.blocked as true
    not blocked.allow
    critical := data.ztna.decision with input as base with input.principal.roles as [role] with input.risk.level as "CRITICAL" with input.risk.score as 2
    not critical.allow
  }
}

test_unscored_stale_high_are_limited_to_workspace {
  unscored := data.ztna.decision with input as base with input.risk.level as "UNKNOWN" with input.risk.updated_at as 0
  unscored.allow
  unscored_dev := data.ztna.decision with input as base with input.risk.level as "UNKNOWN" with input.risk.updated_at as 0 with input.principal.roles as ["developer"] with input.resource.kind as "developer_app"
  not unscored_dev.allow
  stale := data.ztna.decision with input as base with input.risk.updated_at as now-601
  stale.allow
  stale_dev := data.ztna.decision with input as base with input.risk.updated_at as now-601 with input.principal.roles as ["developer"] with input.resource.kind as "developer_app"
  not stale_dev.allow
  high := data.ztna.decision with input as base with input.risk.level as "HIGH" with input.risk.score as 40
  high.allow
  high_dev := data.ztna.decision with input as base with input.risk.level as "HIGH" with input.risk.score as 40 with input.principal.roles as ["developer"] with input.resource.kind as "developer_app"
  not high_dev.allow
  unavailable := data.ztna.decision with input as base with input.risk.available as false
  not unavailable.allow
}

test_freshness_boundaries_and_corrupt_risk {
  boundary := data.ztna.decision with input as base with input.principal.roles as ["developer"] with input.resource.kind as "developer_app" with input.risk.updated_at as now-600
  boundary.allow
  stale := data.ztna.decision with input as base with input.principal.roles as ["developer"] with input.resource.kind as "developer_app" with input.risk.updated_at as now-601
  not stale.allow
  future := data.ztna.decision with input as base with input.risk.updated_at as now+31
  not future.allow
  corrupt := data.ztna.decision with input as base with input.risk.score as 2
  not corrupt.allow
  missing_low_score := data.ztna.decision with input as base with input.risk.score as 0 with input.risk.level as "UNKNOWN" with input.risk.updated_at as 0
  not missing_low_score.allow
}

test_recent_mfa_required_for_privileged_actions {
  every acr in ["", "1", "2", "mfa"] {
    result := data.ztna.decision with input as base with input.principal.roles as ["tenant_admin"] with input.resource.kind as "admin_console" with input.principal.acr as acr
    not result.allow
    result.reasons[_] == "recent_mfa_required"
  }
  old := data.ztna.decision with input as base with input.principal.roles as ["tenant_admin"] with input.resource.kind as "admin_console" with input.principal.auth_time as now-301
  not old.allow
  boundary := data.ztna.decision with input as base with input.principal.roles as ["tenant_admin"] with input.resource.kind as "admin_console" with input.principal.auth_time as now-300
  boundary.allow
}

test_document_ownership_and_unsupported_operations {
  foreign := data.ztna.decision with input as base with input.resource.kind as "document" with input.resource.owner_subject as "other-user"
  not foreign.allow
  admin := data.ztna.decision with input as base with input.resource.kind as "document" with input.resource.owner_subject as "other-user" with input.principal.roles as ["tenant_admin"]
  admin.allow
  unsupported := data.ztna.decision with input as base with input.principal.roles as ["tenant_admin"] with input.resource.supported as false
  not unsupported.allow
  post := data.ztna.decision with input as base with input.http.method as "POST"
  not post.allow
}

test_approval_must_be_verified_fresh_independent_and_exactly_bound {
  req := object.union(base, {"resource": object.union(base.resource,{"kind":"export", "action":"export"}), "principal":object.union(base.principal,{"roles":["tenant_admin"]}), "http":object.union(base.http,{"method":"POST"}), "approval":object.union(base.approval,{"action":"export"})})
  allowed := data.ztna.decision with input as req
  allowed.allow
  unverified := data.ztna.decision with input as req with input.approval.verified as false
  not unverified.allow
  tenant := data.ztna.decision with input as req with input.approval.tenant as "other"
  not tenant.allow
  subject := data.ztna.decision with input as req with input.approval.subject as "other"
  not subject.allow
  session := data.ztna.decision with input as req with input.approval.session as "other"
  not session.allow
  resource := data.ztna.decision with input as req with input.approval.resource as "other"
  not resource.allow
  action := data.ztna.decision with input as req with input.approval.action as "delete"
  not action.allow
  self_approval := data.ztna.decision with input as req with input.approval.approved_by as "user-1"
  not self_approval.allow
  expired := data.ztna.decision with input as req with input.approval.expires_at as now
  not expired.allow
  future := data.ztna.decision with input as req with input.approval.issued_at as now+1
  not future.allow
  too_long := data.ztna.decision with input as req with input.approval.expires_at as now+1000
  not too_long.allow
}

test_headers_and_display_names_cannot_elevate {
  result := data.ztna.decision with input as base with input.principal.username as "zetris-admin" with input.resource.kind as "admin_console" with input.http.headers as {"x-role":"tenant_admin", "x-mfa":"true", "x-approval":"approved", "x-tenant-id":"ztna"}
  not result.allow
  other_client := data.ztna.decision with input as base with input.principal.role_client as "zetris-audit"
  not other_client.allow
}

test_recovery_rechecks_permissions_and_critical_state {
  blocked := data.ztna.decision with input as base with input.risk.blocked as true
  not blocked.allow
  restored := data.ztna.decision with input as base with input.risk.blocked as false
  restored.allow
  still_critical := data.ztna.decision with input as base with input.risk.blocked as false with input.risk.level as "CRITICAL" with input.risk.score as 2
  not still_critical.allow
  never_admin := data.ztna.decision with input as base with input.risk.blocked as false with input.resource.kind as "admin_console"
  not never_admin.allow
}

test_simulator_requires_explicit_subject_and_never_gets_human_routes {
  req := object.union(base,{"principal":object.union(base.principal,{"kind":"simulator", "roles":[], "authorized_party":"zetris-risk-simulator", "username":"service-account-zetris-risk-simulator"}), "resource":object.union(base.resource,{"kind":"simulation_probe", "action":"probe"})})
  unbound := data.ztna.decision with input as req
  not unbound.allow
  bound := data.ztna.decision with input as req with data.ztna.config as object.union(data.ztna.config, {"simulator_subject":"user-1"})
  bound.allow
  blocked := data.ztna.decision with input as req with data.ztna.config as object.union(data.ztna.config, {"simulator_subject":"user-1"}) with input.risk.blocked as true
  not blocked.allow
  ordinary := data.ztna.decision with input as req with data.ztna.config as object.union(data.ztna.config, {"simulator_subject":"user-1"}) with input.resource.kind as "workspace" with input.resource.action as "view"
  not ordinary.allow
  disguised := data.ztna.decision with input as base with data.ztna.config as object.union(data.ztna.config, {"simulator_subject":"user-1"}) with input.principal.roles as ["tenant_admin"]
  not disguised.allow
}

test_application_decision_contains_rule_condition_and_timeout_trace {
  result := data.ztna.decision with input as base
  result.allow
  result.action == "allow"
  result.application_id == "workspace"
  result.access_rule_id == "human-application-access"
  result.timeout_rule_id == "default"
  result.trace[1].result == "matched"
  every condition in result.trace[1].conditions { condition.matched == true }
}

test_absolute_session_expiry_is_part_of_policy_evaluation {
  result := data.ztna.decision with input as base with input.principal.auth_time as now-3600
  not result.allow
  result.action == "reauthenticate"
  result.reasons[_] == "maximum_session_expired"
  result.decision_valid_until == 0
}

test_refresh_does_not_reset_authentication_lifetime_or_override_block {
  result := data.ztna.decision with input as base with input.principal.auth_time as now-3600 with input.principal.issued_at as now with input.principal.expires_at as now+10000
  not result.allow
  blocked := data.ztna.decision with input as base with input.principal.auth_time as now-3600 with input.risk.blocked as true
  blocked.action == "deny"
}
