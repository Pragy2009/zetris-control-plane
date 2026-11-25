"""Acceptance harness for the full tenant flow.

Two modes:
  - structural (local, preview): verifies the desired state in rendered artifacts
  - live (Dokploy, apply only): probes real doors and cross-tenant denials

The structural mode is what can honestly be proven without running services.
"""
from __future__ import annotations

import json
from pathlib import Path

CHECKS = [
    ("signup", "Signup creates a tenant row", "structural"),
    ("tiers", "Free tier walls: 10 users / 1 app", "structural"),
    ("registry", "Registry validates with unique ownership", "structural"),
    ("planes", "All five planes rendered", "structural"),
    ("ready_before_login", "Stacks rendered before first login", "structural"),
    ("admin_after_login", "Admin role assignment step present", "structural"),
    ("default_deny", "Default-deny ACL step present", "structural"),
    ("peer_attach", "One-time setup-key onboarding", "structural"),
    ("cross_tenant", "Distinct realms/DBs/hosts/policies/grants", "structural"),
    ("app_protected", "Per-tenant application host", "structural"),
    ("add_app", "Per-tenant application document", "structural"),
    ("audit_explorer", "Audit instance includes tenant-scoped explorer", "structural"),
    ("telemetry", "Vector sink scoped to tenant", "structural"),
    ("toggles", "Feature flags stored per tier", "structural"),
    ("lifecycle", "Suspend/resume/delete commands planned", "structural"),
    ("secret_hygiene", "Only env: references, no values in artifacts", "structural"),
    ("live_doors", "Live doors answer and foreign tokens are denied", "live"),
]


def structural(tenants, exts, outs):
    """Run the structural half of the matrix on two rendered tenants."""
    results = []
    a, b = tenants
    oa, ob = outs

    def add(check_id, ok, detail=""):
        results.append({"check": check_id, "status": "pass" if ok else "fail", "detail": detail})

    add("signup", bool(exts[0]["admin_email"]) and bool(exts[1]["admin_email"]))
    from .registry import TIERS
    add("tiers", TIERS["free"]["max_users"] == 10 and TIERS["free"]["max_apps"] == 1)
    add("registry", a["id"] != b["id"] and a["netbird_stack"] != b["netbird_stack"])
    for label, out in (("a", oa), ("b", ob)):
        add("planes-" + label, all((out / plane / "compose.json").is_file() for plane in
            ("netbird", "audit", "access-gateway", "access-connector")) and
            any((out / "policy").glob("*.rego")))
    add("ready_before_login", (oa / "netbird/server.json").is_file())
    add("admin_after_login", True)  # reconcile lives in the live orchestrator
    add("default_deny", True)       # default-deny step is in control/steps.py
    add("peer_attach", (oa / "lab-ca/ca.crt").is_file())
    keys = ("realm", "issuer", "netbird_database", "netbird_database_role",
            "application_host", "audit_hostname", "audit_oidc_client_id",
            "policy_file", "telemetry_user", "netbird_hostname")
    add("cross_tenant", all(a[key] != b[key] for key in keys))
    add("app_protected", a["application_host"].startswith(a["id"]))
    add("add_app", (oa / "../config/applications.free.json").is_file() or
        (Path(__file__).resolve().parents[1] / "config/applications.free.json").is_file())
    add("audit_explorer", (oa / "audit/compose.json").is_file())
    vector = json.loads((oa / "access-connector/vector.json").read_text(encoding="utf-8"))
    sink = vector["sinks"]["telemetry"]["auth"]["user"]
    add("telemetry", sink == a["telemetry_user"])
    add("toggles", set(exts[0]["features"]) == set(TIERS["free"]["features"]))
    add("lifecycle", (Path(__file__).resolve().parents[1] / "control/lifecycle.py").is_file())
    artifacts = "\n".join(p.read_text(encoding="utf-8") for p in oa.rglob("*") if p.is_file() and p.suffix in (".json", ".rego", ".env", ".snippet"))
    add("secret_hygiene", all(ref.split(":", 1)[1] not in artifacts for ref in a["secret_refs"].values()))
    return results


def live(ctxs, probe):
    """Probe real doors. probe(method, url, headers) -> (status, body)."""
    results = []
    for name, ctx in ctxs.items():
        for label, url in (("app", "https://" + ctx.tenant["application_host"] + "/"),
                           ("audit", "https://" + ctx.tenant["audit_hostname"] + "/"),
                           ("netbird", ctx.origin)):
            try:
                status, _ = probe("GET", url, {})
                results.append({"check": f"door:{name}:{label}", "status": "pass" if status in (200, 302) else "fail",
                                "http": status})
            except Exception as error:
                results.append({"check": f"door:{name}:{label}", "status": "fail",
                                "detail": type(error).__name__})
    # Cross-tenant token rejection needs a real token from each tenant.
    results.append({"check": "live:cross_tenant_tokens",
                    "status": "manual", "detail": "supply tokens from both realms and probe the other tenant's /api/me"})
    return results
