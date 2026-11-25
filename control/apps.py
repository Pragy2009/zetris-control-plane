"""Add a protected application to one tenant.

Writes a per-tenant application document, re-renders that tenant's Rego policy,
creates a route snippet, and distributes the policy — all through Runner so
preview records operations without side effects.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from .steps import Context, StepError
from .registry import ZETRIS_DEFAULT, load

MODULE_ROOT = Path(__file__).resolve().parents[1]
APP_ID = re.compile(r"[a-z][a-z0-9_-]{1,62}")
KINDS = {"workspace", "developer_app", "admin_console", "diagnostics", "file",
         "simulation_control", "simulation_probe", "document", "export"}


def add_app(ctx: Context, payload):
    if ctx.runner.mode == "apply":
        ctx.runner.ensure_apply()
    app_id = str(payload.get("id", ""))
    host = str(payload.get("host", ""))
    groups = payload.get("groups", ["tenant-http"])
    kinds = payload.get("kinds", ["workspace"])
    if not APP_ID.fullmatch(app_id) or not re.fullmatch(r"[a-z0-9.-]{3,253}", host):
        raise StepError("Invalid application id or host")
    if not isinstance(groups, list) or not groups or not all(re.fullmatch(r"[a-z][a-z0-9-]*", g) for g in groups):
        raise StepError("Invalid groups")
    if not isinstance(kinds, list) or not set(kinds) <= KINDS:
        raise StepError("Unknown resource kind")

    folder = MODULE_ROOT / "state/applications"
    folder.mkdir(mode=0o700, exist_ok=True)
    document_path = folder / (ctx.tenant["id"] + ".json")
    if document_path.is_file():
        document = json.loads(document_path.read_text(encoding="utf-8"))
    else:
        document = json.loads((MODULE_ROOT / "config/applications.free.json").read_text(encoding="utf-8"))
    if any(item.get("id") == app_id for item in document["applications"]):
        raise StepError("Application already exists for this tenant")
    document["applications"].append({
        "id": app_id, "resource_kinds": kinds, "destinations": [host],
        "ports": [443], "protocol": "tcp", "groups": groups,
    })
    ctx.runner.write(document_path, json.dumps(document, indent=2) + "\n")

    policy_dir = ZETRIS_DEFAULT / "node1/policies/access-v1"
    if str(policy_dir) not in sys.path:
        sys.path.insert(0, str(policy_dir))
    policy = load(policy_dir / "render.py", "ztcp_app_policy")
    settings = {"host": ctx.tenant["application_host"], "issuer": ctx.tenant["issuer"],
                "role_client": ctx.tenant["connector_oidc_client_id"], "simulator_subject": ""}
    rego = policy.render(ctx.tenant["id"], settings, document)
    ctx.runner.write(ctx.out_dir / "policy" / ctx.tenant["policy_file"], rego)

    edge = ctx.config.get("edge_host", "zetris-single-node-edge-1")
    snippet = host + " {\n    reverse_proxy " + edge + ":8083\n}\n"
    ctx.runner.write(ctx.out_dir / "routes" / (ctx.tenant["id"] + "-app-" + app_id + ".caddy"), snippet)

    ctx.runner.command([
        "docker", "run", "--rm",
        "-v", ctx.config["policy_volume"] + ":/policies",
        "-v", str(ctx.out_dir / "policy") + ":/src:ro",
        "alpine", "cp", "/src/" + ctx.tenant["policy_file"],
        "/policies/" + ctx.tenant["policy_file"]])
    gateway = ctx.config.get("gateway_container", "zetris-control-plane-tenant-gateway-1")
    ctx.runner.command(["docker", "exec", gateway, "caddy",
                        "reload", "--config", "/etc/caddy/Caddyfile"])

    return {
        "tenant": ctx.tenant["id"], "app": app_id, "host": host,
        "groups": groups, "kinds": kinds, "mode": ctx.runner.mode,
        "note": "Policy rendered and route snippet generated; verification required in apply mode.",
    }
