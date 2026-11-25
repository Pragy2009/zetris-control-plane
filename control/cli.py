"""Preview/validation CLI for tenant-control-plane. No live actions.

Usage (basic, read-only commands):
  python -B -m control.cli validate
  python -B -m control.cli plan --tenant canary
  python -B -m control.cli steps --tenant canary
  python -B -m control.cli render --tenant canary --out provisioned/canary

Live provisioning (Keycloak/Postgres/Docker/Dokploy) is deliberately NOT
implemented here; it requires explicit human approval and is documented in
DOKPLOY-STEPS.md.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import registry as reg
from . import render as rnd
from . import steps as stp

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "config/registry.local.json"


def build_context(args, tenant, ext):
    """Shared context for run, lifecycle and client commands."""
    import secrets
    config = json.loads(args.config.read_text(encoding="utf-8"))
    if args.apply:
        if not args.confirm or len(args.confirm) < 16:
            raise reg.ControlError("--apply requires --confirm with a 16+ character token")
        secrets_map = {name: os.environ.get(name, "") for name in tenant["secret_refs"].values()}
        for section in ("keycloak", "postgres", "clickhouse", "redis", "netbird"):
            name = config.get(section, {}).get("password_env") or config.get(section, {}).get("admin_token_env")
            if name:
                secrets_map[name] = os.environ.get(name, "")
        missing = [name for name, value in secrets_map.items()
                   if name in tenant["secret_refs"].values() and len(value) < 24]
        if missing:
            raise reg.ControlError("Live secrets are missing from the environment: " + ", ".join(sorted(missing)))
        mode, token = "apply", args.confirm
    else:
        secrets_map = rnd.ephemeral_environ(tenant)
        mode, token = "preview", ""
    target = (args.out / tenant["id"]) if args.out else (ROOT / "provisioned" / tenant["id"])
    rnd.render_all(tenant, ext, out=target, zetris_root=args.zetris_root,
                   features=ext.get("features"))
    config["ca_file"] = str(target / "lab-ca/ca.crt")
    config["scripts_root"] = str(reg.ZETRIS_DEFAULT)
    return stp.Context(tenant=tenant, ext=ext, config=config, secrets=secrets_map,
                       out_dir=target, runner=stp.Runner(mode=mode, apply_token=token),
                       admin_password=secrets.token_urlsafe(24))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--zetris-root", type=Path,
                        default=Path(os.environ.get("ZETRIS_ROOT", str(reg.ZETRIS_DEFAULT))),
                        help="Path to the lead's zetris-views tree (read-only)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="Validate the whole registry")
    p.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)

    p = sub.add_parser("plan", help="Print the full provisioning plan")
    p.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    p.add_argument("--tenant", help="Only show this tenant")

    p = sub.add_parser("steps", help="Print the ordered step list for one tenant")
    p.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    p.add_argument("--tenant", required=True)

    p = sub.add_parser("render", help="Render all preview artifacts (no live changes)")
    p.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    p.add_argument("--tenant", required=True)
    p.add_argument("--out", type=Path, required=True, help="Output folder inside tenant-control-plane")

    p = sub.add_parser("run", help="Preview (default) or explicitly apply all steps")
    p.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    p.add_argument("--tenant", required=True)
    p.add_argument("--config", type=Path, default=ROOT / "config/portal.example.json")
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--apply", action="store_true", help="Live actions; requires --confirm")
    p.add_argument("--confirm", default="", help="Explicit confirmation token for live actions")

    p = sub.add_parser("rotate", help="Rotate one tenant's secrets (preview by default)")
    p.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    p.add_argument("--tenant", required=True)
    p.add_argument("--config", type=Path, default=ROOT / "config/portal.example.json")
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--apply", action="store_true")
    p.add_argument("--confirm", default="")

    p = sub.add_parser("acceptance", help="Structural acceptance matrix for two tenants")
    p.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    p.add_argument("--tenant-a", required=True)
    p.add_argument("--tenant-b", required=True)
    p.add_argument("--out", type=Path, default=ROOT / "provisioned")

    for command, help_text in (
        ("suspend", "Stop a tenant's stacks (preview by default)"),
        ("resume", "Start a tenant's stacks (preview by default)"),
        ("backup", "Plan volume backups for a tenant"),
        ("delete", "Tear down a tenant (guarded; never runs in preview)"),
        ("client", "Issue a one-time NetBird setup key for client onboarding"),
    ):
        p = sub.add_parser(command, help=help_text)
        p.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
        p.add_argument("--tenant", required=True)
        p.add_argument("--config", type=Path, default=ROOT / "config/portal.example.json")
        p.add_argument("--out", type=Path, default=None)
        p.add_argument("--apply", action="store_true")
        p.add_argument("--confirm", default="")

    p = sub.add_parser("new-registry", help="Write a canary registry (no secrets)")
    p.add_argument("--out", type=Path, default=DEFAULT_REGISTRY)
    p.add_argument("--slug", default="canary")
    p.add_argument("--domain", default="ztna.local.test")
    p.add_argument("--tier", default="free", choices=sorted(reg.TIERS))
    p.add_argument("--email", default="admin@canary.test")
    p.add_argument("--slot", type=int, default=0)

    args = parser.parse_args(argv)

    if args.command == "new-registry":
        tenant, extra = reg.build_tenant(args.slug, args.domain, args.tier, args.email, slot=args.slot)
        data = {"schema_version": 1, "tenants": [tenant], "tenant_ext": {args.slug: extra}}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote registry for {args.slug} (free tier = {reg.TIERS[args.tier]['max_users']} users); no secrets stored")
        return 0

    tenants, ext = reg.validate(args.registry, args.zetris_root)
    if args.command == "validate":
        print(f"Valid registry: {len(tenants)} tenant(s); tiers: " + ", ".join(ext[t['id']]['tier'] for t in tenants))
        return 0

    selected = [t for t in tenants if not getattr(args, "tenant", None) or t["id"] == args.tenant]
    if not selected:
        raise reg.ControlError("Requested tenant is not in the registry")

    if args.command == "plan":
        print(json.dumps({"dry_run": True, "plans": [
            {"tenant": t["id"], "tier": ext[t["id"]]["tier"],
             "hosts": [t[k] for k in ("application_host", "audit_hostname", "netbird_hostname")],
             "operations": rnd.plan(t, ext[t["id"]])} for t in selected]}, indent=2))
        return 0

    if args.command == "steps":
        for step in rnd.plan(selected[0], ext[selected[0]["id"]]):
            print(f"{step['step']:20} {step['action']}")
        return 0

    if args.command == "run":
        tenant = selected[0]
        ctx = build_context(args, tenant, ext[tenant["id"]])
        records = stp.run_all(ctx)
        print(json.dumps({"tenant": tenant["id"], "mode": ctx.runner.mode, "records": records,
                          "planned_operations": len(ctx.runner.operations)}, indent=2))
        return 0

    if args.command in ("suspend", "resume", "backup", "delete", "client"):
        from . import lifecycle as life
        from . import client as cli_client
        tenant = selected[0]
        ctx = build_context(args, tenant, ext[tenant["id"]])
        if args.command == "suspend":
            result = life.suspend(ctx)
        elif args.command == "resume":
            result = life.resume(ctx)
        elif args.command == "backup":
            result = life.backup(ctx)
        elif args.command == "delete":
            result = life.delete(ctx)
        else:
            result = cli_client.issue_setup_key(ctx)
        print(json.dumps({"tenant": tenant["id"], "mode": ctx.runner.mode,
                          "result": result,
                          "planned_operations": len(ctx.runner.operations)}, indent=2))
        return 0

    if args.command == "rotate":
        from . import secrets as sec
        tenant = selected[0]
        ctx = build_context(args, tenant, ext[tenant["id"]])
        result = sec.rotate(ctx)
        print(json.dumps({"tenant": tenant["id"], "result": result,
                          "planned_operations": len(ctx.runner.operations)}, indent=2))
        return 0

    if args.command == "acceptance":
        from . import acceptance as acc
        by_id = {t["id"]: t for t in tenants}
        outs = [args.out / slug for slug in (args.tenant_a, args.tenant_b)]
        results = acc.structural([by_id[args.tenant_a], by_id[args.tenant_b]],
                                 [ext[args.tenant_a], ext[args.tenant_b]], outs)
        failed = [item for item in results if item["status"] == "fail"]
        print(json.dumps({"mode": "structural", "results": results,
                          "passed": len(results) - len(failed), "failed": len(failed)}, indent=2))
        return 1 if failed else 0

    if args.command == "render":
        for tenant in selected:
            manifest = rnd.render_all(tenant, ext[tenant["id"]],
                                      out=args.out / tenant["id"],
                                      zetris_root=args.zetris_root)
            print(f"Rendered {manifest['tenant']}: " + ", ".join(
                f"{key}={len(value)}" for key, value in manifest["artifacts"].items()))
            print("Preview secrets are ephemeral and were never read from disk.")
        return 0

    raise reg.ControlError("Unknown command")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except reg.ControlError as error:
        raise SystemExit(str(error)) from None
