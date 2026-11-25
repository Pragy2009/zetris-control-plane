"""Tenant lifecycle actions. Preview by default; destructive apply is guarded.

All container operations go through Runner, so preview records the exact
commands without executing anything. Deletion never happens in preview mode.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from . import registry as reg
from .steps import Context, StepError, _token_request
from . import tokens as tenant_tokens

PLANES = ("netbird", "audit", "access-gateway", "access-connector")


def compose_files(ctx: Context):
    return [(plane, ctx.out_dir / plane / "compose.json") for plane in PLANES
            if (ctx.out_dir / plane / "compose.json").is_file()]


def suspend(ctx: Context):
    files = compose_files(ctx)
    if not files:
        raise StepError("No rendered tenant stack found")
    for plane, path in files:
        ctx.runner.command(["docker", "compose", "-f", path, "stop"], timeout=180)
    return {"status": "suspended", "planes": [plane for plane, _ in files]}


def resume(ctx: Context):
    files = compose_files(ctx)
    if not files:
        raise StepError("No rendered tenant stack found")
    for plane, path in files:
        ctx.runner.command(["docker", "compose", "-f", path, "up", "-d", "--wait"], timeout=240)
    return {"status": "running", "planes": [plane for plane, _ in files]}


def backup(ctx: Context):
    target = Path(ctx.config.get("backup_dir", str(ctx.out_dir / "backups")))
    ctx.runner.command(["mkdir", "-p", str(target)])
    for plane, path in compose_files(ctx):
        project = ctx.tenant["netbird_stack"] + ("-" + plane if plane != "netbird" else "")
        ctx.runner.command([
            "docker", "run", "--rm",
            "-v", project + "_data:/data:ro",
            "-v", str(target) + ":/backup",
            "alpine", "tar", "czf", "/backup/" + project + ".tar.gz", "-C", "/data", "."])
    return {"status": "backup planned", "target": str(target)}


def delete(ctx: Context):
    """Tear down every plane. Apply requires the explicit confirmation token."""
    if ctx.runner.mode == "apply":
        ctx.runner.ensure_apply()
    files = compose_files(ctx)
    for plane, path in files:
        ctx.runner.command(["docker", "compose", "-f", path, "down", "-v", "--remove-orphans"], timeout=240)
    gateway = ctx.config.get("gateway_container", "zetris-control-plane-tenant-gateway-1")
    for plane in PLANES:
        ctx.runner.command(["docker", "exec", gateway, "rm", "-f",
                            "/etc/caddy/tenants/" + ctx.tenant["id"] + "-" + plane + ".caddy"])
    ctx.runner.command(["docker", "exec", gateway, "caddy", "reload", "--config", "/etc/caddy/Caddyfile"])

    if ctx.runner.mode == "apply":
        # Keycloak realm deletion (identity plane).
        token = _token_request(ctx)
        ctx.runner.http("DELETE", ctx.config["keycloak"]["origin"] +
                        "/admin/realms/" + ctx.tenant["realm"],
                        headers={"Authorization": "Bearer " + token})
        # PostgreSQL logical database and role.
        import psycopg
        pg = ctx.config["postgres"]
        environ = {"PGPASSWORD": ctx.secrets[pg["password_env"]]}
        with psycopg.connect(host=pg["host"], port=pg["port"], user=pg["admin_user"],
                             dbname="postgres", password=environ["PGPASSWORD"],
                             sslmode=pg.get("sslmode", "verify-full"), autocommit=True) as conn:
            conn.execute('DROP DATABASE IF EXISTS "' + ctx.tenant["netbird_database"] + '"')
            conn.execute('DROP ROLE IF EXISTS "' + ctx.tenant["netbird_database_role"] + '"')
        # Only a path inside this module may be removed.
        root = Path(__file__).resolve().parents[1].resolve()
        target = ctx.out_dir.resolve()
        if target == root or root not in target.parents:
            raise StepError("Refusing to remove an output outside the control-plane folder")
        shutil.rmtree(target)
        tenant_tokens.forget(ctx.tenant["id"])
    return {"status": "deleted" if ctx.runner.mode == "apply" else "deletion planned",
            "planes": [plane for plane, _ in files]}
