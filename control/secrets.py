"""Per-tenant secret rotation. Never reads or writes a .env file.

New values are generated in memory. In apply mode the service APIs are called
and one 0600 file is written for the operator to paste into Dokploy's
Environment tab. Diagnostics and Runner logs never contain any value.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import secrets as rng
from pathlib import Path

from .steps import Context, _token_request

MODULE_ROOT = Path(__file__).resolve().parents[1]


def rotate(ctx: Context):
    if ctx.runner.mode == "apply":
        ctx.runner.ensure_apply()
    new = {field: rng.token_urlsafe(32) for field in ctx.tenant["secret_refs"]}
    kc = ctx.config["keycloak"]

    # 1. PostgreSQL role password: SCRAM verifier over a direct connection,
    #    never as a process argument.
    if ctx.runner.mode == "apply":
        import psycopg
        from psycopg import sql
        pg = ctx.config["postgres"]
        with psycopg.connect(host=pg["host"], port=pg["port"], user=pg["admin_user"],
                             dbname="postgres", password=ctx.secrets[pg["password_env"]],
                             sslmode=pg.get("sslmode", "verify-full"), autocommit=True) as conn:
            verifier = conn.pgconn.encrypt_password(
                new["database_password"].encode(),
                ctx.tenant["netbird_database_role"].encode(), b"scram-sha-256").decode()
            conn.execute('ALTER ROLE "' + ctx.tenant["netbird_database_role"] +
                         '" PASSWORD ' + sql.Literal(verifier).as_string(conn))
    else:
        ctx.runner.command(["psql", "ALTER ROLE", ctx.tenant["netbird_database_role"],
                            "PASSWORD", "<rotated in apply mode>"])

    # 2. Keycloak confidential clients.
    token = _token_request(ctx)
    for client_id in (ctx.tenant["connector_oidc_client_id"],
                      ctx.tenant["audit_oidc_client_id"],
                      ctx.tenant["netbird_oidc_client_id"]):
        found = ctx.runner.http(
            "GET", kc["origin"] + "/admin/realms/" + ctx.tenant["realm"] +
            "/clients?clientId=" + client_id,
            headers={"Authorization": "Bearer " + token})
        internal = found[0]["id"] if ctx.runner.mode == "apply" and found else "<client-id>"
        ctx.runner.http(
            "PUT", kc["origin"] + "/admin/realms/" + ctx.tenant["realm"] +
            "/clients/" + str(internal),
            body={"secret": new["keycloak_client_secret"] if ctx.runner.mode == "apply" else "<rotated>"},
            headers={"Authorization": "Bearer " + token})

    # 3. ClickHouse audit user (same sha256 scheme as the provisioner).
    digest = hashlib.sha256(new["audit_clickhouse_password"].encode()).hexdigest()
    ctx.runner.http(
        "POST", ctx.config["clickhouse"]["origin"],
        body={"sql": "ALTER USER `" + ctx.tenant["id"] +
              "` IDENTIFIED WITH sha256_hash BY '" +
              (digest if ctx.runner.mode == "apply" else "<rotated>") + "'"},
        headers={"X-ClickHouse-User": ctx.config["clickhouse"]["admin_user"]})

    result = {
        "tenant": ctx.tenant["id"],
        "mode": ctx.runner.mode,
        "env_vars_to_update": sorted(ctx.tenant["secret_refs"].values()),
        "manual_followups": [
            "Enter the new values in Dokploy's Environment tab yourself.",
            "Update the Redis ACL with provision-audit-data.py using the new audit password.",
            "Recreate the tenant stacks so they pick up the new client secrets.",
        ],
        "note": "Values are never printed and never read from a .env file.",
    }
    if ctx.runner.mode == "apply":
        out = MODULE_ROOT / "state" / ("rotation-" + ctx.tenant["id"] + ".json")
        out.parent.mkdir(mode=0o700, exist_ok=True)
        descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with io.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({ctx.tenant["secret_refs"][field]: value for field, value in new.items()},
                      stream, indent=2)
        result["one_time_file"] = str(out)
        result["fingerprints"] = {name: hashlib.sha256(value.encode()).hexdigest()[:12]
                                  for name, value in new.items()}
    return result
