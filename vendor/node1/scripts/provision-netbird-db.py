#!/usr/bin/env python3
"""Preview or provision tenant NetBird databases. Dry-run is the default.

Credentials come from environment references. SQL/errors never print them.
Existing stores are not migrated, deleted, renamed or silently adopted.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tenant_registry", Path(__file__).with_name("provision-tenant.py"))
registry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry)
LOCK_ID = 736894125


class ProvisionError(RuntimeError):
    """A safe diagnostic that does not contain secrets or SQL text."""


def marker(tenant, resource):
    return "zetris.netbird.v1:" + tenant["id"] + ":" + resource


def validate_database_names(tenants):
    special = {"all", "sameuser", "samerole", "samegroup", "replication"}
    for tenant in tenants:
        database, role = tenant["netbird_database"], tenant["netbird_database_role"]
        if database in special | {"postgres", "template0", "template1"}:
            raise ProvisionError("Tenant database names must not be HBA keywords or system databases")
        if role in special | {"public", "postgres"} or role.startswith("pg_"):
            raise ProvisionError("Tenant role names must not be HBA keywords or system roles")


def hba_rules(tenants):
    validate_database_names(tenants)
    rules = []
    for tenant in tenants:
        db, role = tenant["netbird_database"], tenant["netbird_database_role"]
        rules.extend([
            ("local", [db], [role], None, None, "scram-sha-256"),
            ("host", [db], [role], "0.0.0.0", "0.0.0.0", "scram-sha-256"),
            ("host", [db], [role], "::", "::", "scram-sha-256"),
        ])
    roles = [tenant["netbird_database_role"] for tenant in tenants]
    rules.extend([
        ("local", ["all"], roles, None, None, "reject"),
        ("host", ["all"], roles, "0.0.0.0", "0.0.0.0", "reject"),
        ("host", ["all"], roles, "::", "::", "reject"),
    ])
    return rules


def render_hba(tenants):
    lines = ["# BEGIN ZETRIS TENANT DATABASE RULES (before generic allow rules)"]
    for kind, databases, roles, address, _, method in hba_rules(tenants):
        fields = [kind, ",".join(databases), ",".join(roles)]
        if address is not None:
            fields.append(address + "/0")
        fields.append(method)
        lines.append(" ".join(fields))
    lines.append("# END ZETRIS TENANT DATABASE RULES")
    return "\n".join(lines) + "\n"


def verify_hba(conn, tenants):
    rows = conn.execute(
        "SELECT type, database, user_name, address, netmask, auth_method, error "
        "FROM pg_hba_file_rules ORDER BY line_number"
    ).fetchall()
    expected = hba_rules(tenants)
    if any(row[6] for row in rows) or [tuple(row[:6]) for row in rows[:len(expected)]] != expected:
        raise ProvisionError("Install and reload the generated tenant HBA rules before provisioning")


def resolve_passwords(tenants, environ):
    passwords = {}
    for tenant in tenants:
        name = tenant["secret_refs"]["database_password"].split(":", 1)[1]
        value = environ.get(name, "")
        if len(value) < 24 or "\x00" in value:
            raise ProvisionError("Each selected tenant needs a database password of at least 24 characters")
        if value in passwords.values():
            raise ProvisionError("Selected tenants must not share a database password")
        passwords[tenant["id"]] = value
    return passwords


def driver():
    try:
        import psycopg
        from psycopg import sql
    except ImportError:
        raise ProvisionError("Install scripts/requirements-db.txt before using --apply") from None
    return psycopg, sql


def inspect_resources(conn, tenant):
    role_name, db_name = tenant["netbird_database_role"], tenant["netbird_database"]
    role = conn.execute(
        "SELECT oid, rolsuper, rolcreatedb, rolcreaterole, rolreplication, "
        "rolbypassrls, rolcanlogin, rolinherit, shobj_description(oid, 'pg_authid') "
        "FROM pg_roles WHERE rolname = %s", (role_name,)
    ).fetchone()
    db = conn.execute(
        "SELECT pg_get_userbyid(datdba), shobj_description(oid, 'pg_database') "
        "FROM pg_database WHERE datname = %s", (db_name,)
    ).fetchone()
    if "existing_database" in tenant:
        if conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (tenant["existing_database"],)).fetchone():
            raise ProvisionError("An existing tenant store needs a separate migration; no replacement is provisioned")
    if role:
        if (role[8] != marker(tenant, "role") or any(role[1:6])
                or not role[6] or role[7]):
            raise ProvisionError("Existing database role has conflicting ownership or unsafe privileges")
        memberships = conn.execute(
            "SELECT count(*) FROM pg_auth_members WHERE member = %s OR roleid = %s", (role[0], role[0])
        ).fetchone()[0]
        if memberships:
            raise ProvisionError("Tenant database roles must not have role memberships")
    if db and (not role or db[0] != role_name or db[1] != marker(tenant, "database")):
        raise ProvisionError("Existing database is not owned by this managed tenant role")
    return role, db


def connection_options(args, user, database, password):
    return {
        "host": args.host, "port": args.port, "user": user, "dbname": database,
        "password": password, "sslmode": args.sslmode, "connect_timeout": 5,
        "application_name": "zetris-tenant-db-provisioner", "autocommit": True,
    }


def verify_login(psycopg, args, tenant, password):
    try:
        with psycopg.connect(**connection_options(args, tenant["netbird_database_role"], tenant["netbird_database"], password)) as conn:
            current = conn.execute("SELECT current_user, current_database()").fetchone()
            if current != (tenant["netbird_database_role"], tenant["netbird_database"]):
                raise ProvisionError("Tenant login identity does not match desired ownership")
    except psycopg.Error:
        raise ProvisionError("Tenant credentials could not be verified; existing passwords are not rotated") from None


def access_denied(error):
    if error.sqlstate in ("28000", "42501"):
        return True
    # libpq does not expose SQLSTATE for every connection-startup error.
    # Recognize only explicit PostgreSQL denial messages, never timeouts,
    # bad passwords, missing databases or certificate failures. Other locales
    # without SQLSTATE fail verification rather than being treated as denial.
    return error.sqlstate is None and any(text in str(error) for text in (
        "pg_hba.conf rejects connection", "permission denied for database",
    ))


def verify_foreign_denial(psycopg, args, tenant, password, databases):
    # pg_hba_file_rules describes the file, not necessarily the last loaded
    # rules. Real connection attempts also detect a missing reload.
    for database in databases:
        if database == tenant["netbird_database"]:
            continue
        try:
            with psycopg.connect(**connection_options(args, tenant["netbird_database_role"], database, password)):
                pass
        except psycopg.OperationalError as error:
            if access_denied(error):
                continue
            raise ProvisionError("Could not verify foreign-database denial; details withheld") from None
        raise ProvisionError("Tenant role can connect to a foreign database; reload the required HBA rules")


def provision(args, all_tenants, selected, environ=None):
    validate_connection(args)
    validate_database_names(all_tenants)
    environ = os.environ if environ is None else environ
    passwords = resolve_passwords(selected, environ)
    admin_password = environ.get("PGPASSWORD", "")
    if not admin_password:
        raise ProvisionError("PGPASSWORD must supply the provisioning administrator password")
    psycopg, sql = driver()
    results = []
    try:
        with psycopg.connect(**connection_options(args, args.admin_user, args.maintenance_database, admin_password)) as conn:
            # A dedicated privileged provisioner performs catalog/HBA checks.
            # Tenant roles never receive these privileges.
            if not conn.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()[0]:
                raise ProvisionError("A trusted PostgreSQL provisioning administrator is required")
            conn.execute("SELECT pg_advisory_lock(%s)", (LOCK_ID,))
            try:
                verify_hba(conn, all_tenants)
                databases = [row[0] for row in conn.execute("SELECT datname FROM pg_database WHERE datallowconn").fetchall()]
                existing = {}
                # Check every selected ownership conflict before the first DDL.
                for tenant in selected:
                    existing[tenant["id"]] = inspect_resources(conn, tenant)
                    role, database = existing[tenant["id"]]
                    if role and database:
                        verify_login(psycopg, args, tenant, passwords[tenant["id"]])
                        verify_foreign_denial(psycopg, args, tenant, passwords[tenant["id"]], databases)
                for tenant in selected:
                    role, database = existing[tenant["id"]]
                    role_id, db_id = sql.Identifier(tenant["netbird_database_role"]), sql.Identifier(tenant["netbird_database"])
                    if role is None:
                        # Send a SCRAM verifier instead of the plaintext tenant
                        # password in the CREATE ROLE statement.
                        verifier = conn.pgconn.encrypt_password(
                            passwords[tenant["id"]].encode(), tenant["netbird_database_role"].encode(), b"scram-sha-256"
                        ).decode()
                        with conn.transaction():
                            conn.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD {}").format(role_id, sql.Literal(verifier)))
                            conn.execute(sql.SQL("COMMENT ON ROLE {} IS {}").format(role_id, sql.Literal(marker(tenant, "role"))))
                    if database is None:
                        # CREATE DATABASE cannot run in a transaction. If a
                        # later step fails, retain data and report the failure.
                        conn.execute(sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0").format(db_id, role_id))
                        conn.execute(sql.SQL("COMMENT ON DATABASE {} IS {}").format(db_id, sql.Literal(marker(tenant, "database"))))
                    with conn.transaction():
                        conn.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(db_id))
                        conn.execute(sql.SQL("GRANT CONNECT, TEMPORARY ON DATABASE {} TO {}").format(db_id, role_id))
                    with psycopg.connect(**connection_options(args, args.admin_user, tenant["netbird_database"], admin_password)) as database_conn:
                        with database_conn.transaction():
                            database_conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
                            database_conn.execute(sql.SQL("GRANT USAGE, CREATE ON SCHEMA public TO {}").format(role_id))
                    verify_login(psycopg, args, tenant, passwords[tenant["id"]])
                    databases = [row[0] for row in conn.execute("SELECT datname FROM pg_database WHERE datallowconn").fetchall()]
                    verify_foreign_denial(psycopg, args, tenant, passwords[tenant["id"]], databases)
                    results.append({"tenant": tenant["id"], "database": tenant["netbird_database"],
                        "role": tenant["netbird_database_role"], "state": "verified", "password": "created" if role is None else "preserved"})
            finally:
                conn.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))
    except psycopg.Error as error:
        code = error.sqlstate or "unavailable"
        raise ProvisionError("PostgreSQL provisioning failed; SQLSTATE " + code + "; details withheld") from None
    return results


def validate_connection(args):
    if not 1 <= args.port <= 65535:
        raise ProvisionError("Invalid PostgreSQL port")
    if args.sslmode == "disable":
        try:
            loopback = args.host == "localhost" or ipaddress.ip_address(args.host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise ProvisionError("Plaintext PostgreSQL is permitted only for the loopback test fixture")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=ROOT / "config/tenants.json")
    parser.add_argument("--tenant")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--print-hba", action="store_true", help="Print the required non-secret connection rules")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--admin-user", default=os.environ.get("PGUSER", "postgres"))
    parser.add_argument("--maintenance-database", default="postgres")
    parser.add_argument("--sslmode", choices=("verify-full", "disable"), default="verify-full")
    args = parser.parse_args(argv)
    all_tenants = registry.load_registry(args.registry)
    validate_database_names(all_tenants)
    selected = [tenant for tenant in all_tenants if args.tenant is None or tenant["id"] == args.tenant]
    if not selected:
        raise ProvisionError("Requested tenant is not present in the registry")
    if args.print_hba:
        if args.apply:
            raise ProvisionError("--print-hba and --apply are separate operations")
        print(render_hba(all_tenants), end="")
        return 0
    validate_connection(args)
    if not args.apply:
        print(json.dumps({"dry_run": True, "databases": [
            {"tenant": tenant["id"], "database": tenant["netbird_database"], "role": tenant["netbird_database_role"],
             "migration_required": "existing_database" in tenant} for tenant in selected
        ], "requires": ["tenant HBA rules installed and reloaded", "provisioning administrator", "private password references"]}, indent=2))
        return 0
    print(json.dumps({"dry_run": False, "databases": provision(args, all_tenants, selected)}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ProvisionError, registry.RegistryError) as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        raise SystemExit("Database provisioning failed: " + type(error).__name__ + "; details withheld") from None
