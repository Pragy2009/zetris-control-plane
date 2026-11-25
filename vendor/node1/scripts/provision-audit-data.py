#!/usr/bin/env python3
"""Provision owned tenant audit views and Redis ACLs; preview is the default.

No base-table row policies, broad-user changes, password rotation or deletion.
Backend credentials and SQL responses are withheld from diagnostics.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tenant_registry", ROOT / "scripts/provision-tenant.py")
registry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry)
TABLES = ("risk_events", "session_activity_features", "envoy_access_logs")
VERSION = "zetris.audit.v1:"


class DataError(RuntimeError):
    """A credential-free deployment diagnostic."""


def names(tenant):
    return "audit_"+tenant["id"], "audit_"+tenant["id"].replace("-", "_")


def marker(tenant):
    return VERSION+tenant["id"]


def owner_role(tenant):
    return "zetris_audit_owner_v1_"+tenant["id"].replace("-", "_")


def quoted(value):
    return "'"+value.replace("\\", "\\\\").replace("'", "\\'")+"'"


def selector_rules(tenant):
    prefix = "tenant:"+tenant["id"]
    return ["(~"+prefix+":session:* +hgetall +hget +type)",
            "(~"+prefix+":live_sessions +zrangebyscore)",
            "(~"+prefix+":blocked_sessions +smembers +sismember +srem)",
            "(~zetris:audit-owner:v1:"+tenant["id"]+" -@all)"]


def user_rules(tenant, password):
    return ["reset", "on", "#"+hashlib.sha256(password.encode()).hexdigest(), "-@all",
            "+ping", "+hello", "+client|setname", "+client|setinfo", *selector_rules(tenant)]


FINAL_TABLES = {"risk_events", "session_activity_features"}  # Merge-tree family that supports dedup reads


def view_select(tenant, table):
    final = " FINAL" if table in FINAL_TABLES else ""
    return "SELECT * FROM default."+table+final+" WHERE tenant_id = "+quoted(tenant["id"])


def compact_sql(sql):
    # Tenant literals and identifiers are case-sensitive. Only normalize the
    # whitespace/backticks introduced by ClickHouse's canonical serialization.
    return re.sub(r"\s+", "", sql.replace("`", ""))


def check_view(tenant, table, row, admin):
    definition = row.get("create_table_query", "")
    match = re.search(r"\bAS\s+(.*?)(?:\s+COMMENT\s+|$)", definition, re.S|re.I)
    selection = match[1].strip() if match else ""
    if selection.startswith("(") and selection.endswith(")"):
        selection = selection[1:-1]
    tenant_filter = re.search(r"\bWHERE\s+`?tenant_id`?\s*=\s*'([A-Za-z0-9_-]+)'\s*$",selection,re.I)
    definer = re.search(r"\bDEFINER\s*=\s*([^\s]+)\s+SQL\s+SECURITY\s+DEFINER\b", definition, re.I)
    if (row.get("engine") != "View" or row.get("comment") != marker(tenant)
            or not match or not tenant_filter or tenant_filter[1] != tenant["id"]
            or compact_sql(selection) != compact_sql(view_select(tenant, table))
            or not definer or definer[1].strip("`'") != admin):
        raise DataError("Existing audit view has different ownership, filtering or SQL security")


def command_set(value):
    return set(value if isinstance(value,list) else value.split())


def redis_shape(user):
    selectors = []
    for item in user.get("selectors", []):
        if isinstance(item,list):
            item = dict(zip(item[::2],item[1::2]))
        selectors.append((tuple(sorted(command_set(item.get("keys", "")))),
            tuple(sorted(command_set(item.get("commands", "")))),tuple(sorted(command_set(item.get("channels", ""))))))
    return {"commands": command_set(user.get("commands", "")) | command_set(user.get("categories", [])),
        "keys": command_set(user.get("keys", "")), "channels": command_set(user.get("channels", "")), "selectors": sorted(selectors)}


def expected_redis_shape(tenant):
    prefix = "tenant:"+tenant["id"]
    return {"commands": {"-@all", "+ping", "+hello", "+client|setname", "+client|setinfo"}, "keys": set(), "channels": set(),
        "selectors": sorted([(("~"+prefix+":session:*",), tuple(sorted(("-@all", "+hgetall", "+hget", "+type"))), ()),
            (("~"+prefix+":live_sessions",), tuple(sorted(("-@all", "+zrangebyscore"))), ()),
            (("~"+prefix+":blocked_sessions",), tuple(sorted(("-@all", "+smembers", "+sismember", "+srem"))), ()),
            (("~zetris:audit-owner:v1:"+tenant["id"],), ("-@all",), ())])}


def resolve(tenants, environ):
    result, seen = {}, set()
    for tenant in tenants:
        values = {}
        for field in ("audit_clickhouse_password", "audit_redis_password"):
            ref = tenant["secret_refs"].get(field, "")
            if not registry.SECRET_REF.fullmatch(ref):
                raise DataError("Audit data secret references are required")
            value = environ.get(ref.split(":", 1)[1], "")
            if len(value) < 24 or "\x00" in value or value in seen:
                raise DataError("Audit data credentials must be present, private and independently scoped")
            seen.add(value)
            values[field] = value
        result[tenant["id"]] = values
    return result


def inspect_ch(tenant, query, admin, password):
    user, database = names(tenant)
    databases = query("SELECT name,comment FROM system.databases WHERE name="+quoted(database)+" FORMAT JSONEachRow")
    if databases and (len(databases) != 1 or databases[0].get("comment") != marker(tenant)):
        raise DataError("Existing audit database is not owned by this tenant provisioner")
    views = query("SELECT name,engine,comment,create_table_query FROM system.tables WHERE database="+quoted(database)+" FORMAT JSONEachRow")
    if any(row.get("name") not in TABLES for row in views):
        raise DataError("Unexpected objects exist in the audit database")
    for row in views:
        check_view(tenant, row["name"], row, admin)
    role = owner_role(tenant)
    roles = query("SELECT name,id FROM system.roles WHERE name="+quoted(role)+" FORMAT JSONEachRow")
    if roles:
        role_grants = query("SHOW GRANTS FOR `"+role+"` FORMAT JSONEachRow")
        if role_grants or not databases:
            raise DataError("Existing audit ownership role has privileges or no owned database")
    users = query("SELECT name,auth_type,default_database,default_roles_all,default_roles_list,default_roles_except FROM system.users WHERE name="+quoted(user)+" FORMAT JSONEachRow")
    if users:
        row = users[0]
        if (len(users) != 1 or not roles or row.get("default_database") != database or row.get("default_roles_all") != 0
                or row.get("default_roles_list") != [role] or row.get("default_roles_except")
                or row.get("auth_type") != ["sha256_password"]):
            raise DataError("Existing audit user ownership/password differs; it was not adopted or rotated")
        if not hasattr(query,"identity") or query.identity(user,password) != [{"actor":user,"database":database}]:
            raise DataError("Existing audit credentials could not be verified; no password was rotated")
        permissions = query("SHOW GRANTS FOR `"+user+"` FORMAT JSONEachRow")
        allowed_tables = {database+"."+table for table in TABLES}
        for grant in permissions:
            statement = grant["statement"].replace("`", "")
            if statement == "GRANT "+role+" TO "+user:
                continue
            selection = re.fullmatch(r"GRANT SELECT ON (.+) TO "+re.escape(user), statement)
            if not selection or not {item.strip() for item in selection[1].split(",")} <= allowed_tables:
                raise DataError("Existing audit user has unexpected privileges or role membership")
    return bool(databases), {row["name"] for row in views}, bool(users), bool(roles)


def inspect_redis(tenant, client, password):
    user, _ = names(tenant)
    state = client.acl_getuser(user)
    if state is None:
        return False
    if ("on" not in state.get("flags", []) or "nopass" in state.get("flags", [])
            or state.get("passwords") != [hashlib.sha256(password.encode()).hexdigest()]
            or redis_shape(state) != expected_redis_shape(tenant)):
        raise DataError("Redis audit user password/permissions differ; no account was rewritten")
    return True


def backfill_index(tenant, client):
    prefix = "tenant:"+tenant["id"]+":session:"
    index = "tenant:"+tenant["id"]+":live_sessions"
    kind = client.type(index)
    if kind not in ("none", "zset"):
        raise DataError("Existing tenant session index has an incompatible type")
    clock = client.time()
    now = clock[0]*1000+clock[1]//1000
    client.zremrangebyscore(index, "-inf", now)
    # Only the trusted provisioner scans for legacy sessions. Audit users have
    # no SCAN/KEYS/EVAL permission. Existing hashes and TTLs are preserved.
    for key in client.scan_iter(match=prefix+"*", count=500):
        if client.type(key) != "hash":
            continue
        session = key[len(prefix):]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", session):
            continue
        ttl = client.pttl(key)
        if ttl == -2:
            continue
        client.eval("local ttl=redis.call('PTTL',KEYS[1]); if ttl == -2 then return 0 end; "
            "local t=redis.call('TIME'); local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000); "
            "redis.call('ZADD',KEYS[2],ttl<0 and '+inf' or now+ttl,ARGV[1]); return 1", 2, key, index, session)


def provision(tenants, query, redis_admin, admin, passwords):
    if not redis_admin.config_get("aclfile").get("aclfile"):
        raise DataError("Prepare a writable Redis ACL file before provisioning persistent audit accounts")
    token = secrets.token_urlsafe(32)
    lock = "zetris:audit-provision-lock"
    if not redis_admin.set(lock, token, nx=True):
        raise DataError("Audit provisioning is locked; inspect any interrupted operation")
    try:
        return apply(tenants, query, redis_admin, admin, passwords)
    finally:
        redis_admin.eval("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0", 1, lock, token)


def apply(tenants, query, redis_admin, admin, passwords):
    states = []
    # Check both backend ownership boundaries for every selected tenant first.
    for tenant in tenants:
        values = passwords[tenant["id"]]
        states.append((inspect_ch(tenant, query, admin, values["audit_clickhouse_password"]),
                       inspect_redis(tenant, redis_admin, values["audit_redis_password"])))
        if redis_admin.type("tenant:"+tenant["id"]+":live_sessions") not in ("none", "zset"):
            raise DataError("Tenant session index has an incompatible type")
    for tenant, ((exists, views, user_exists, role_exists), redis_exists) in zip(tenants, states):
        user, database = names(tenant)
        values = passwords[tenant["id"]]
        if not exists:
            query("CREATE DATABASE `"+database+"` COMMENT "+quoted(marker(tenant)))
        for table in TABLES:
            if table not in views:
                query("CREATE VIEW `"+database+"`.`"+table+"` DEFINER = `"+admin+"` SQL SECURITY DEFINER AS "+view_select(tenant, table)+" COMMENT "+quoted(marker(tenant)))
        if not user_exists:
            if not role_exists:
                query("CREATE ROLE `"+owner_role(tenant)+"`")
            query("CREATE USER `"+user+"` IDENTIFIED WITH sha256_hash BY '"+hashlib.sha256(values["audit_clickhouse_password"].encode()).hexdigest()+"' DEFAULT DATABASE `"+database+"` DEFAULT ROLE NONE")
            query("GRANT `"+owner_role(tenant)+"` TO `"+user+"`")
            query("ALTER USER `"+user+"` DEFAULT ROLE `"+owner_role(tenant)+"`")
        for table in TABLES:
            query("GRANT SELECT ON `"+database+"`.`"+table+"` TO `"+user+"`")
        if not redis_exists:
            redis_admin.execute_command("ACL", "SETUSER", user, *user_rules(tenant, values["audit_redis_password"]))
        backfill_index(tenant, redis_admin)
        inspect_ch(tenant, query, admin, values["audit_clickhouse_password"])
        inspect_redis(tenant, redis_admin, values["audit_redis_password"])
    redis_admin.acl_save()
    return [{"tenant": tenant["id"], "database": names(tenant)[1], "account": names(tenant)[0], "passwords": "preserved"} for tenant in tenants]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def ch_requester(origin, ca, user, password):
    parsed = urlparse(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise DataError("ClickHouse must use a credential-free HTTPS origin")
    context = ssl.create_default_context(cafile=str(ca))
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
    def query(sql):
        request = urllib.request.Request(origin, data=sql.encode(), headers={"X-ClickHouse-User": user, "X-ClickHouse-Key": password})
        try:
            with opener.open(request, timeout=20) as response:
                raw = response.read().decode()
            if sql.startswith("SHOW GRANTS"):
                return [{"statement": next(iter(json.loads(line).values()))} for line in raw.splitlines()]
            return [json.loads(line) for line in raw.splitlines()] if "FORMAT JSONEachRow" in sql else []
        except HTTPError as error:
            raise DataError("ClickHouse returned HTTP "+str(error.code)+"; SQL/response withheld") from None
        except (URLError, ValueError):
            raise DataError("Verified ClickHouse connection or response failed; details withheld") from None
    query.identity = lambda account, supplied: ch_requester(origin,ca,account,supplied)("SELECT currentUser() AS actor,currentDatabase() AS database FORMAT JSONEachRow")
    return query


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=ROOT/"config/tenants.json")
    parser.add_argument("--tenant")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--clickhouse-url", default="https://localhost:8443")
    parser.add_argument("--clickhouse-ca", type=Path)
    parser.add_argument("--redis-host", default="localhost")
    parser.add_argument("--redis-port", type=int, default=6380)
    parser.add_argument("--redis-ca", type=Path)
    args = parser.parse_args(argv)
    all_tenants = registry.load_registry(args.registry)
    tenants = [tenant for tenant in all_tenants if args.tenant is None or tenant["id"] == args.tenant]
    if not tenants:
        raise DataError("Selected tenant is absent")
    if not args.apply:
        print(json.dumps({"dry_run": True, "tenants": [{"tenant": tenant["id"], "account": names(tenant)[0], "database": names(tenant)[1],
            "clickhouse": "SELECT only on fixed tenant-filtered views", "redis": "owned session/index reads and owned block-set removal; no global scan"} for tenant in tenants]}, indent=2))
        return 0
    if args.clickhouse_ca is None or args.redis_ca is None:
        raise DataError("Verified backend CA files are required")
    passwords = resolve(tenants, os.environ)
    admin = os.environ.get("CH_ADMIN_USER", "default")
    ch_password, redis_password = os.environ.get("CH_ADMIN_PASSWORD", ""), os.environ.get("REDIS_ADMIN_PASSWORD", "")
    if not registry.IDENTIFIER.fullmatch(admin) or not ch_password or not redis_password:
        raise DataError("Trusted backend administrator identities/password references are required")
    import redis
    client = redis.Redis(host=args.redis_host, port=args.redis_port, username=os.environ.get("REDIS_ADMIN_USER", "default"),
        password=redis_password, ssl=True, ssl_ca_certs=str(args.redis_ca), ssl_check_hostname=True, decode_responses=True, socket_timeout=10)
    query = ch_requester(args.clickhouse_url, args.clickhouse_ca, admin, ch_password)
    try:
        result = provision(tenants, query, client, admin, passwords)
    finally:
        client.close()
    print(json.dumps({"applied": True, "tenants": result}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (DataError, registry.RegistryError) as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        raise SystemExit("Audit data provisioning failed: "+type(error).__name__+"; details withheld") from None
