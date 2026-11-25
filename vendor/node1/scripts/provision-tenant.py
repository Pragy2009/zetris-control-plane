#!/usr/bin/env python3
"""Validate tenant ownership and print a dry-run plan. No resources are changed.

This first build slice does not resolve secrets, connect to services, execute
commands, or write deployment files. The registry describes desired state.
"""
import argparse
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
DATABASE = re.compile(r"[a-z_][a-z0-9_]{0,62}")
STACK = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
SECRET_REF = re.compile(r"env:[A-Z][A-Z0-9_]{0,127}")
REQUIRED = {
    "id", "realm", "issuer", "netbird_stack", "netbird_hostname",
    "netbird_database", "netbird_database_role", "dashboard_port",
    "management_port", "stun_port", "connector_id", "application_host",
    "policy_file", "telemetry_user", "secret_refs",
}
OPTIONAL = {"existing_database", "netbird_oidc_client_id", "gateway_id", "connector_oidc_client_id",
            "audit_hostname", "audit_oidc_client_id", "audit_port"}
SECRET_FIELDS = {"database_password", "netbird_auth_secret"}
OPTIONAL_SECRET_FIELDS = {"keycloak_client_secret", "gateway_setup_key", "connector_setup_key",
                          "connector_client_secret", "connector_hmac_secret", "telemetry_password",
                          "audit_clickhouse_password", "audit_redis_password", "audit_client_secret"}


class RegistryError(ValueError):
    """Configuration is invalid. Error messages never include input values."""


def unique_json_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError("Duplicate JSON field")
        result[key] = value
    return result


def require_string(record, field, pattern):
    value = record.get(field)
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise RegistryError("Invalid " + field)
    return value


def require_hostname(record, field):
    value = record.get(field)
    if (not isinstance(value, str) or len(value) > 253 or "." not in value
            or not all(DNS_LABEL.fullmatch(label) for label in value.split("."))):
        raise RegistryError("Invalid " + field)
    return value


def validate_issuer(tenant):
    value = tenant.get("issuer")
    if not isinstance(value, str):
        raise RegistryError("Invalid issuer")
    try:
        parsed = urlparse(value)
        parsed.port  # Reject malformed ports before generating any configuration.
    except ValueError:
        raise RegistryError("Invalid issuer") from None
    parts = parsed.path.strip("/").split("/")
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.params
            or "%" in parsed.path or "//" in parsed.path
            or any(part in (".", "..") for part in parts)
            or len(parts) < 2 or parts[-2] != "realms"
            or parts[-1] != tenant["realm"] or parsed.path.endswith("/")):
        raise RegistryError("Issuer must be an exact HTTPS Keycloak realm URL")


def validate_registry(registry):
    if (not isinstance(registry, dict) or set(registry) != {"schema_version", "tenants"}
            or type(registry["schema_version"]) is not int or registry["schema_version"] != 1
            or not isinstance(registry["tenants"], list) or not registry["tenants"]):
        raise RegistryError("Expected registry schema version 1 and a nonempty tenant list")
    seen = {}

    def reserve(kind, value):
        if value in seen.setdefault(kind, set()):
            raise RegistryError("Duplicate ownership for " + kind)
        seen[kind].add(value)

    for tenant in registry["tenants"]:
        if (not isinstance(tenant, dict) or not REQUIRED <= set(tenant)
                or set(tenant) - REQUIRED - OPTIONAL):
            raise RegistryError("Tenant fields are missing or unsupported")
        for field in ("id", "realm", "connector_id"):
            require_string(tenant, field, IDENTIFIER)
            reserve(field, tenant[field])
        if tenant["id"] != tenant["realm"]:
            raise RegistryError("Tenant ID must match its Keycloak realm")
        reserve("policy package", tenant["id"].replace("-", "_"))
        require_string(tenant, "netbird_stack", STACK)
        reserve("netbird_stack", tenant["netbird_stack"])
        for field in ("netbird_database", "netbird_database_role"):
            require_string(tenant, field, DATABASE)
            reserve(field, tenant[field])
        if "existing_database" in tenant:
            require_string(tenant, "existing_database", DATABASE)
            reserve("existing_database", tenant["existing_database"])
            if tenant["existing_database"] == tenant["netbird_database"]:
                raise RegistryError("Migration source and desired database must differ")
        for field in ("netbird_hostname", "application_host"):
            reserve("hostname", require_hostname(tenant, field))
        if any(field in tenant for field in ("audit_hostname", "audit_oidc_client_id", "audit_port")):
            if not {"audit_hostname", "audit_oidc_client_id", "audit_port"} <= set(tenant):
                raise RegistryError("Audit deployment requires its host, client and loopback port")
            reserve("hostname", require_hostname(tenant, "audit_hostname"))
            require_string(tenant, "audit_oidc_client_id", IDENTIFIER)
            if type(tenant["audit_port"]) is not int or not 1024 <= tenant["audit_port"] <= 65535:
                raise RegistryError("Invalid audit_port")
            reserve("tcp port", tenant["audit_port"])
        validate_issuer(tenant)
        reserve("issuer", tenant["issuer"])
        if tenant["policy_file"] != tenant["id"] + ".rego":
            raise RegistryError("Policy filename must match its tenant")
        if tenant["telemetry_user"] != "ingest_" + tenant["id"]:
            raise RegistryError("Telemetry account must match its tenant")
        for field in ("dashboard_port", "management_port", "stun_port"):
            port = tenant[field]
            if type(port) is not int or not 1024 <= port <= 65535:
                raise RegistryError("Invalid " + field)
            # Dashboard and management bind the same loopback host. UDP has
            # its own port namespace, but each tenant's STUN port stays unique.
            reserve("udp port" if field == "stun_port" else "tcp port", port)
        refs = tenant["secret_refs"]
        if (not isinstance(refs, dict) or not SECRET_FIELDS <= set(refs)
                or set(refs) - SECRET_FIELDS - OPTIONAL_SECRET_FIELDS):
            raise RegistryError("Only the required secret references are permitted")
        if "netbird_oidc_client_id" in tenant:
            require_string(tenant, "netbird_oidc_client_id", IDENTIFIER)
            if "keycloak_client_secret" not in refs:
                raise RegistryError("NetBird Keycloak client requires a secret reference")
        if "gateway_id" in tenant:
            require_string(tenant, "gateway_id", IDENTIFIER)
            reserve("gateway_id", tenant["gateway_id"])
            if "gateway_setup_key" not in refs:
                raise RegistryError("Gateway identity requires a setup-key reference")
        if "connector_oidc_client_id" in tenant:
            require_string(tenant, "connector_oidc_client_id", IDENTIFIER)
            if not {"connector_setup_key", "connector_client_secret", "connector_hmac_secret", "telemetry_password"} <= set(refs):
                raise RegistryError("Application connector requires its private secret references")
        if "audit_hostname" in tenant and not {"audit_clickhouse_password", "audit_redis_password", "audit_client_secret"} <= set(refs):
            raise RegistryError("Audit deployment requires its private secret references")
        for field in refs:
            require_string(refs, field, SECRET_REF)
            reserve("secret reference", refs[field])
    if seen.get("existing_database", set()) & seen.get("netbird_database", set()):
        raise RegistryError("A migration source cannot be another tenant's desired database")
    if seen.get("gateway_id", set()) & seen.get("connector_id", set()):
        raise RegistryError("A gateway and connector cannot share a peer identity")
    return registry["tenants"]


def load_registry(path):
    try:
        registry = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_json_fields)
    except RegistryError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RegistryError("Cannot read a valid JSON tenant registry; details withheld") from None
    return validate_registry(registry)


def provisioning_plan(tenant):
    operations = []
    if "existing_database" in tenant:
        operations.append("Prepare a backup and migration plan for the existing database; retain peer state")
    operations.extend([
        "Provision a tenant-owned logical database and restricted database role",
        "Pin compatible NetBird server/dashboard versions and verify Keycloak integration",
        "Generate separate NetBird configuration, volumes and advertised endpoints",
        "Configure exact Keycloak client callbacks for this tenant",
        "Provide a dedicated tenant gateway to the permitted shared APIs",
        "Issue the connector certificate and server-owned tenant grant",
        "Bind the tenant application hostname to Envoy and its local policy",
        "Provision the tenant telemetry writer and audit access",
        "Run positive access and negative cross-tenant isolation tests",
    ])
    return {
        "dry_run": True,
        "tenant": tenant["id"],
        "realm": tenant["realm"],
        "netbird_stack": tenant["netbird_stack"],
        "netbird_database": tenant["netbird_database"],
        "database_role": tenant["netbird_database_role"],
        "connector_id": tenant["connector_id"],
        "application_host": tenant["application_host"],
        "secret_references": "validated; values are not resolved",
        "operations": operations,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "plan"))
    parser.add_argument("--registry", type=Path, default=ROOT / "config/tenants.json")
    parser.add_argument("--tenant", help="Print a plan for one tenant; the whole registry is still validated")
    args = parser.parse_args(argv)
    tenants = load_registry(args.registry)
    if args.tenant:
        tenants = [tenant for tenant in tenants if tenant["id"] == args.tenant]
        if not tenants:
            raise RegistryError("Requested tenant is not present in the registry")
    if args.action == "validate":
        print("Valid tenant registry:", len(tenants), "selected tenant(s)")
    else:
        print(json.dumps({"dry_run": True, "plans": [provisioning_plan(tenant) for tenant in tenants]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RegistryError as exc:
        raise SystemExit(str(exc)) from None
    except Exception as exc:
        raise SystemExit("Tenant validation failed: " + type(exc).__name__ + "; details withheld") from None
