"""Tenant desired-state registry for the full ZTNA control plane.

Design rule: the core `tenants` list is validated by the lead's unchanged
`provision-tenant.py`. Our additions live in a separate `tenant_ext` map, so
his validator and every existing renderer keep working with no edits to his
tree. Only `env:` secret REFERENCES are stored — never secret values.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parents[1]
VENDOR_ROOT = MODULE_ROOT / "vendor"
# The vendored snapshot is the self-contained default (so Dokploy builds need
# only this folder). The source tree is a fallback for local development.
ZETRIS_DEFAULT = (VENDOR_ROOT if (VENDOR_ROOT / "node1/scripts/provision-tenant.py").is_file()
                  else Path(r"C:\Users\pragy\opencode_IITM_multiten_test\zetris-views"))
SLUG = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
EMAIL = re.compile(r"[^\s@]{1,64}@[^\s@]+\.[^\s@]+")

# Free tier = 10 (matching the NetBird free-node allowance the team chose).
TIERS = {
    "free": {
        "max_users": 10,
        "max_apps": 1,
        "features": {
            "audit_explorer": True,
            "risk_writes": False,
            "block_on_critical": False,
            "netbird_posture": False,
            "falco": False,
        },
    },
    "paid": {
        "max_users": 100,
        "max_apps": 100,
        "features": {
            "audit_explorer": True,
            "risk_writes": True,
            "block_on_critical": False,  # explicit human decision, never auto
            "netbird_posture": True,
            "falco": True,
        },
    },
}

SECRET_NAMES = {
    "database_password": "DB_PASSWORD",
    "netbird_auth_secret": "AUTH_SECRET",
    "keycloak_client_secret": "KEYCLOAK_SECRET",
    "gateway_setup_key": "GATEWAY_SETUP_KEY",
    "connector_setup_key": "CONNECTOR_SETUP_KEY",
    "connector_client_secret": "CONNECTOR_CLIENT_SECRET",
    "connector_hmac_secret": "CONNECTOR_HMAC_SECRET",
    "telemetry_password": "TELEMETRY_PASSWORD",
    "audit_clickhouse_password": "AUDIT_CH_PASSWORD",
    "audit_redis_password": "AUDIT_REDIS_PASSWORD",
    "audit_client_secret": "AUDIT_CLIENT_SECRET",
}

EXT_FIELDS = {"tier", "domain", "admin_email", "features", "applications_document", "description"}


class ControlError(ValueError):
    """Diagnostics never include input values or secret material."""


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ControlError("Cannot load required module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validator(zetris_root: Path = ZETRIS_DEFAULT):
    path = Path(zetris_root) / "node1/scripts/provision-tenant.py"
    if not path.is_file():
        raise ControlError("The lead's tenant validator was not found at the configured root")
    return load(path, "ztna_tenant_validator")


def validate(path: Path, zetris_root: Path = ZETRIS_DEFAULT):
    """Return (tenants, ext) after validating both halves of the registry."""
    v = validator(zetris_root)
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=v.unique_json_fields)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ControlError("Registry is not valid UTF-8 JSON") from None
    if set(raw) != {"schema_version", "tenants", "tenant_ext"}:
        raise ControlError("Registry must contain schema_version, tenants and tenant_ext")
    core = {"schema_version": raw["schema_version"], "tenants": raw["tenants"]}
    try:
        tenants = v.validate_registry(core)
    except v.RegistryError as exc:
        raise ControlError(str(exc)) from None
    ext = raw["tenant_ext"]
    ids = {tenant["id"] for tenant in tenants}
    if not isinstance(ext, dict) or set(ext) != ids:
        raise ControlError("tenant_ext must describe exactly the tenants in the registry")
    for tenant in tenants:
        extra = ext[tenant["id"]]
        if not isinstance(extra, dict) or set(extra) != EXT_FIELDS:
            raise ControlError("Tenant extension fields are missing or unsupported")
        if extra["tier"] not in TIERS:
            raise ControlError("Unknown tier")
        if extra["domain"] != tenant["netbird_hostname"].split(".", 1)[1]:
            raise ControlError("Tenant domain does not match its hostnames")
        if not SLUG.fullmatch(tenant["id"]) or not EMAIL.fullmatch(extra["admin_email"]):
            raise ControlError("Invalid tenant ID or administrator email")
        features = extra["features"]
        if not isinstance(features, dict) or set(features) != set(TIERS[extra["tier"]]["features"]):
            raise ControlError("Feature set does not match the tier")
        if any(type(value) is not bool for value in features.values()):
            raise ControlError("Feature values must be booleans")
        if features["block_on_critical"] and not features["risk_writes"]:
            raise ControlError("Enforcement cannot be enabled without score writes")
        if not isinstance(extra["applications_document"], str) or not extra["applications_document"]:
            raise ControlError("An application document must be configured")
        if not isinstance(extra["description"], str) or len(extra["description"]) > 200:
            raise ControlError("Invalid tenant description")
    return tenants, ext


def build_tenant(slug, domain, tier, admin_email, *, base_port=42000, slot=0,
                 applications_document="config/applications.free.json", description=""):
    """Build one core tenant entry plus its extension (no secret values)."""
    if not SLUG.fullmatch(slug) or not EMAIL.fullmatch(admin_email) or tier not in TIERS:
        raise ControlError("Invalid tenant parameters")
    if not 1024 <= base_port <= 60000:
        raise ControlError("Invalid base port")
    ports = base_port + slot * 4
    if ports + 3 > 65535:
        raise ControlError("Port range exhausted")
    prefix = "ZTCP_" + slug.upper().replace("-", "_") + "_"
    tenant = {
        "id": slug,
        "realm": slug,
        "issuer": f"https://auth.{domain}/realms/{slug}",
        "netbird_stack": "ztcp-" + slug,
        "netbird_oidc_client_id": "zetris-netbird",
        "netbird_hostname": f"{slug}-netbird.{domain}",
        "netbird_database": "nb_" + slug.replace("-", "_"),
        "netbird_database_role": "nb_" + slug.replace("-", "_") + "_service",
        "dashboard_port": ports,
        "management_port": ports + 1,
        "audit_port": ports + 2,
        "stun_port": ports + 3,
        "gateway_id": "control-" + slug,
        "connector_id": "connector-" + slug,
        "connector_oidc_client_id": "node2-app-connector",
        "application_host": f"{slug}-app.{domain}",
        "audit_hostname": f"{slug}-audit.{domain}",
        "audit_oidc_client_id": "zetris-audit-" + slug,
        "policy_file": slug + ".rego",
        "telemetry_user": "ingest_" + slug,
        "secret_refs": {field: "env:" + prefix + suffix for field, suffix in SECRET_NAMES.items()},
    }
    ext = {
        "tier": tier,
        "domain": domain,
        "admin_email": admin_email,
        "features": dict(TIERS[tier]["features"]),
        "applications_document": applications_document,
        "description": description,
    }
    return tenant, ext


def build_registry(entries):
    """entries: iterable of (slug, domain, tier, email, slot, description)."""
    tenants, ext = [], {}
    for slug, domain, tier, email, slot, description in entries:
        tenant, extra = build_tenant(slug, domain, tier, email, slot=slot, description=description)
        tenants.append(tenant)
        ext[slug] = extra
    return {"schema_version": 1, "tenants": tenants, "tenant_ext": ext}
