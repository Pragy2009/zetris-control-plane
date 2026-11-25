"""Render every tenant plane with the lead's existing renderers.

Preview-only by default: writes artifacts under this module's provisioned/
directory using EPHEMERAL lab secrets generated in memory. No real credential
file is ever read, no container is started, and no live service is contacted.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .registry import ControlError, ZETRIS_DEFAULT, load

MODULE_ROOT = Path(__file__).resolve().parents[1]


def ephemeral_environ(tenant):
    """Throwaway values for env: references; never reads a real secret store."""
    values = {}
    for ref in tenant["secret_refs"].values():
        if not ref.startswith("env:"):
            raise ControlError("Only env: secret references are supported")
        values[ref.split(":", 1)[1]] = secrets.token_urlsafe(32)
    return values


def private_write(path: Path, text: str, mode: int = 0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


class LabCA:
    """Throwaway certificate authority for local preview only."""

    def __init__(self, folder: Path):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ZTCP preview lab CA")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name).public_key(self.key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(self.key, hashes.SHA256()))
        self.crt = self.folder / "ca.crt"
        private_write(self.crt, cert.public_bytes(serialization.Encoding.PEM).decode())
        private_write(self.folder / "ca.key", self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode())

    def leaf(self, name: str, *, sans=()):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .issuer_name(x509.load_pem_x509_certificate(self.crt.read_bytes()).subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(value) for value in sans]), False)
                .sign(self.key, hashes.SHA256()))
        crt, keyfile = self.folder / (name + ".crt"), self.folder / (name + ".key")
        private_write(crt, cert.public_bytes(serialization.Encoding.PEM).decode())
        private_write(keyfile, key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode())
        return crt, keyfile, hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _write_artifacts(folder: Path, artifacts: dict):
    folder.mkdir(parents=True, exist_ok=True)
    for name, value in artifacts.items():
        if name.endswith(".json") and not isinstance(value, str):
            value = json.dumps(value, indent=2) + "\n"
        private_write(folder / name, value)


def _policy_renderer(zetris_root: Path):
    folder = Path(zetris_root) / "node1/policies/access-v1"
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
    return load(folder / "render.py", "ztna_access_policy_render")


def render_all(tenant, ext, *, out: Path, zetris_root: Path = ZETRIS_DEFAULT,
               gateway_ip="100.64.0.10", features=None):
    """Render NetBird, policy, audit, gateway and connector artifacts.

    Returns a manifest describing what was generated (no private values).
    """
    root = MODULE_ROOT.resolve()
    out = Path(out).resolve()
    if out != root and root not in out.parents:
        raise ControlError("Generated output must stay inside the control-plane folder")
    env = ephemeral_environ(tenant)
    ca = LabCA(out / "lab-ca")
    manifest = {"tenant": tenant["id"], "tier": ext["tier"],
                "preview": True, "artifacts": {}, "prerequisites": []}

    # 1. NetBird plane.
    netbird = load(Path(zetris_root) / "node1/scripts/render-netbird-tenant.py", "ztcp_netbird")
    nb = netbird.build_artifacts(
        tenant, db_host="postgres", db_network="ztcp-shared-database",
        trusted_proxies=["10.253.245.2/32"], db_sslmode="verify-full",
        origin="https://" + tenant["netbird_hostname"], lab=True, bootstrap=True,
        environ=env, oidc_ca=str(ca.crt))
    _write_artifacts(out / "netbird", nb)
    manifest["artifacts"]["netbird"] = sorted(nb)

    # 2. Policy plane (per-tenant application document).
    policy = _policy_renderer(zetris_root)
    appdoc_path = Path(ext["applications_document"])
    if not appdoc_path.is_absolute():
        appdoc_path = root / appdoc_path
    if not appdoc_path.is_file():
        raise ControlError("Configured application document is missing")
    document = json.loads(appdoc_path.read_text(encoding="utf-8"))
    settings = {"host": tenant["application_host"], "issuer": tenant["issuer"],
                "role_client": tenant["connector_oidc_client_id"], "simulator_subject": ""}
    rego = policy.render(tenant["id"], settings, document)
    private_write(out / "policy" / tenant["policy_file"], rego)
    manifest["artifacts"]["policy"] = [tenant["policy_file"]]

    # 3. Audit plane.
    audit = load(Path(zetris_root) / "node1/scripts/render-tenant-audit.py", "ztcp_audit")
    au = audit.build(tenant, network="ztcp-backend", backend_ca=str(ca.crt),
                     oidc_ca=str(ca.crt), environ=env)
    if features:
        compose = json.loads(au["compose.json"])
        audit_env = compose["services"]["audit"]["environment"]
        audit_env["WRITE_SCORES"] = "true" if features.get("risk_writes") else "false"
        audit_env["BLOCK_ON_CRITICAL"] = "true" if features.get("block_on_critical") else "false"
        au["compose.json"] = json.dumps(compose, indent=2) + "\n"
    _write_artifacts(out / "audit", au)
    manifest["artifacts"]["audit"] = sorted(au)

    # 4. Access plane (gateway and connector).
    access = load(Path(zetris_root) / "node1/scripts/render-tenant-access.py", "ztcp_access")
    connector_dir = out / "connector-identity"
    connector_dir.mkdir(parents=True, exist_ok=True)
    server_dir = out / "application-tls"
    server_dir.mkdir(parents=True, exist_ok=True)
    connector_crt, connector_key, fingerprint = ca.leaf(
        tenant["connector_id"], sans=[tenant["connector_id"]])
    for source, target in ((connector_crt, connector_dir / "client.crt"),
                           (connector_key, connector_dir / "client.key"),
                           (ca.crt, connector_dir / "ca.crt")):
        private_write(target, source.read_text())
    server_crt, server_key, _ = ca.leaf(
        tenant["application_host"], sans=[tenant["application_host"]])
    private_write(server_dir / "server.crt", server_crt.read_text())
    private_write(server_dir / "server.key", server_key.read_text())
    grant_file = out / "connector-grants.json"
    private_write(grant_file, json.dumps({fingerprint: {
        "id": tenant["connector_id"], "tenants": [tenant["id"]]}}, indent=2) + "\n")

    common = dict(environ=env, api_network="ztcp-service-access",
                  connector_source=str(Path(zetris_root) / "node2"),
                  netbird_ca=str(ca.crt), oidc_ca=str(ca.crt), lab=True)
    gateway = access.build(tenant, "gateway", **common)
    connector = access.build(tenant, "connector", client_dir=str(connector_dir),
                             grant_file=str(grant_file), gateway_ip=gateway_ip,
                             application_tls=str(server_dir),
                             telemetry_ca=str(ca.crt), **common)
    _write_artifacts(out / "access-gateway", gateway)
    _write_artifacts(out / "access-connector", connector)
    manifest["artifacts"]["access-gateway"] = sorted(gateway)
    manifest["artifacts"]["access-connector"] = sorted(connector)

    manifest["prerequisites"] = [
        "Shared Keycloak admin access (operator enters credentials in Dokploy).",
        "Shared PostgreSQL admin with HBA management rights.",
        "Shared ClickHouse/Redis admins for tenant views and ACLs.",
        "Wildcard DNS and Let's Encrypt for the tenant hostnames.",
        "NetBird client enrollment keys for the tenant's own machines.",
        "Linux Docker host for NET_ADMIN/NET_RAW peers and /dev/net/tun.",
    ]
    private_write(out / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return manifest


def plan(tenant, ext):
    """Ordered, human-readable operations for the full orchestrator."""
    tier = ext["tier"]
    steps = [
        ("database", "Provision NetBird logical DB + restricted role (HBA isolated)"),
        ("audit_data", "Provision ClickHouse tenant views + Redis ACLs"),
        ("identity", "Create Keycloak realm, app/audit clients, roles and admin user"),
        ("netbird_stack", "Render and start the tenant NetBird server/dashboard"),
        ("netbird_bootstrap", "Bootstrap owner, OIDC provider, default-deny ACL; finalize"),
        ("access_gateway", "Render/start the tenant gateway peer and shared-API proxy"),
        ("access_connector", "Issue connector identity, render/start the app connector"),
        ("policy", "Render per-tenant rego and distribute it to the policy server"),
        ("audit_stack", "Render/start the tenant audit console (Decision Explorer included)"),
        ("routes", "Add per-tenant TLS routes for app/audit/netbird hosts"),
        ("verify", "Verify all doors, cross-tenant denials and admin role handoff"),
        ("handoff", "Issue tenant URLs, one-time admin credentials and client download"),
    ]
    if tier == "paid":
        steps.insert(8, ("posture", "Enable paid-tier NetBird posture checks"))
    return [{"step": name, "action": text, "mode": "preview"} for name, text in steps]
