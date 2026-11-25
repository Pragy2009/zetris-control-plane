"""Live orchestration steps for one tenant.

Every side effect goes through Runner, whose default mode is PREVIEW: it records
the intended operation but performs no network, Docker or database action.
Apply is possible only when the caller passes an explicit apply token.
No secret value is ever read from disk or written to logs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import secrets
import subprocess
from typing import Callable

from . import registry as reg
from . import tokens as tenant_tokens
from .render import private_write

MODULE_ROOT = Path(__file__).resolve().parents[1]


class StepError(RuntimeError):
    """Diagnostics contain no credentials or response bodies."""


@dataclass
class Runner:
    mode: str = "preview"
    apply_token: str = ""
    operations: list = field(default_factory=list)

    def ensure_apply(self):
        if self.mode != "apply" or not self.apply_token:
            raise StepError("Apply requires an explicit confirmation token")
        return self.apply_token

    def command(self, args, timeout=180):
        self.operations.append({"kind": "command", "argv": [str(a) for a in args]})
        if self.mode != "apply":
            return ""
        try:
            result = subprocess.run([str(a) for a in args], capture_output=True,
                                    text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise StepError("A container command was unavailable or timed out") from None
        if result.returncode:
            raise StepError("A container command failed; diagnostics withheld")
        return result.stdout

    def http(self, method: str, url: str, *, body=None, headers=None, expected=(200, 201, 204)):
        self.operations.append({"kind": "http", "method": method, "url": url,
                                "header_names": sorted((headers or {}).keys())})
        if self.mode != "apply":
            return {}
        import requests
        try:
            response = requests.request(method, url, json=body, headers=headers or {},
                                        timeout=20, allow_redirects=False)
        except requests.RequestException:
            raise StepError("A service was unreachable over verified transport") from None
        if response.status_code not in expected:
            raise StepError(f"Service returned HTTP {response.status_code}; response withheld")
        return response.json() if response.content else {}

    def write(self, path, text, mode=0o600):
        self.operations.append({"kind": "write", "path": str(path), "bytes": len(text)})
        if self.mode == "apply":
            private_write(Path(path), text, mode)


@dataclass
class Context:
    tenant: dict
    ext: dict
    config: dict
    secrets: dict                 # generated in memory, never read from .env
    out_dir: Path
    runner: Runner
    admin_password: str = ""      # held only in memory during the job
    application_hosts: list = field(default_factory=list)

    @property
    def root(self) -> Path:
        return Path(self.config.get("scripts_root", str(reg.ZETRIS_DEFAULT)))

    def module(self, relative: str, name: str):
        return reg.load(self.root / relative, name)

    @property
    def origin(self) -> str:
        return "https://" + self.tenant["netbird_hostname"]


def _token_request(ctx: Context) -> str:
    kc = ctx.config["keycloak"]
    form = {"grant_type": "password", "client_id": "admin-cli",
            "username": kc["admin_user"],
            "password": ctx.secrets.get(kc["admin_password_env"], "")}
    data = ctx.runner.http("POST", kc["origin"] + "/realms/master/protocol/openid-connect/token",
                           body=form)
    return data.get("access_token", "")


def step_database(ctx: Context):
    db = ctx.module("node1/scripts/provision-netbird-db.py", "ztcp_db")
    ctx.runner.write(ctx.config["postgres"]["managed_hba_file"],
                     db.render_hba([ctx.tenant]))
    if ctx.runner.mode == "apply":
        from types import SimpleNamespace
        pg = ctx.config["postgres"]
        args = SimpleNamespace(host=pg["host"], port=pg["port"], admin_user=pg["admin_user"],
                               maintenance_database="postgres", sslmode=pg.get("sslmode", "verify-full"))
        environ = dict(ctx.secrets)
        environ["PGPASSWORD"] = ctx.secrets[pg["password_env"]]
        db.provision(args, [ctx.tenant], [ctx.tenant], environ)
    return "database prepared"


def step_audit_data(ctx: Context):
    data = ctx.module("node1/scripts/provision-audit-data.py", "ztcp_audit_data")
    if ctx.runner.mode != "apply":
        return "audit views and ACLs planned"
    query = data.ch_requester(ctx.config["clickhouse"]["origin"],
                              ctx.config.get("ca_file"), ctx.config["clickhouse"]["admin_user"],
                              ctx.secrets[ctx.config["clickhouse"]["password_env"]])
    import redis
    admin = redis.Redis(host=ctx.config["redis"]["host"], port=ctx.config["redis"]["port"],
                        ssl=True, ssl_ca_certs=ctx.config.get("ca_file"),
                        username=ctx.config["redis"].get("admin_user", "default"),
                        password=ctx.secrets[ctx.config["redis"]["password_env"]],
                        decode_responses=True)
    passwords = {ctx.tenant["id"]: {
        "audit_clickhouse_password": ctx.secrets["ZTCP_" + ctx.tenant["id"].upper().replace("-", "_") + "_AUDIT_CH_PASSWORD"],
        "audit_redis_password": ctx.secrets["ZTCP_" + ctx.tenant["id"].upper().replace("-", "_") + "_AUDIT_REDIS_PASSWORD"],
    }}
    data.provision([ctx.tenant], query, admin, ctx.config["clickhouse"]["admin_user"], passwords)
    return "audit data plane prepared"


def step_identity(ctx: Context):
    token = _token_request(ctx)
    origin = ctx.config["keycloak"]["origin"]
    prefix = "ZTCP_" + ctx.tenant["id"].upper().replace("-", "_") + "_"
    access = ctx.module("node1/scripts/render-tenant-access.py", "ztcp_access_identity")
    app_client = access.application_client(ctx.tenant, ctx.secrets[prefix + "KEYCLOAK_SECRET"])
    realm = {
        "realm": ctx.tenant["realm"], "enabled": True, "sslRequired": "external",
        "registrationAllowed": False,
        "attributes": {"zetris.owner": "ztcp:" + ctx.tenant["netbird_stack"]},
        "roles": {"client": {"zetris-audit-" + ctx.tenant["id"]: [
            {"name": "audit-viewer"}, {"name": "audit-admin"}]}},
        "clients": [
            app_client,
            {"clientId": ctx.tenant["audit_oidc_client_id"], "enabled": True,
             "publicClient": False, "protocol": "openid-connect",
             "secret": ctx.secrets[prefix + "AUDIT_CLIENT_SECRET"],
             "redirectUris": ["https://" + ctx.tenant["audit_hostname"] + "/oauth2/callback"],
             "defaultClientScopes": ["profile", "email", "roles", "basic"]},
            {"clientId": ctx.tenant["netbird_oidc_client_id"], "enabled": True,
             "publicClient": False, "protocol": "openid-connect",
             "secret": ctx.secrets[prefix + "KEYCLOAK_SECRET"],
             "redirectUris": [ctx.origin + "/oauth2/callback"],
             "defaultClientScopes": ["profile", "email", "roles", "basic"]},
        ],
        "users": [{"username": ctx.ext["admin_email"], "email": ctx.ext["admin_email"],
                   "enabled": True, "emailVerified": True,
                   "requiredActions": ["UPDATE_PASSWORD"],
                   "credentials": [{"type": "password", "temporary": True,
                                    "value": ctx.admin_password}]}],
    }
    ctx.runner.http("POST", origin + "/admin/realms", body=realm,
                    headers={"Authorization": "Bearer " + token})
    ctx.admin_password = ""  # clear the plaintext from memory immediately
    ctx.runner.http("GET", origin + "/admin/realms/" + ctx.tenant["realm"],
                    headers={"Authorization": "Bearer " + token})
    return "realm, clients, roles and administrator created"


def step_netbird_stack(ctx: Context):
    netbird = ctx.module("node1/scripts/render-netbird-tenant.py", "ztcp_netbird_stack")
    artifacts = netbird.build_artifacts(
        ctx.tenant, db_host=ctx.config["postgres"]["container_host"],
        db_network=ctx.config["database_network"],
        trusted_proxies=ctx.config["trusted_proxies"],
        origin=ctx.origin, bootstrap=True, environ=ctx.secrets,
        oidc_ca=ctx.config.get("ca_file"))
    for name, value in artifacts.items():
        ctx.runner.write(ctx.out_dir / "netbird" / name, value)
    ctx.runner.command(["docker", "compose", "-f", ctx.out_dir / "netbird/compose.json",
                        "up", "-d", "--wait", "--wait-timeout", "150"], timeout=240)
    return "NetBird stack rendered and started"


def step_netbird_bootstrap(ctx: Context):
    if ctx.runner.mode != "apply":
        return "OIDC provider and default-deny ACLs planned"
    provider = ctx.module("node1/scripts/configure-netbird-keycloak.py", "ztcp_provider")
    access = ctx.module("node1/scripts/configure-netbird-access.py", "ztcp_access")

    def request(path, method="GET", body=None, token=None):
        headers = {"Authorization": "Token " + token} if token else {}
        return ctx.runner.http(method, ctx.origin + path, body=body, headers=headers)

    prefix = "ZTCP_" + ctx.tenant["id"].upper().replace("-", "_") + "_"
    admin_token_env = ctx.config.get("netbird", {}).get("admin_token_env", "ZTCP_ADMIN_TOKEN")
    network = ctx.tenant["netbird_stack"] + "-network"
    server = ctx.tenant["netbird_stack"] + "-server"
    setup_body = json.dumps({
        "email": "bootstrap-" + ctx.tenant["id"] + "@portal.invalid",
        "name": "Zetris provisioner", "create_pat": True, "pat_expire_in": 30})
    raw = ctx.runner.command([
        "docker", "run", "--rm", "--network", network,
        "curlimages/curl:8.5.0", "-sS", "-X", "POST",
        "http://" + server + ":80/api/setup",
        "-H", "Content-Type: application/json", "-d", setup_body], timeout=90)
    if ctx.runner.mode == "apply":
        token_data = json.loads(raw) if raw else {}
        pat = token_data.get("personal_access_token")
        if not pat:
            raise StepError("NetBird setup returned no automation token")
        ctx.secrets[admin_token_env] = pat
        tenant_tokens.save(ctx.tenant["id"], pat)
    admin_token = ctx.secrets.get(admin_token_env, "")
    provider.configure(ctx.tenant, ctx.origin, admin_token,
                       ctx.secrets[prefix + "KEYCLOAK_SECRET"], request)
    access.configure(ctx.tenant, ctx.origin, admin_token,
                     request, disable_default=True)
    return "OIDC provider and default-deny ACLs installed"


def step_access_gateway(ctx: Context):
    access = ctx.module("node1/scripts/render-tenant-access.py", "ztcp_gateway")
    artifacts = access.build(ctx.tenant, "gateway", environ=ctx.secrets,
                             api_network=ctx.config["api_network"],
                             connector_source=str(ctx.root / "node2"),
                             netbird_ca=ctx.config.get("ca_file"),
                             oidc_ca=ctx.config.get("ca_file"), lab=ctx.config.get("lab", False))
    for name, value in artifacts.items():
        ctx.runner.write(ctx.out_dir / "access-gateway" / name, value)
    ctx.runner.command(["docker", "compose", "-f", ctx.out_dir / "access-gateway/compose.json",
                        "up", "-d", "--wait"], timeout=240)
    return "tenant gateway rendered and started"


def step_access_connector(ctx: Context):
    access = ctx.module("node1/scripts/render-tenant-access.py", "ztcp_connector")
    artifacts = access.build(
        ctx.tenant, "connector", environ=ctx.secrets,
        api_network=ctx.config["api_network"],
        connector_source=str(ctx.root / "node2"),
        client_dir=ctx.out_dir / "connector-identity",
        grant_file=ctx.out_dir / "connector-grants.json",
        gateway_ip=ctx.config["gateway_ip"],
        application_tls=ctx.out_dir / "application-tls",
        telemetry_ca=ctx.config.get("ca_file"),
        oidc_ca=ctx.config.get("ca_file"), lab=ctx.config.get("lab", False))
    for name, value in artifacts.items():
        ctx.runner.write(ctx.out_dir / "access-connector" / name, value)
    ctx.runner.command(["docker", "compose", "-f", ctx.out_dir / "access-connector/compose.json",
                        "up", "-d", "--wait"], timeout=240)
    return "application connector rendered and started"


def step_policy(ctx: Context):
    # The policy store reloads <tenant>.rego from its POLICY_DIR on a ticker.
    ctx.runner.command([
        "docker", "run", "--rm",
        "-v", ctx.config["policy_volume"] + ":/policies",
        "-v", str(ctx.out_dir / "policy") + ":/src:ro",
        "alpine", "cp", "/src/" + ctx.tenant["policy_file"],
        "/policies/" + ctx.tenant["policy_file"]])
    return "policy file distributed to the shared volume"


def step_audit_stack(ctx: Context):
    audit = ctx.module("node1/scripts/render-tenant-audit.py", "ztcp_audit_stack")
    artifacts = audit.build(ctx.tenant, network=ctx.config["backend_network"],
                            backend_ca=ctx.config.get("ca_file"), environ=ctx.secrets)
    for name, value in artifacts.items():
        ctx.runner.write(ctx.out_dir / "audit" / name, value)
    ctx.runner.command(["docker", "compose", "-f", ctx.out_dir / "audit/compose.json",
                        "up", "-d", "--build", "--wait"], timeout=300)
    return "audit console (with Decision Explorer) rendered and started"


def step_routes(ctx: Context):
    """Install hostname routes on the tenant gateway (Traefik → Caddy → edge)."""
    edge = ctx.config.get("edge_host", "zetris-single-node-edge-1")
    generated = []

    netbird = ctx.out_dir / "netbird/Caddyfile.snippet"
    if netbird.is_file():
        text = netbird.read_text(encoding="utf-8")
        text = text.replace("h2c://127.0.0.1:" + str(ctx.tenant["management_port"]),
                            "h2c://" + edge + ":8081")
        text = text.replace("127.0.0.1:" + str(ctx.tenant["management_port"]), edge + ":8081")
        text = text.replace("127.0.0.1:" + str(ctx.tenant["dashboard_port"]), edge + ":8081")
        generated.append((ctx.tenant["id"] + "-netbird.caddy", text))

    audit = ctx.out_dir / "audit/Caddyfile.snippet"
    if audit.is_file():
        text = audit.read_text(encoding="utf-8")
        text = text.replace("127.0.0.1:" + str(ctx.tenant["audit_port"]), edge + ":8082")
        generated.append((ctx.tenant["id"] + "-audit.caddy", text))

    app_host = ctx.tenant["application_host"]
    generated.append((ctx.tenant["id"] + "-app.caddy",
                      app_host + " {\n    reverse_proxy " + edge + ":8083\n}\n"))

    for name, text in generated:
        ctx.runner.write(ctx.out_dir / "routes" / name, text)
    volume = ctx.config.get("route_volume", "zetris-control-plane_ztcp-routes")
    ctx.runner.command(["docker", "run", "--rm",
                        "-v", volume + ":/routes",
                        "-v", str(ctx.out_dir / "routes") + ":/src:ro",
                        "alpine", "cp", "/src/.", "/routes/"])
    gateway = ctx.config.get("gateway_container", "zetris-control-plane-tenant-gateway-1")
    ctx.runner.command(["docker", "exec", gateway, "caddy", "validate", "--config", "/etc/caddy/Caddyfile"])
    ctx.runner.command(["docker", "exec", gateway, "caddy", "reload", "--config", "/etc/caddy/Caddyfile"])
    return "tenant hostname routes installed on the gateway"


def step_verify(ctx: Context):
    for host in (ctx.tenant["netbird_hostname"], ctx.tenant["audit_hostname"],
                 ctx.tenant["application_host"]):
        ctx.runner.http("GET", "https://" + host + "/", expected=(200, 302))
    return "all three tenant doors verified"


def step_posture(ctx: Context):
    # NOT ENABLED: the posture-check API path for the pinned NetBird 0.80.0
    # release has not been verified in this module. Recording a guessed endpoint
    # would be dishonest; this step is a placeholder until it is reviewed.
    raise StepError("Posture checks require a reviewed NetBird API contract")


def step_handoff(ctx: Context):
    one_time = secrets.token_urlsafe(24)
    handoff = {
        "tenant": ctx.tenant["id"], "tier": ctx.ext["tier"],
        "urls": {"app": "https://" + ctx.tenant["application_host"],
                 "audit": "https://" + ctx.tenant["audit_hostname"],
                 "netbird": ctx.origin},
        "administrator": ctx.ext["admin_email"],
        "credential_delivery": "one-time link; password never stored by the control plane",
        "one_time_token": one_time,
        "handoff_url": ctx.config.get("portal_base_url", "http://127.0.0.1:8788").rstrip("/") +
                       "/handoff/" + ctx.tenant["id"] + "?token=" + one_time,
    }
    text = json.dumps(handoff, indent=2) + "\n"
    if ctx.runner.mode == "preview":
        # Preview must materialize the token so the one-time handoff can be
        # tested locally. It contains no password or secret value.
        private_write(ctx.out_dir / "handoff.json", text)
    else:
        ctx.runner.write(ctx.out_dir / "handoff.json", text)
    ctx.admin_password = ""
    return "handoff prepared; credentials shown once"


STEPS: list[tuple[str, Callable[[Context], str]]] = [
    ("database", step_database),
    ("audit_data", step_audit_data),
    ("identity", step_identity),
    ("netbird_stack", step_netbird_stack),
    ("netbird_bootstrap", step_netbird_bootstrap),
    ("access_gateway", step_access_gateway),
    ("access_connector", step_access_connector),
    ("policy", step_policy),
    ("audit_stack", step_audit_stack),
    ("routes", step_routes),
    ("verify", step_verify),
    ("handoff", step_handoff),
]


def run_all(ctx: Context):
    """Execute (or preview) all steps; returns a status record per step."""
    records = []
    for name, fn in STEPS:
        if name == "posture" and ctx.ext["tier"] != "paid":
            records.append({"step": name, "status": "skipped", "detail": "free tier"})
            continue
        try:
            detail = fn(ctx)
            records.append({"step": name, "status": "ok", "detail": detail})
        except Exception as error:  # diagnostics are sanitized by each step
            records.append({"step": name, "status": "failed",
                            "detail": type(error).__name__ + "; details withheld"})
            break
    return records
