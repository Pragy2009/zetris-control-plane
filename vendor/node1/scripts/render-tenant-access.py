#!/usr/bin/env python3
"""Preview or generate an owned tenant TCP gateway/application connector.

Uses existing connector certificates/grants and caller-supplied runtime secrets.
No certificate issuance, realm replacement, service startup or secret rotation.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


netbird = load(ROOT / "scripts/render-netbird-tenant.py", "netbird_render")
grants = load(ROOT / "scripts/provision-connectors.py", "connector_grants")
ENVOY = "envoyproxy/envoy:v1.30.1"
VECTOR = "timberio/vector:0.46.1-alpine"
PORTS = (50051, 50553, 8443)


class DeploymentError(RuntimeError):
    """Private values are never included in diagnostics."""


def mesh_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise DeploymentError("Invalid gateway mesh address") from None
    if address not in ipaddress.ip_network("100.64.0.0/10"):
        raise DeploymentError("Gateway must use its assigned NetBird IPv4 address")
    return str(address)


def endpoint(value):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+:[0-9]{1,5}", value) or not 1 <= int(value.rsplit(":", 1)[1]) <= 65535:
        raise DeploymentError("Backend must be an explicit host:port without credentials")
    return value


def mesh_service(tenant, role, netbird_ca=None, lab=False):
    identity = tenant["gateway_id" if role == "gateway" else "connector_id"]
    service = {
        "image": netbird.versions()["client_image"], "hostname": identity,
        "cap_add": ["NET_ADMIN", "NET_RAW"], "devices": ["/dev/net/tun:/dev/net/tun"],
        "sysctls": {"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"},
        "environment": {"NB_MANAGEMENT_URL": "https://" + tenant["netbird_hostname"],
                        "NB_HOSTNAME": identity, "NB_LOG_LEVEL": "warn"},
        "volumes": ["mesh-state:/var/lib/netbird", "mesh-runtime:/run/netbird", "./mesh-health.sh:/config/mesh-health.sh:ro"],
        "healthcheck": {"test": ["CMD", "sh", "/config/mesh-health.sh"], "interval": "3s", "timeout": "5s", "retries": 30},
        "restart": "unless-stopped", "networks": {"transport": {}},
    }
    if lab:
        service["environment"].update(NB_WG_KERNEL_DISABLED="true", NB_DISABLE_EBPF_WG_PROXY="true")
    if netbird_ca:
        service["volumes"].append(str(Path(netbird_ca).resolve()) + ":/config/netbird-ca.crt:ro")
        service["environment"]["SSL_CERT_FILE"] = "/config/netbird-ca.crt"
    return service


def envoy_service():
    return {"image": ENVOY, "network_mode": "service:mesh", "cap_drop": ["ALL"],
            "cap_add": ["NET_BIND_SERVICE"], "entrypoint": ["sh", "/config/start-envoy.sh"],
            "depends_on": {"mesh": {"condition": "service_healthy"}},
            "volumes": ["./envoy.json:/config/envoy.json:ro", "./start-envoy.sh:/config/start-envoy.sh:ro", "mesh-runtime:/run/netbird:ro"],
            "healthcheck": {"test": ["CMD", "bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/9901 && printf 'GET /ready HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3 && IFS= read -r status <&3 && [[ $$status == *' 200 '* ]]"],
                            "interval": "3s", "timeout": "3s", "retries": 20},
            "restart": "unless-stopped"}


def gateway_config(backends):
    listeners, clusters = [], []
    for name, port in zip(("score", "policy", "telemetry"), PORTS):
        host, target_port = endpoint(backends[name]).rsplit(":", 1)
        listeners.append({"name": name, "address": {"socket_address": {"address": "__MESH_IP__", "port_value": port}},
            "filter_chains": [{"filters": [{"name": "envoy.filters.network.tcp_proxy", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
                "stat_prefix": name, "cluster": name, "idle_timeout": "300s"}}]}]})
        clusters.append({"name": name, "type": "STRICT_DNS", "connect_timeout": "3s", "dns_lookup_family": "V4_ONLY",
            "load_assignment": {"cluster_name": name, "endpoints": [{"lb_endpoints": [{"endpoint": {"address": {
                "socket_address": {"address": host, "port_value": int(target_port)}}}}]}]}})
    return {"static_resources": {"listeners": listeners, "clusters": clusters},
            "admin": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 9901}}}}


def connector_identity(tenant, client_dir, grant_file):
    client_dir = Path(client_dir).resolve()
    certificate = (client_dir / "client.crt").read_text(encoding="ascii")
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
    grant = grants.load_grants(Path(grant_file)).get(fingerprint)
    if grant != {"id": tenant["connector_id"], "tenants": [tenant["id"]]}:
        raise DeploymentError("Client certificate does not have this connector's exact tenant grant")
    context = ssl.create_default_context(cafile=str(client_dir / "ca.crt"))
    context.load_cert_chain(str(client_dir / "client.crt"), str(client_dir / "client.key"))
    return client_dir, fingerprint


def application_client(tenant, secret):
    origin = "https://" + tenant["application_host"]
    return {"clientId": tenant["connector_oidc_client_id"], "enabled": True, "publicClient": False,
        "protocol": "openid-connect", "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
        "secret": secret, "redirectUris": [origin + "/oauth2/callback"], "webOrigins": [origin],
        "attributes": {"post.logout.redirect.uris": origin + "/signed-out"},
        "defaultClientScopes": ["profile", "email", "roles", "basic"], "optionalClientScopes": ["offline_access"],
        "protocolMappers": [{"name": "connector-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": tenant["connector_oidc_client_id"], "access.token.claim": "true", "id.token.claim": "false"}}]}


def connector_envoy(tenant, source, client_secret, hmac_secret, oidc_ca=None):
    import yaml
    doc = yaml.safe_load((Path(source) / "envoy/envoy.yaml.tmpl").read_text(encoding="utf-8"))
    issuer = tenant["issuer"]
    if not re.fullmatch(r"https://[A-Za-z0-9_.:/-]+", issuer):
        raise DeploymentError("Unsupported issuer characters in the application template")
    values = {"KEYCLOAK_ISSUER": issuer, "KEYCLOAK_HOST": urlparse(issuer).hostname,
        "OAUTH2_CLIENT_ID": tenant["connector_oidc_client_id"], "VIRTUAL_HOST": tenant["application_host"],
        "CORS_ORIGIN": "https://" + tenant["application_host"], "OAUTH2_TOKEN_SECRET": client_secret, "OAUTH2_HMAC_SECRET": hmac_secret}
    def substitute(value):
        if isinstance(value, dict):
            return {key: substitute(item) for key, item in value.items()}
        if isinstance(value, list):
            return [substitute(item) for item in value]
        if isinstance(value, str):
            return re.sub(r"\$\{([A-Z0-9_]+)(?::-[^}]*)?\}", lambda match: values[match[1]], value)
        return value
    doc = substitute(doc)
    doc["static_resources"]["listeners"][0]["address"]["socket_address"]["address"] = "__MESH_IP__"
    hcm = doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
    # Envoy 1.30 lacks REQ_WITHOUT_QUERY. The first Lua filter records the path
    # without OAuth callback/query data before any auth filter can terminate it.
    hcm["access_log"][0]["typed_config"]["log_format"]["json_format"]["request_path"] = "%DYNAMIC_METADATA(zetris.access:path)%"
    for http_filter in hcm["http_filters"]:
        if http_filter["name"] == "envoy.filters.http.lua":
            source_code = http_filter["typed_config"]["default_source_code"]["inline_string"]
            anchor = "local headers = handle:headers()"
            if anchor not in source_code:
                raise DeploymentError("Application Lua template differs from the expected gateway-owned filter")
            if 'dynamicMetadata():set("zetris.access", "path"' not in source_code:
                http_filter["typed_config"]["default_source_code"]["inline_string"] = source_code.replace(anchor,
                    anchor + '\n  handle:streamInfo():dynamicMetadata():set("zetris.access", "path", (headers:get(":path") or ""):match("^[^?]*"))', 1)
        if http_filter["name"] == "envoy.filters.http.jwt_authn":
            http_filter["typed_config"]["providers"]["keycloak"]["audiences"] = [tenant["connector_oidc_client_id"]]
    host = tenant["application_host"]
    hcm["route_config"]["virtual_hosts"][0]["domains"] = [host, host + ":443"]
    # The first connector slice has one backend/application. Existing OAuth,
    # JWT, logout and fail-closed authorization filters are retained.
    for cluster in doc["static_resources"]["clusters"]:
        address = cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["socket_address"]
        if cluster["name"] == "local_opa_sidecar":
            address["address"] = "127.0.0.1"
        elif cluster["name"] == "keycloak":
            address["port_value"] = urlparse(issuer).port or 443
            if oidc_ca:
                cluster["transport_socket"]["typed_config"]["common_tls_context"]["validation_context"]["trusted_ca"]["filename"] = "/config/oidc-ca.crt"
            cluster["transport_socket"]["typed_config"]["common_tls_context"]["validation_context"]["match_typed_subject_alt_names"] = [
                {"san_type": "DNS", "matcher": {"exact": urlparse(issuer).hostname}}]
        else:
            address.update(address="portal", port_value=3000)
    return doc


def build(tenant, role, *, environ=None, api_network="zetris-service-access", backends=None,
          connector_source=None, client_dir=None, grant_file=None, gateway_ip=None,
          application_tls=None, telemetry_ca=None, telemetry_server_name="clickhouse", netbird_ca=None, oidc_ca=None, lab=False):
    environ = os.environ if environ is None else environ
    if "gateway_id" not in tenant or "connector_oidc_client_id" not in tenant:
        raise DeploymentError("Tenant gateway and application client identities are required")
    name = tenant["netbird_stack"] + ("-access" if role == "gateway" else "-connector")
    mesh = mesh_service(tenant, role, netbird_ca, lab)
    mesh["environment"]["NB_SETUP_KEY"] = netbird.secret(tenant, role + "_setup_key", environ).replace("$", "$$")
    compose = {"name": name, "services": {"mesh": mesh, "envoy": envoy_service()},
        "networks": {"transport": {"name": name + "-transport"}},
        "volumes": {key: {"name": name + "-" + key} for key in ("mesh-state", "mesh-runtime")}}
    metadata = {"tenant": tenant["id"], "role": role, "stack": name, "peer": mesh["hostname"]}
    artifacts = {file: (ROOT / "deploy/mesh" / file).read_text(encoding="utf-8") for file in ("mesh-health.sh", "start-envoy.sh")}
    if role == "gateway":
        if not netbird.registry.STACK.fullmatch(api_network):
            raise DeploymentError("Invalid trusted API network name")
        mesh["networks"]["access"] = {}
        compose["networks"]["access"] = {"external": True, "name": api_network}
        config = gateway_config(backends or {"score": "score-service:50051", "policy": "score-service:50551", "telemetry": "clickhouse:8443"})
        metadata["allowed_tcp_ports"] = list(PORTS)
    else:
        gateway_ip = mesh_address(gateway_ip)
        client_dir, fingerprint = connector_identity(tenant, client_dir, grant_file)
        for path in (Path(application_tls) / "server.crt", Path(application_tls) / "server.key", Path(telemetry_ca)):
            if not path.is_file():
                raise DeploymentError("Required TLS file is unavailable")
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(Path(application_tls) / "server.crt"), str(Path(application_tls) / "server.key"))
        client_secret = netbird.secret(tenant, "connector_client_secret", environ)
        config = connector_envoy(tenant, connector_source, client_secret, netbird.secret(tenant, "connector_hmac_secret", environ), oidc_ca)
        mesh["networks"]["application"] = {}
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", telemetry_server_name):
            raise DeploymentError("Telemetry TLS server name must be a hostname")
        # Vector verifies the endpoint host independently of TLS SNI. Keep the
        # real backend certificate name and resolve it to this mesh's gateway.
        # Containers sharing mesh's namespace inherit these host mappings.
        mesh["extra_hosts"] = {telemetry_server_name: gateway_ip}
        compose["networks"]["application"] = {"name": name + "-application", "internal": True}
        compose["volumes"].update({key: {"name": name + "-" + key} for key in ("policy-cache", "envoy-logs", "vector-state")})
        compose["services"]["opa"] = {"build": {"context": str(Path(connector_source).resolve() / "opa-sidecar")}, "network_mode": "service:mesh",
            "cap_drop": ["ALL"], "command": ["-addr", "127.0.0.1:9191", "-metrics-addr", "127.0.0.1:9192"],
            "environment": {"TENANT": tenant["id"], "TENANTS": tenant["id"], "KEYCLOAK_ISSUER": tenant["issuer"],
                "CONNECTOR_ID": tenant["connector_id"], "CONNECTOR_ENDPOINT": "https://" + tenant["application_host"],
                "TRUST_ENGINE_MODE": "grpc", "TRUST_ENGINE_ADDR": gateway_ip + ":50051", "POLICY_SERVER": "https://" + gateway_ip + ":50553",
                "TLS_CERTS_DIR": "/certs", "POLICIES_DIR": "/policies-live", "POLICY_OUT_DIR": "/policies-live"},
            "volumes": [str(client_dir) + ":/certs:ro", "policy-cache:/policies-live"],
            "depends_on": {"mesh": {"condition": "service_healthy"}},
            "healthcheck": {"test": ["CMD", "wget", "-qO-", "http://127.0.0.1:9192/readyz"], "interval": "3s", "timeout": "3s", "retries": 30}, "restart": "unless-stopped"}
        envoy = compose["services"]["envoy"]
        envoy["depends_on"]["opa"] = {"condition": "service_healthy"}
        envoy["volumes"].extend([str(Path(application_tls).resolve()) + ":/etc/envoy/certs:ro", "envoy-logs:/var/log/envoy"])
        if oidc_ca:
            envoy["volumes"].append(str(Path(oidc_ca).resolve()) + ":/config/oidc-ca.crt:ro")
        compose["services"]["portal"] = {"build": {"context": str(Path(connector_source).resolve() / "zetris-portal")},
            "networks": ["application"], "cap_drop": ["ALL"], "restart": "unless-stopped"}
        transform = '. = parse_json!(.message)\n.tenant_id = ' + json.dumps(tenant["id"]) + '\n.connector_id = ' + json.dumps(tenant["connector_id"]) + '\nts = parse_timestamp!(.timestamp, "%+")\n.timestamp_ms = format_timestamp!(ts, "%Y-%m-%d %H:%M:%S%.3f")\n.timestamp = format_timestamp!(ts, "%Y-%m-%d %H:%M:%S")\n.response_code = to_int!(.response_code)\n.duration_ms = to_int!(.duration_ms)\n'
        vector = {"data_dir": "/var/lib/vector", "sources": {"access": {"type": "file", "include": ["/var/log/envoy/access.log"], "read_from": "beginning"}},
            "transforms": {"tenant": {"type": "remap", "inputs": ["access"], "source": transform}},
            "sinks": {"telemetry": {"type": "clickhouse", "inputs": ["tenant"], "endpoint": "https://" + telemetry_server_name + ":8443",
                "database": "default", "table": "envoy_access_logs", "format": "json_each_row", "skip_unknown_fields": True,
                "auth": {"strategy": "basic", "user": tenant["telemetry_user"], "password": "${CLICKHOUSE_PASSWORD}"},
                "tls": {"ca_file": "/config/telemetry-ca.crt", "verify_certificate": True, "verify_hostname": True, "server_name": telemetry_server_name},
                "batch": {"timeout_secs": 0.5}, "healthcheck": {"enabled": False}}}}
        artifacts["vector.json"] = json.dumps(vector, indent=2) + "\n"
        artifacts["keycloak-client.json"] = json.dumps(application_client(tenant, client_secret), indent=2) + "\n"
        compose["services"]["vector"] = {"image": VECTOR, "network_mode": "service:mesh", "cap_drop": ["ALL"],
            "environment": {"CLICKHOUSE_PASSWORD": netbird.secret(tenant, "telemetry_password", environ).replace("$", "$$")},
            "command": ["--config", "/config/vector.json"], "depends_on": {"envoy": {"condition": "service_healthy"}},
            "volumes": ["./vector.json:/config/vector.json:ro", str(Path(telemetry_ca).resolve()) + ":/config/telemetry-ca.crt:ro", "envoy-logs:/var/log/envoy:ro", "vector-state:/var/lib/vector"], "restart": "unless-stopped"}
        metadata.update(connector=tenant["connector_id"], issuer=tenant["issuer"], host=tenant["application_host"], certificate_sha256=fingerprint, gateway_ip=gateway_ip)
    artifacts.update({"envoy.json": json.dumps(config, indent=2) + "\n", "compose.json": json.dumps(compose, indent=2) + "\n", "tenant.json": json.dumps(metadata, indent=2) + "\n"})
    return artifacts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=ROOT / "config/tenants.json")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--role", choices=("gateway", "connector"), required=True)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--api-network", default="zetris-service-access")
    parser.add_argument("--connector-source", type=Path,
        default=ROOT.parent / ("node2" if (ROOT.parent / "node2").is_dir() else "zetris-current-node2"))
    parser.add_argument("--client-dir", type=Path)
    parser.add_argument("--grant-file", type=Path, default=ROOT / "config/connector-access.json")
    parser.add_argument("--gateway-ip")
    parser.add_argument("--application-tls", type=Path)
    parser.add_argument("--telemetry-ca", type=Path)
    parser.add_argument("--telemetry-server-name", default="clickhouse")
    parser.add_argument("--netbird-ca", type=Path)
    parser.add_argument("--oidc-ca", type=Path)
    parser.add_argument("--lab", action="store_true")
    args = parser.parse_args(argv)
    tenants = netbird.registry.load_registry(args.registry)
    tenant = next((item for item in tenants if item["id"] == args.tenant), None)
    if tenant is None:
        raise DeploymentError("Requested tenant is absent")
    if not args.write:
        print(json.dumps({"dry_run": True, "tenant": tenant["id"], "role": args.role,
            "peer": tenant["gateway_id" if args.role == "gateway" else "connector_id"], "allowed_tcp_ports": list(PORTS) if args.role == "gateway" else [443]}, indent=2))
        return 0
    if args.out is None:
        raise DeploymentError("Writing runtime configuration requires --out")
    if args.role == "connector" and any(value is None for value in (args.client_dir, args.gateway_ip, args.application_tls, args.telemetry_ca)):
        raise DeploymentError("Connector generation requires client credentials, gateway IP, application TLS and telemetry CA")
    artifacts = build(tenant, args.role, api_network=args.api_network, connector_source=args.connector_source,
        client_dir=args.client_dir, grant_file=args.grant_file, gateway_ip=args.gateway_ip,
        application_tls=args.application_tls, telemetry_ca=args.telemetry_ca, telemetry_server_name=args.telemetry_server_name,
        netbird_ca=args.netbird_ca, oidc_ca=args.oidc_ca, lab=args.lab)
    created = netbird.write_artifacts(args.out, artifacts)
    print("Tenant access files " + ("created" if created else "already match") + "; private values withheld")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (DeploymentError, netbird.RenderError, netbird.registry.RegistryError) as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        raise SystemExit("Tenant access rendering failed: " + type(error).__name__ + "; details withheld") from None
