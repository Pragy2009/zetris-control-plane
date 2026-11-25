#!/usr/bin/env python3
"""Render private tenant NetBird runtime files. Preview is the default.

No stack is started and no database is provisioned. Existing output is retained
when identical; changed ownership/configuration fails without overwriting it.
"""
import argparse
import base64
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
from string import Template
import sys
import tempfile
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tenant_registry", Path(__file__).with_name("provision-tenant.py"))
registry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry)


class RenderError(RuntimeError):
    """A diagnostic without credentials or private configuration values."""


def versions():
    lock = json.loads((ROOT / "netbird-infra/versions.json").read_text(encoding="utf-8"))
    for key in ("server_image", "dashboard_image", "client_image"):
        if not re.fullmatch(r"netbirdio/[a-z-]+:[v0-9.]+@sha256:[0-9a-f]{64}", lock[key]):
            raise RenderError("NetBird images must be pinned by version and digest")
    return lock


def secret(tenant, name, environ):
    ref = tenant["secret_refs"].get(name, "")
    if not registry.SECRET_REF.fullmatch(ref):
        raise RenderError("Required private secret reference is missing")
    value = environ.get(ref.split(":", 1)[1], "")
    if len(value) < 24 or "\x00" in value:
        raise RenderError("Required private secret is missing or too short")
    return value


def origin_for(tenant, origin=None, lab=False):
    value = "https://" + tenant["netbird_hostname"] if origin is None else origin
    # urlparse strips some control characters. Reject them before parsing so
    # the validated URL is also safe to embed in env files and Caddy syntax.
    if (not isinstance(value, str) or not value
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
            or any(char in value for char in "?#;")):
        raise RenderError("Invalid NetBird origin")
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        raise RenderError("Invalid NetBird origin") from None
    standard_port = 80 if parsed.scheme == "http" else 443
    if (parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or parsed.params
            or parsed.path not in ("", "/") or parsed.hostname != tenant["netbird_hostname"]
            or parsed.scheme not in (("http", "https") if lab else ("https",))
            or parsed.netloc.endswith(":")
            or (port is not None and not 1024 <= port <= 65535 and port != standard_port)):
        raise RenderError("NetBird origin must match the configured tenant hostname")
    return parsed.scheme + "://" + parsed.netloc


def quote_dsn(value):
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def derive(seed, tenant, purpose):
    return base64.b64encode(hmac.new(seed.encode(), ("zetris-netbird-v1:"+tenant+":"+purpose).encode(), hashlib.sha256).digest()).decode()


def build_artifacts(tenant, *, db_host, db_network, trusted_proxies, db_port=5432,
                    db_sslmode="verify-full", origin=None, lab=False, bootstrap=False,
                    environ=None, db_ca=None, oidc_ca=None):
    environ = os.environ if environ is None else environ
    lock = versions()
    public_origin = origin_for(tenant, origin, lab)
    if "netbird_oidc_client_id" not in tenant or "keycloak_client_secret" not in tenant["secret_refs"]:
        raise RenderError("The tenant NetBird Keycloak client and its secret reference are required")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", db_host) or not registry.STACK.fullmatch(db_network):
        raise RenderError("Invalid database host/network")
    if not 1 <= db_port <= 65535 or db_sslmode not in ("verify-full", "disable"):
        raise RenderError("Invalid database transport configuration")
    if db_sslmode == "disable" and not lab:
        raise RenderError("Plaintext database transport is restricted to the explicit local lab")
    if not trusted_proxies:
        raise RenderError("Provide the address ranges of the actual reverse proxy")
    for value in trusted_proxies:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise RenderError("Invalid trusted reverse-proxy range") from None
        if network.prefixlen == 0:
            raise RenderError("Do not trust every address as a reverse proxy")
    seed = secret(tenant, "netbird_auth_secret", environ)
    password = secret(tenant, "database_password", environ)
    dsn_fields = {"host":db_host,"port":db_port,"user":tenant["netbird_database_role"],
        "password":password,"dbname":tenant["netbird_database"],"sslmode":db_sslmode}
    if db_ca:
        dsn_fields["sslrootcert"] = "/etc/netbird/db-ca.crt"
    dsn = " ".join(key+"="+quote_dsn(value) for key,value in dsn_fields.items())
    exposed_address = public_origin
    if urlparse(public_origin).port is None:
        # The pinned native Signal client needs an explicit host:port target.
        # Embedded OIDC still uses the exact browser origin without an added port.
        exposed_address += ":443" if public_origin.startswith("https://") else ":80"
    config = {"server": {
        "listenAddress":":80", "exposedAddress":exposed_address,
        "stunPorts":[tenant["stun_port"]], "metricsPort":9090, "healthcheckAddress":":9000",
        "logLevel":"warn", "logFile":"console", "dataDir":"/var/lib/netbird",
        "disableAnonymousMetrics":True, "disableGeoliteUpdate":True,
        "authSecret":derive(seed,tenant["id"],"relay"),
        "auth": {"issuer":public_origin+"/oauth2", "localAuthDisabled":not bootstrap,
            "signKeyRefreshEnabled":True, "sessionCookieEncryptionKey":derive(seed,tenant["id"],"cookie"),
            "dashboardRedirectURIs":[public_origin+"/nb-auth",public_origin+"/nb-silent-auth"],
            "dashboardPostLogoutRedirectURIs":[public_origin+"/"],"cliRedirectURIs":["http://localhost:53000/"]},
        "reverseProxy":{"trustedPeers":trusted_proxies,"trustedHTTPProxies":trusted_proxies},
        "store":{"engine":"postgres","dsn":dsn,"encryptionKey":derive(seed,tenant["id"],"store")},
        "activityStore":{"engine":"postgres","dsn":dsn},
        "authStore":{"engine":"postgres","dsn":dsn},
    }}
    replacements = {"STACK":tenant["netbird_stack"],"SERVER_IMAGE":lock["server_image"],
        "DASHBOARD_IMAGE":lock["dashboard_image"],"BOOTSTRAP":"true" if bootstrap else "false",
        "MANAGEMENT_PORT":str(tenant["management_port"]),"DASHBOARD_PORT":str(tenant["dashboard_port"]),
        "STUN_PORT":str(tenant["stun_port"]),"UDP_BIND":"127.0.0.1" if lab else "0.0.0.0",
        "DATABASE_NETWORK":db_network}
    template = (ROOT / "netbird-infra/templates/compose.tenant.json.tmpl").read_text(encoding="utf-8")
    # Compose consumes $$ as an escaped shell dollar. string.Template must
    # preserve it rather than trying to resolve the healthcheck's shell variable.
    template = template.replace("$$status", "__SHELL_STATUS__")
    compose = json.loads(Template(template).substitute(replacements).replace("__SHELL_STATUS__", "$$status"))
    server = compose["services"]["server"]
    for file, path in (("db-ca.crt", db_ca),("oidc-ca.crt",oidc_ca)):
        if path:
            if not Path(path).is_file():
                raise RenderError("Configured CA file is unavailable")
            server["volumes"].append(str(Path(path).resolve())+":/etc/netbird/"+file+":ro")
    if db_ca:
        # The pinned embedded Dex DSN parser omits sslrootcert. lib/pq uses
        # this standard path for its root-owned process instead.
        server["volumes"].append(str(Path(db_ca).resolve())+":/root/.postgresql/root.crt:ro")
    if oidc_ca:
        server["environment"]["SSL_CERT_FILE"] = "/etc/netbird/oidc-ca.crt"
    dashboard = "\n".join([
        "NETBIRD_MGMT_API_ENDPOINT="+public_origin,"NETBIRD_MGMT_GRPC_API_ENDPOINT="+public_origin,
        "AUTH_AUDIENCE=netbird-dashboard","AUTH_CLIENT_ID=netbird-dashboard","AUTH_CLIENT_SECRET=",
        "AUTH_AUTHORITY="+public_origin+"/oauth2","USE_AUTH0=false",
        "AUTH_SUPPORTED_SCOPES=openid profile email groups","AUTH_REDIRECT_URI=/nb-auth",
        "AUTH_SILENT_REDIRECT_URI=/nb-silent-auth","LETSENCRYPT_DOMAIN=none","NGINX_SSL_PORT=443",""])
    # A bare hostname enables Caddy's automatic HTTPS even on a lab HTTP port.
    caddy_address = public_origin if public_origin.startswith("http://") else public_origin.split("://",1)[1]
    caddy = caddy_address + " {\n    @grpc header Content-Type application/grpc*\n"
    caddy += "    reverse_proxy @grpc h2c://127.0.0.1:"+str(tenant["management_port"])+"\n"
    caddy += "    @backend path /relay* /ws-proxy/* /api/* /oauth2/*\n"
    caddy += "    reverse_proxy @backend 127.0.0.1:"+str(tenant["management_port"])+"\n"
    caddy += "    reverse_proxy 127.0.0.1:"+str(tenant["dashboard_port"])+"\n}\n"
    metadata = {"tenant":tenant["id"],"stack":tenant["netbird_stack"],"origin":public_origin,
        "issuer":tenant["issuer"],"database":tenant["netbird_database"],"versions":lock}
    return {"server.json":json.dumps(config,indent=2)+"\n","compose.json":json.dumps(compose,indent=2)+"\n",
        "dashboard.env":dashboard,"Caddyfile.snippet":caddy,"tenant.json":json.dumps(metadata,indent=2)+"\n"}


def private_write(path, value):
    # Request restrictive creation permissions before any secret is written.
    descriptor = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,"w",encoding="utf-8",newline="\n") as stream:
        stream.write(value)


def write_artifacts(out, artifacts, *, finalize=False):
    out = Path(os.path.abspath(out))
    if any(path.is_symlink() for path in (out,*out.parents)):
        raise RenderError("Generated output must not use symlinks")
    out = out.resolve()
    if out == ROOT or ROOT in out.parents and ROOT / "provisioned" not in out.parents:
        raise RenderError("Generated runtime files inside the repository must use provisioned/")
    if out.exists():
        if out.is_symlink() or not out.is_dir() or set(path.name for path in out.iterdir()) != set(artifacts):
            raise RenderError("Existing output is not this complete tenant generation")
        if any((out/name).is_symlink() or not (out/name).is_file() for name in artifacts):
            raise RenderError("Existing output contains unexpected files or symlinks")
        existing = {name:(out/name).read_text(encoding="utf-8") for name in artifacts}
        if existing != artifacts:
            if not finalize:
                raise RenderError("Existing output differs; it was not overwritten or rotated")
            expected = dict(existing)
            config = json.loads(expected["server.json"])
            compose = json.loads(expected["compose.json"])
            if (config["server"]["auth"]["localAuthDisabled"] not in (False,True)
                    or compose["services"]["server"]["environment"]["NB_SETUP_PAT_ENABLED"] not in ("true","false")):
                raise RenderError("Only an existing explicit bootstrap generation can be finalized")
            config["server"]["auth"]["localAuthDisabled"] = True
            compose["services"]["server"]["environment"]["NB_SETUP_PAT_ENABLED"] = "false"
            expected["server.json"] = json.dumps(config,indent=2)+"\n"
            expected["compose.json"] = json.dumps(compose,indent=2)+"\n"
            if expected != artifacts:
                raise RenderError("Finalization cannot change ownership, versions, secrets or other settings")
            # Stage both files before replacing either. Keep temporary files
            # outside the generation so a failed replacement cannot make the
            # output look foreign and prevent an otherwise valid retry.
            with tempfile.TemporaryDirectory(prefix=".netbird-finalize-",dir=out.parent) as directory:
                stage = Path(directory)
                for name in ("server.json","compose.json"):
                    private_write(stage/name,artifacts[name])
                # Each replacement is atomic. A partial transition can be
                # retried without rotating keys or changing other settings.
                for name in ("server.json","compose.json"):
                    os.replace(stage/name,out/name)
            return True
        return False
    if finalize:
        raise RenderError("Finalization requires an existing tenant bootstrap generation")
    out.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    # An interrupted initial write leaves no partial generation at the target.
    with tempfile.TemporaryDirectory(prefix=".netbird-render-",dir=out.parent) as directory:
        stage = Path(directory)
        for name,value in artifacts.items():
            private_write(stage/name,value)
        stage.rename(out)
        # TemporaryDirectory cleanup is harmless after the directory is moved.
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry",type=Path,default=ROOT/"config/tenants.json")
    parser.add_argument("--tenant",required=True)
    parser.add_argument("--write",action="store_true")
    parser.add_argument("--out",type=Path)
    parser.add_argument("--db-host",default="postgres")
    parser.add_argument("--db-port",type=int,default=5432)
    parser.add_argument("--db-network",default="zetris-netbird-database")
    parser.add_argument("--db-sslmode",choices=("verify-full","disable"),default="verify-full")
    parser.add_argument("--trusted-proxy",action="append",default=[])
    parser.add_argument("--origin")
    parser.add_argument("--lab",action="store_true")
    parser.add_argument("--bootstrap",action="store_true")
    parser.add_argument("--finalize",action="store_true",help="Disable local login/setup PAT after testing Keycloak login; preserve all other runtime values")
    parser.add_argument("--token-ref",default="env:NETBIRD_ADMIN_TOKEN")
    parser.add_argument("--api-ca",type=Path)
    parser.add_argument("--db-ca",type=Path)
    parser.add_argument("--oidc-ca",type=Path)
    args = parser.parse_args(argv)
    if args.bootstrap and args.finalize:
        raise RenderError("Bootstrap and finalization are separate actions")
    tenants = registry.load_registry(args.registry)
    tenant = next((tenant for tenant in tenants if tenant["id"]==args.tenant),None)
    if tenant is None:
        raise RenderError("Requested tenant is absent")
    if not args.write:
        print(json.dumps({"dry_run":True,"tenant":tenant["id"],"stack":tenant["netbird_stack"],
            "origin":origin_for(tenant,args.origin,args.lab),"database":tenant["netbird_database"],
            "versions":versions(),"keycloak_provider":"requires authenticated setup after startup"},indent=2))
        return 0
    if args.out is None:
        raise RenderError("--write requires --out")
    artifacts = build_artifacts(tenant,db_host=args.db_host,db_network=args.db_network,db_port=args.db_port,
        trusted_proxies=args.trusted_proxy,db_sslmode=args.db_sslmode,origin=args.origin,lab=args.lab,
        bootstrap=args.bootstrap,db_ca=args.db_ca,oidc_ca=args.oidc_ca)
    if args.finalize:
        if not registry.SECRET_REF.fullmatch(args.token_ref):
            raise RenderError("Administrator token must use a private environment reference")
        token = os.environ.get(args.token_ref.split(":",1)[1],"")
        if not token or "netbird_oidc_client_id" not in tenant:
            raise RenderError("Finalization requires the tenant administrator token and Keycloak client")
        provider_spec = importlib.util.spec_from_file_location("netbird_provider",ROOT/"scripts/configure-netbird-keycloak.py")
        provider = importlib.util.module_from_spec(provider_spec)
        provider_spec.loader.exec_module(provider)
        public_origin = origin_for(tenant,args.origin,args.lab)
        if not provider.inspect_provider(tenant,public_origin,token,provider.requester(public_origin,args.api_ca)):
            raise RenderError("The exact tenant Keycloak provider must exist before finalization")
    created = write_artifacts(args.out,artifacts,finalize=args.finalize)
    print("Tenant runtime files "+("created" if created else "already match")+"; private values withheld")
    return 0


if __name__=="__main__":
    try:
        sys.exit(main())
    except (RenderError,registry.RegistryError) as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        raise SystemExit("NetBird rendering failed: "+type(error).__name__+"; details withheld") from None
