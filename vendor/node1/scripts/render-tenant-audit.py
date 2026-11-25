#!/usr/bin/env python3
"""Preview or generate a tenant audit instance with scoped backend accounts."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def load(file,name):
    spec = importlib.util.spec_from_file_location(name,ROOT/"scripts"/file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


netbird = load("render-netbird-tenant.py","netbird_renderer")
data = load("provision-audit-data.py","audit_data")


def build(tenant,*,network="n1-control",backend_ca,oidc_ca=None,environ=None):
    environ = os.environ if environ is None else environ
    if not {"audit_hostname","audit_oidc_client_id","audit_port"} <= set(tenant):
        raise data.DataError("Tenant audit host, client and loopback port are required")
    if not netbird.registry.STACK.fullmatch(network) or not Path(backend_ca).is_file():
        raise data.DataError("Prepared backend network and CA are required")
    user,database = data.names(tenant)
    secret = lambda field: netbird.secret(tenant,field,environ)
    client_secret = secret("audit_client_secret")
    origin = "https://"+tenant["audit_hostname"]
    environment = {"LISTEN":"0.0.0.0:9092","CLICKHOUSE_ADDR":"clickhouse:9440","CLICKHOUSE_DB":database,
        "CLICKHOUSE_USER":user,"CLICKHOUSE_PASSWORD":secret("audit_clickhouse_password").replace("$","$$"),"CLICKHOUSE_TLS_CA":"/tls/ca.crt",
        "REDIS_ADDR":"redis:6380","REDIS_USER":user,"REDIS_PASSWORD":secret("audit_redis_password").replace("$","$$"),"REDIS_TLS_CA":"/tls/ca.crt",
        "AUDIT_TENANT":tenant["id"],"AUDIT_ISSUER":tenant["issuer"],"AUDIT_PUBLIC_URL":origin,
        "AUDIT_CLIENT_ID":tenant["audit_oidc_client_id"],"AUDIT_CLIENT_SECRET":client_secret.replace("$","$$"),"POLICY_DIR":"/policies"}
    service = {"build":{"context":str(ROOT/"risk-engine"),"dockerfile":"Dockerfile.audit"},"environment":environment,
        "ports":["127.0.0.1:"+str(tenant["audit_port"])+":9092"],"networks":["backend"],
        "volumes":[str(Path(backend_ca).resolve())+":/tls/ca.crt:ro",str(ROOT/"policies")+":/policies:ro"],"restart":"unless-stopped"}
    if oidc_ca:
        if not Path(oidc_ca).is_file():
            raise data.DataError("Audit OIDC CA is unavailable")
        service["volumes"].append(str(Path(oidc_ca).resolve())+":/tls/oidc-ca.crt:ro")
        environment["SSL_CERT_FILE"] = "/tls/oidc-ca.crt"
    compose = {"name":tenant["netbird_stack"]+"-audit","services":{"audit":service},"networks":{"backend":{"external":True,"name":network}}}
    client = {"clientId":tenant["audit_oidc_client_id"],"enabled":True,"publicClient":False,"protocol":"openid-connect",
        "standardFlowEnabled":True,"secret":client_secret,"redirectUris":[origin+"/oauth2/callback"],"webOrigins":[origin],
        "attributes":{"post.logout.redirect.uris":origin+"/login"},
        "defaultClientScopes":["profile","email","roles","basic"],"protocolMappers":[{"name":"audit-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper",
            "config":{"included.client.audience":tenant["audit_oidc_client_id"],"access.token.claim":"true","id.token.claim":"true"}}]}
    return {"compose.json":json.dumps(compose,indent=2)+"\n","keycloak-client.json":json.dumps(client,indent=2)+"\n",
        "keycloak-roles.json":json.dumps([{"name":"audit-viewer"},{"name":"audit-admin"}],indent=2)+"\n",
        "Caddyfile.snippet":tenant["audit_hostname"]+" {\n reverse_proxy 127.0.0.1:"+str(tenant["audit_port"])+"\n}\n",
        "tenant.json":json.dumps({"tenant":tenant["id"],"host":tenant["audit_hostname"],"issuer":tenant["issuer"],"database":database,"account":user},indent=2)+"\n"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry",type=Path,default=ROOT/"config/tenants.json")
    parser.add_argument("--tenant",required=True)
    parser.add_argument("--write",action="store_true")
    parser.add_argument("--out",type=Path)
    parser.add_argument("--network",default="n1-control")
    parser.add_argument("--backend-ca",type=Path)
    parser.add_argument("--oidc-ca",type=Path)
    args = parser.parse_args(argv)
    tenant = next((item for item in netbird.registry.load_registry(args.registry) if item["id"]==args.tenant),None)
    if tenant is None or "audit_hostname" not in tenant:
        raise data.DataError("Requested audit tenant is absent")
    if not args.write:
        print(json.dumps({"dry_run":True,"tenant":tenant["id"],"host":tenant["audit_hostname"],"database":data.names(tenant)[1],"account":data.names(tenant)[0]},indent=2))
        return 0
    if args.out is None or args.backend_ca is None:
        raise data.DataError("Audit generation requires a private output directory and backend CA")
    created = netbird.write_artifacts(args.out,build(tenant,network=args.network,backend_ca=args.backend_ca,oidc_ca=args.oidc_ca))
    print("Tenant audit files "+("created" if created else "already match")+"; private values withheld")
    return 0


if __name__=="__main__":
    try:
        sys.exit(main())
    except (data.DataError,netbird.RenderError,netbird.registry.RegistryError) as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        raise SystemExit("Audit generation failed: "+type(error).__name__+"; details withheld") from None
