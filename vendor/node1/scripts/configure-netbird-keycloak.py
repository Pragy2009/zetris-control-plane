#!/usr/bin/env python3
"""Add the exact tenant Keycloak provider to its NetBird instance.

Dry-run by default. Uses an existing private administrator PAT. Never creates
owners, imports realms, replaces providers or rotates existing secrets.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import ssl
import sys
import urllib.request
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("netbird_render", Path(__file__).with_name("render-netbird-tenant.py"))
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)


class ProviderError(RuntimeError):
    """A diagnostic with request/response secrets withheld."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def requester(origin, ca=None):
    context = ssl.create_default_context(cafile=str(ca) if ca else None)
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
    def request(path, method="GET", body=None, token=None):
        headers = {"Accept":"application/json"}
        if token:
            headers["Authorization"] = "Token " + token
        if body is not None:
            headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode() if body is not None else None
        try:
            with opener.open(urllib.request.Request(origin+path,data=data,headers=headers,method=method),timeout=20) as response:
                raw = response.read(1 << 20)
                return json.loads(raw) if raw else None
        except HTTPError as error:
            raise ProviderError("NetBird returned HTTP "+str(error.code)+"; response withheld") from None
        except (URLError,ValueError):
            raise ProviderError("Could not reach or decode NetBird through verified TLS") from None
    return request


def inspect_provider(tenant, origin, token, request):
    discovery = request("/oauth2/.well-known/openid-configuration")
    if discovery.get("issuer") != origin+"/oauth2":
        raise ProviderError("Target NetBird issuer does not match this tenant origin")
    providers = request("/api/identity-providers",token=token)
    if not isinstance(providers,list):
        raise ProviderError("Unexpected identity provider list")
    desired = {"type":"oidc","name":"Keycloak "+tenant["id"],"issuer":tenant["issuer"],
        "client_id":tenant["netbird_oidc_client_id"]}
    for provider in providers:
        if provider.get("issuer") != tenant["issuer"]:
            raise ProviderError("Another realm/provider exists; inspect before altering this tenant instance")
    if providers:
        if len(providers)==1 and all(providers[0].get(key)==value for key,value in desired.items()):
            return True
        raise ProviderError("Conflicting tenant provider exists; nothing was replaced")
    return False


def configure(tenant, origin, token, client_secret, request):
    if inspect_provider(tenant,origin,token,request):
        return "already configured"
    desired = {"type":"oidc","name":"Keycloak "+tenant["id"],"issuer":tenant["issuer"],
        "client_id":tenant["netbird_oidc_client_id"]}
    payload = dict(desired,client_secret=client_secret)
    request("/api/identity-providers",method="POST",body=payload,token=token)
    installed = request("/api/identity-providers",token=token)
    if len(installed)!=1 or not all(installed[0].get(key)==value for key,value in desired.items()):
        raise ProviderError("Provider submitted but read-back did not match; inspect before retrying")
    return "configured"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry",type=Path,default=ROOT/"config/tenants.json")
    parser.add_argument("--tenant",required=True)
    parser.add_argument("--origin")
    parser.add_argument("--ca",type=Path)
    parser.add_argument("--token-ref",default="env:NETBIRD_ADMIN_TOKEN")
    parser.add_argument("--apply",action="store_true")
    args = parser.parse_args(argv)
    tenants = render.registry.load_registry(args.registry)
    tenant = next((item for item in tenants if item["id"]==args.tenant),None)
    if tenant is None or "netbird_oidc_client_id" not in tenant:
        raise ProviderError("Tenant and its NetBird Keycloak client configuration are required")
    origin = render.origin_for(tenant,args.origin)
    if not args.apply:
        print(json.dumps({"dry_run":True,"tenant":tenant["id"],"issuer":tenant["issuer"],
            "client_id":tenant["netbird_oidc_client_id"],"keycloak_redirect_uri":origin+"/oauth2/callback",
            "dashboard_post_logout_uri":origin+"/"},indent=2))
        return 0
    if not render.registry.SECRET_REF.fullmatch(args.token_ref):
        raise ProviderError("Administrator token must use a private environment reference")
    token = os.environ.get(args.token_ref.split(":",1)[1],"")
    if not token:
        raise ProviderError("Existing tenant NetBird administrator token is required")
    client_secret = render.secret(tenant,"keycloak_client_secret",os.environ)
    status = configure(tenant,origin,token,client_secret,requester(origin,args.ca))
    print("Tenant Keycloak provider "+status+"; credentials withheld")
    return 0


if __name__=="__main__":
    try:
        sys.exit(main())
    except (ProviderError,render.RenderError,render.registry.RegistryError) as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        raise SystemExit("Provider configuration failed: "+type(error).__name__+"; details withheld") from None
