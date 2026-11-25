"""NetBird Community Edition client onboarding for a tenant.

Uses NetBird's documented setup-key flow: a short-lived, usage-limited key is
issued through the tenant's own management API and shown ONCE. The control plane
never stores the key. Clients are downloaded from NetBird's official releases —
we do not ship a modified binary.
"""
from __future__ import annotations

from .steps import Context

DOWNLOAD = "https://github.com/netbirdio/netbird/releases"
DOCS = "https://docs.netbird.io/how-to/installation"


def issue_setup_key(ctx: Context, *, name="Zetris tenant client",
                    usage_limit=10, expires_in=86400, auto_groups=None):
    token_env = ctx.config.get("netbird", {}).get("admin_token_env", "ZTCP_ADMIN_TOKEN")
    token = ctx.secrets.get(token_env, "")
    body = {"name": name, "type": "reusable", "expires_in": expires_in,
            "auto_groups": auto_groups or [], "usage_limit": usage_limit}
    data = ctx.runner.http("POST", ctx.origin + "/api/setup-keys", body=body,
                           headers={"Authorization": "Token " + token} if token else {})
    key = data.get("key", "") if ctx.runner.mode == "apply" else "PREVIEW_ONLY (no key issued)"
    return {
        "tenant": ctx.tenant["id"],
        "one_time_setup_key": key,
        "expires_in_seconds": expires_in,
        "usage_limit": usage_limit,
        "management_url": ctx.origin,
        "download_url": DOWNLOAD,
        "docs_url": DOCS,
        "instructions": [
            "Download the NetBird client for your OS from the official releases page.",
            "Join the tenant network with the one-time setup key shown above.",
            "Sign in through the tenant's Keycloak realm when prompted.",
            "Verify with: netbird status (management and signal both connected).",
        ],
    }
