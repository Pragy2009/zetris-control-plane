"""Real tenant user invitations via the Keycloak Admin API.

Passwords are generated in memory, sent once to Keycloak, and returned once to
the operator. Never read from or written to a .env or to the store.
"""
from __future__ import annotations

import secrets

from .steps import Context, StepError, _token_request

ROLE_MAP = {
    "viewer": {"audit": "audit-viewer", "realm": "viewer"},
    "developer": {"audit": "audit-viewer", "realm": "developer"},
    "tenant_admin": {"audit": "audit-admin", "realm": "tenant_admin"},
    "platform_operator": {"audit": "audit-admin", "realm": "platform_operator"},
}


def invite(ctx: Context, email: str, role: str):
    if role not in ROLE_MAP:
        raise StepError("Unknown role")
    if ctx.runner.mode == "apply":
        ctx.runner.ensure_apply()
    password = secrets.token_urlsafe(24)
    kc = ctx.config["keycloak"]
    realm = ctx.tenant["realm"]
    base = kc["origin"] + "/admin/realms/" + realm
    token = _token_request(ctx)
    auth = {"Authorization": "Bearer " + token}

    # 1. Ensure the realm roles used by the access policy exist.
    mapping = ROLE_MAP[role]
    existing = ctx.runner.http("GET", base + "/roles", headers=auth)
    if ctx.runner.mode == "apply" and not isinstance(existing, list):
        raise StepError("Could not read realm roles")
    names = {item.get("name") for item in existing} if isinstance(existing, list) else set()
    roles_to_create = [name for name in ("viewer", "developer", "tenant_admin", "platform_operator")
                       if name not in names]
    for name in roles_to_create:
        ctx.runner.http("POST", base + "/roles", body={"name": name}, headers=auth)

    # 2. Create the user with a one-time password.
    created = ctx.runner.http("POST", base + "/users", body={
        "username": email, "email": email, "enabled": True, "emailVerified": True,
        "requiredActions": ["UPDATE_PASSWORD"],
        "credentials": [{"type": "password", "temporary": True,
                         "value": password if ctx.runner.mode == "apply" else "<rotated>"}],
    }, headers=auth)
    user_id = created.get("id") if isinstance(created, dict) else None
    if ctx.runner.mode == "apply" and not user_id:
        # Keycloak returns 201 with Location only; look the user up.
        found = ctx.runner.http("GET", base + "/users?username=" + email + "&exact=true", headers=auth)
        if isinstance(found, list) and found:
            user_id = found[0]["id"]
    if ctx.runner.mode == "apply" and not user_id:
        raise StepError("Invited user could not be verified")

    # 3. Assign realm role.
    role_rep = ctx.runner.http("GET", base + "/roles/" + mapping["realm"], headers=auth)
    if isinstance(role_rep, dict) and role_rep.get("name"):
        ctx.runner.http("POST", base + "/users/" + str(user_id) + "/role-mappings/realm",
                        body=[role_rep], headers=auth)

    # 4. Assign the matching audit client role.
    clients = ctx.runner.http("GET", base + "/clients?clientId=zetris-audit-" + ctx.tenant["id"], headers=auth)
    if isinstance(clients, list) and clients:
        client_id = clients[0]["id"]
        role_name = mapping["audit"]
        roles = ctx.runner.http("GET", base + "/clients/" + str(client_id) + "/roles", headers=auth)
        chosen = [item for item in roles if isinstance(item, dict) and item.get("name") == role_name] \
            if isinstance(roles, list) else []
        if chosen:
            ctx.runner.http("POST", base + "/users/" + str(user_id) +
                            "/role-mappings/clients/" + str(client_id), body=chosen, headers=auth)

    return {
        "tenant": ctx.tenant["id"], "email": email, "role": role,
        "one_time_password": password if ctx.runner.mode == "preview" else password,
        "mode": ctx.runner.mode,
        "note": "Password is shown once; user must change it at first login.",
    }
