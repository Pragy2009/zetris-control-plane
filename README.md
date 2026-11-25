# tenant-control-plane — the missing piece (local module)

Created Nov 20, 2026. This folder is the **only** place this part of the project
is built. It never writes to your lead's repo; it only *reads* his scripts from
`..\zetris-views` (configured in `control/registry.py:ZETRIS_DEFAULT`).

## Assumptions (since you said "any other questions?" — none were blocking)
1. Free tier = **10 users** (matching the NetBird free allowance), 1 protected app,
   shadow risk mode. Paid tier is defined but inactive until you decide prices.
2. **NetBird Community Edition / self-hosted only** — no paid NetBird features.
3. Deployments to Dokploy are **performed by you**, from detailed steps I provide.
4. Secrets are entered by you in Dokploy's UI. This module stores **only `env:`
   references**. No `.env` file is ever opened here, ever.
5. Local lab domain: `*.ztna.local.test` (preview only). Real domain is your choice.

## What exists now (build slice 2 — DONE locally)
| File | Purpose |
| --- | --- |
| `control/registry.py` | Tenant registry validated by the lead's validator; free/paid limits; `env:` refs only |
| `control/render.py` | Calls the lead's renderers for all five planes; throwaway in-memory secrets |
| **`control/steps.py`** | 12-step live engine (Keycloak, Postgres, NetBird, gateway/connector, policy, audit, routes, verify, handoff). **Preview by default**; apply requires an explicit confirmation token |
| **`web/app.py`** | Public signup + operator dashboard + **tenant-facing portal** (one-time handoff page, per-tenant management console), free-tier walls, lifecycle, healthz |
| `web/landing.js` | Role-aware entry page: platform operator vs customer organization |
| `web/tenant-handoff.js`, `web/tenant-portal.js` | Tenant handoff + tenant console frontend (external scripts, strict CSP) |
| **`control/lifecycle.py`** | Suspend / resume / backup / guarded delete for all four tenant stacks |
| **`control/client.py`** | NetBird CE setup-key issuance (one-time, never stored) + official client download/onboarding instructions |
| `control/cli.py` | `new-registry`, `validate`, `plan`, `steps`, `render`, **`run`** (preview or guarded apply) |
| `vendor/node1`, `vendor/node2` | Self-contained snapshot of the lead's renderers and templates — no build-time dependency on his tree |
| `config/*` | Canary registry, per-tenant application model, non-secret operator config |
| `control/users.py` | Real Keycloak invitations with role mapping (apply mode) |
| `control/apps.py` | Real add-app: per-tenant app doc, Rego re-render, route snippet |
| `control/toggles.py` | Real feature reconciliation into tenant stacks |
| `tests/` | **22 local tests — all passing** (registry, render, steps, lifecycle, invites, apps, auth, signup/tier walls, handoff/tenant portal, isolation) |
| `provisioned/canary/` | Rendered preview artifacts (throwaway keys; git-ignored) |
| **`Dockerfile`** | Dokploy build: Python 3.12 + Docker CLI + pinned dependencies |
| **`docker-compose.control-plane.yml`** | Dokploy-ready: Traefik TLS labels, persistent volumes, healthcheck, operator auth, guarded apply |
| `docker-compose.preview.yml` | Local preview CLI + web service; no live dependencies |

## Verified locally (basic commands only)
```
python -B -m unittest discover -s tests -v        # 16/16 OK
python -B -m control.cli validate
python -B -m control.cli render --tenant canary --out provisioned
python -B -m control.cli run --tenant canary      # all 12 steps preview OK
python -B -m control.cli suspend --tenant canary  # 4 stop commands planned
python -B -m control.cli resume --tenant canary
python -B -m control.cli backup --tenant canary
python -B -m control.cli client --tenant canary   # one-time key (preview stub)
python -B -m control.cli delete --tenant canary   # deletion planned, nothing removed
```
Render result: `netbird=5, policy=1, audit=5, access-gateway=5, access-connector=7`
artifacts; lead's repo `git status` clean; no secret values anywhere.

## What is NOT built yet (only live-stage work remains)
1. **Live apply against real services** — every apply path exists but requires
   real endpoints/credentials and your explicit `--apply --confirm` token.
2. **Live isolation/acceptance proof** — the structural half passes 17/17; the
   real 401/404/peer denial tests require the running Dokploy environment.
3. **Dokploy rollout** — you execute it from `DOKPLOY-STEPS.md`.

Local build is COMPLETE. Start with `RUN-AND-TEST.md`.

## Security boundary
- Only `env:` references in config/registry; secret values live in Dokploy's UI.
- Preview renders use `secrets.token_urlsafe` generated **in memory** and a
  throwaway CA under `provisioned/`. Never reuse preview keys in production.
- Nothing here contacts a live service. No Docker, HTTP or DB calls are made.

See `LOCAL-RUN.md` and `DOKPLOY-STEPS.md` for the exact next actions.
