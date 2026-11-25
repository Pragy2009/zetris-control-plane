# LOCAL RUNBOOK — what works now, what needs your permission next

## A. Already run (by me, basic commands only — all green)
1. `python -B -m unittest discover -s tests -v` → **16/16 OK** (registry, render,
   step engine, lifecycle, client onboarding, signup HTTP + tier walls, isolation).
2. `python -B -m control.cli new-registry ...` → canary registry (no secrets).
3. `python -B -m control.cli validate` → valid, 1 tenant, free tier.
4. `python -B -m control.cli steps --tenant canary` → 12 ordered steps.
5. `python -B -m control.cli render --tenant canary --out provisioned` →
   all five planes rendered from the **vendored** renderers.
6. `python -B -m control.cli run --tenant canary` → **all 12 steps preview OK**,
   planned operations recorded, zero live side effects.
7. Lifecycle/client commands all previewed cleanly: `suspend`, `resume`, `backup`,
   `client`, `delete` (delete planned 9 operations; **nothing was removed** —
   `provisioned/canary/netbird/compose.json` still present).
8. `python -B web/app.py --port 8788` is available for local UI preview (not run
   against live services; the HTTP handler is covered by the tests).

## B. High-level local test — needs your explicit go-ahead (I will not run without it)
These are the commands that touch Docker. You can either approve them one by one
or run them yourself from this folder. **No real credentials are needed** — the
preview uses in-memory throwaway secrets.

1. `docker compose -f docker-compose.preview.yml config --quiet` — parse check only.
2. `docker compose -f docker-compose.preview.yml run --rm preview validate`
3. `docker compose -f docker-compose.preview.yml run --rm preview render --tenant canary --out provisioned`
   (writes inside the mounted module folder; same as the host run above).
4. Inspect `provisioned/canary/*/compose.json` with `docker compose -f <file> config --quiet`
   for each generated plane — verifies every rendered compose is syntactically valid.
5. `docker compose -f docker-compose.preview.yml run --rm preview run --tenant canary`
   — step engine inside the container (preview only).
6. `docker compose -f docker-compose.preview.yml up -d web` then open
   `http://127.0.0.1:8788/` — signup + status UI in preview mode.

**Not in this slice:** actually starting these stacks. That needs a shared
Keycloak/Postgres/ClickHouse/Redis and wildcard DNS — i.e. the Dokploy
environment. The accepted local proof today is *render + validate*; live proof
comes after the Dokploy rollout in `DOKPLOY-STEPS.md`.

## C. Checklist of evidence to keep from this stage
- `tests` output 6/6 OK.
- CLI `steps` output with all 12 planes.
- `provisioned/canary/manifest.json` listing all generated artifacts.
- `git status` in `..\zetris-views` empty (his repo untouched).

## D. What I will build next after your go-ahead (order)
1. Live step implementations in `control/steps.py` (Keycloak/Postgres/Docker/Caddy)
   with `--apply` requiring an explicit confirmation token — never default.
2. Public signup UI + quota middleware (free = 10 users).
3. Tenant self-service pages (users, apps, toggles, client download).
4. Lifecycle actions (suspend/resume/delete) and full acceptance test suite.
5. Only then: final Dokploy steps with your credentials entered by you.
