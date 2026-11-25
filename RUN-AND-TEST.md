# RUN & TEST — local, then Dokploy

This is the handover runbook. Everything below is either a **basic command**
(you can run it as-is) or a **high-level command** (marked; run it yourself —
I will not run Docker or touch the server without your go-ahead).

**Golden rules:** do not open `.env`; enter secrets only in Dokploy's UI; no
command here reads a secret file. All generated preview keys are throwaway.

---

## 0. What is finished (local build)
- Registry + free/paid tier walls (10 users / 1 app).
- 12-step orchestrator (Keycloak → Postgres → NetBird → app gateway/connector →
  policy → audit → routes → verify → handoff). Preview by default; guarded apply.
- Signup + operator UI with tenant status, users/apps/feature endpoints.
- Lifecycle: suspend / resume / backup / guarded delete.
- NetBird CE client onboarding: one-time setup key + official download link.
- Secret rotation (service APIs; no `.env`; one-time 0600 file for Dokploy values).
- One-time handoff page: credentials shown once, then burned.
- Acceptance harness: 17 checks (16 structural pass locally, 1 live stage).
- Security-console UI: black/green glassmorphism theme, all live values sourced
  from the real backend (`/api/state` + `/api/tenants`): server time, persisted
  tenant statuses, user/app counts, real provisioning step records (pipeline
  counters + per-tenant progress bars), and 5-per-page navigation. No dummy
  signals, fake logs, or synthetic measurements. The whole page fits one screen.
  JavaScript is served as `/app.js` (strict CSP compatible — inline scripts were
  blocked before, so the buttons now actually work in the browser).

Verified: **19/19 unit tests**, **17/17 structural acceptance**, all 12 steps
preview OK, all lifecycle commands preview OK, lead's repo untouched.

---

## 1. Basic commands — run these now (no Docker, no secrets)

Open PowerShell in `C:\Users\pragy\opencode_IITM_multiten_test\tenant-control-plane`.

```powershell
# 1. Full test suite — expect "Ran 19 tests ... OK"
python -B -m unittest discover -s tests -v

# 2. Registry validation — expect "Valid registry: 1 tenant(s); tiers: free"
python -B -m control.cli validate

# 3. All 12 steps in preview — every record "status": "ok"
python -B -m control.cli run --tenant canary

# 4. Render all five planes — expect netbird=5, policy=1, audit=5, gateway=5, connector=7
python -B -m control.cli render --tenant canary --out provisioned

# 5. Lifecycle previews — expect "planned_operations" > 0 in each result
python -B -m control.cli suspend --tenant canary
python -B -m control.cli resume --tenant canary
python -B -m control.cli backup --tenant canary
python -B -m control.cli client --tenant canary
python -B -m control.cli delete --tenant canary   # deletion PLANNED; nothing removed

# 6. Secret rotation preview — expect env_vars_to_update + manual_followups, NO values
python -B -m control.cli rotate --tenant canary

# 7. Structural acceptance (two tenants) — expect "passed": 17, "failed": 0
python -B -m control.cli render --registry config/registry.acceptance.json --tenant canary --out provisioned
python -B -m control.cli render --registry config/registry.acceptance.json --tenant other --out provisioned
python -B -m control.cli acceptance --registry config/registry.acceptance.json --tenant-a canary --tenant-b other

# 8. Confirm delete-preview did not remove anything — expect True
Test-Path provisioned\canary\netbird\compose.json
```

If any of these fail, send me the **first failing line only** — never paste a
credential, even though none should appear.

---

## 2. High-level local commands — YOU run these (Docker only, no real credentials)

```powershell
cd C:\Users\pragy\opencode_IITM_multiten_test\tenant-control-plane

# Parse check (writes nothing)
docker compose -f docker-compose.preview.yml config --quiet

# Step engine inside the container, preview only
docker compose -f docker-compose.preview.yml run --rm preview run --tenant canary

# Start the UI locally
docker compose -f docker-compose.preview.yml up -d web
```

Then open `http://127.0.0.1:8788/` in your browser — role-aware entry page:
platform operator sign-in on the left, customer organization on the right.
The operator console is at `/operator`.

---

## 3. Browser test (10 minutes)

0. **Operator auth:** local preview has no token, so `/api/me` returns
   `{"authenticated":true}`. On Dokploy, sign in with `ZTCP_OPERATOR_TOKEN`
   through the login overlay.
1. **Health:** `http://127.0.0.1:8788/healthz` → `{"ok": true}`.
2. **Signup:** enter slug `acme`, email `admin@acme.test`, tier **free** → Create.
3. **Progress:** the tenant row moves `queued → provisioning → ready`; step list
   shows database → audit_data → identity → netbird_stack → netbird_bootstrap →
   access_gateway → access_connector → policy → audit_stack → routes → verify → handoff.
   Everything is **preview** — no live container is created.
4. **Tier walls:** use the API (from PowerShell):
   ```powershell
   1..10 | ForEach-Object { Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8788/api/tenants/acme/users -ContentType application/json -Body '{"email":"user@example.com"}' }
   ```
   The 10th invite must fail with HTTP 403 ("user limit reached"). Apps: the
   second app must fail (free = 1 app). `risk_writes` toggle must be 403 on free.
5. **Real forms:** use **Invite a user** (email + role) — returns a one-time
   password and creates a real Keycloak user in apply mode; use **Add a
   protected app** — appends to the tenant's application document, re-renders
   `<tenant>.rego`, and generates a route snippet.
 6. **Lifecycle buttons:** Stop → status `suspended`; Start → `ready`; Backup,
   Client key (shows `PREVIEW_ONLY`), Rotate (shows env var names, no values).
6. **Delete:** click Delete → status `deleted`, but `provisioned\acme\` still exists.
7. **One-time handoff:** the handoff token is in
   `provisioned\<tenant>\handoff.json` (token + URLs only, no password). Extract it
   in PowerShell from this folder with:
   ```powershell
   $h = Get-Content provisioned\<tenant>\handoff.json -Raw | ConvertFrom-Json
   $h.one_time_token
   ```
   Open `handoff_url` from that file in the browser. It shows a one-time page with
   the admin email, one-time password, and three tenant door cards. Click **Open
   management console** to reach the tenant-facing portal at
   `/tenant/<tenant>?session=<session>`. There the tenant admin can invite users,
   add apps, issue a NetBird client key, and change feature toggles. The handoff
   token can be consumed only once — a second attempt returns 404.

---

## 4. Full acceptance matrix (what "tested" means)

| # | Check | Local proof | Dokploy proof (later) |
| --- | --- | --- | --- |
| 1 | Signup creates tenant | UI + test | browser signup |
| 2 | Tier walls 10 users / 1 app | HTTP tests | repeat in deployed UI |
| 3 | Registry validation | CLI validate | CLI inside container |
| 4 | Five planes rendered | render CLI | container artifacts |
| 5 | Ready before first login | preview steps | doors answer before login |
| 6 | Admin role after login | step present | first SSO login → admin |
| 7 | Default-deny ACL | step present | NetBird policies + cross ping |
| 8 | Peer attach (ZeroTier-like) | setup-key test | real client `netbird status` |
| 9 | Cross-tenant isolation | structural 17/17 | 401/404/denied live |
| 10 | Protected app | per-tenant host | login → 200, foreign → 403 |
| 11 | Add app via form | app doc test | new policy served |
| 12 | Audit + Explorer | audit compose | `/explorer` rows/details/CSV |
| 13 | Telemetry scoping | vector sink test | ClickHouse tenant rows |
| 14 | Feature toggles | tier tests | per-tenant change only |
| 15 | Lifecycle | preview commands | stop/start/delete live |
| 16 | Secret hygiene | grep tests | no values in logs |
| 17 | Live doors | manual stage | curl probes |

---

## 5. After the local test → Dokploy

1. Stop the local UI: `docker compose -f docker-compose.preview.yml down`.
2. Read `DOKPLOY-STEPS.md` sections 1–3 exactly. First deployment stays in
   **preview mode** (no live service changes).
3. Create one canary tenant in the deployed UI, confirm all 12 steps, then we
   will do one together-reviewed apply rehearsal with your credentials entered
   by you in Dokploy's Environment tab.

---

## 6. Troubleshooting quick map

| Symptom | Meaning / action |
| --- | --- |
| Test failure | send me the first failing line only |
| `invalid choice: config/...` | `--registry` goes AFTER the subcommand |
| UI shows no tenants | service worker needs a second; refresh in 2 s |
| `PREVIEW_ONLY` client key | correct — no live key in preview mode |
| Delete shows `deletion planned` | correct — apply requires `--apply --confirm` |
| Secret values anywhere in output | stop and tell me immediately |
