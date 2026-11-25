# DOKPLOY STEPS — you execute; I never touch the server or read secrets

Status (Nov 25): the control-plane module now has a **Dockerfile**,
**`docker-compose.control-plane.yml`**, operator auth, real user invites, real
add-app, real toggles, and a guarded apply path. The first deploy should be
**preview mode** (`ZTCP_APPLY=false`), then one reviewed apply rehearsal.

---

## 0. Confirmed environment (from the user, Nov 25)

1. **Domain:** `ztna.sc.deeptrustxai.com`. Wildcard DNS confirmed: a random
   `test123.ztna.sc.deeptrustxai.com` resolves to `200.97.163.244`.
2. **Traefik network:** moving with `dokploy-network` (lead compose default).
3. **Container prefix:** `ztna-zetrissinglenode-fcrups-`.
   - keycloak: `ztna-zetrissinglenode-fcrups-keycloak-1`
   - postgres: `ztna-zetrissinglenode-fcrups-postgres-1`
   - clickhouse: `ztna-zetrissinglenode-fcrups-clickhouse-1`
   - redis: `ztna-zetrissinglenode-fcrups-redis-1`
   - edge: `ztna-zetrissinglenode-fcrups-edge-1`
   - volumes/networks derived from the same project prefix.
4. **Admin usernames (names only):** PostgreSQL `admin`, ClickHouse `default`,
   Keycloak admin `admin` (from the lead's tracked compose defaults).
5. **Docker socket:** our compose already contains the bind mount. Confirm with
   `ls -l /var/run/docker.sock` in Dokploy's server terminal.
6. **Git remote:** needed only at final push time. Push only to your own fork.

### Important live-state warning
The live stack currently has `WRITE_SCORES=true` and `BLOCK_ON_CRITICAL=true`
(shared risk engine in enforcement mode), plus
`COMPOSE_PROFILES=host-sensor,mesh-pilot,risk-demo`. Before live apply, decide
explicitly whether new free tenants inherit this enforcement or must be forced
to shadow. Do not flip anything silently.

---

## 1. Push the code (me, after you confirm the remote)
- Only your own repo/fork, never the lead's repo.
- The module is self-contained: `vendor/` contains the read-only renderers.
- `.dockerignore` excludes generated keys/state/test temp folders.

## 2. DNS / TLS (you)
- Add `A` record: `*.ztna.sc.deeptrustxai.com → <Dokploy server IP>` (or your domain).
- Traefik must be configured for wildcard Let's Encrypt (DNS-01). If wildcard
  certificates are not available, create explicit records per tenant at signup.

## 3. Create the Dokploy service (you)
1. In your Dokploy project → **Create Service → Compose**.
2. Source: your repo, branch, compose file **`docker-compose.control-plane.yml`**.
3. In the service's **Environment** tab enter ONLY values (never share them):
   - `ZTCP_OPERATOR_TOKEN` — random 16+ chars; used to sign into the dashboard.
   - `ZTCP_PUBLIC_HOST` — e.g. `portal.ztna.sc.deeptrustxai.com`.
   - `ZTCP_DOMAIN` — e.g. `ztna.sc.deeptrustxai.com`.
   - `ZTCP_TRAEFIK_NETWORK` — answer from section 0 (default `dokploy-network`).
   - `ZTCP_EDGE_HOST` — the edge container/service name from section 0
     (default `zetris-single-node-edge-1`); it is the shared router on ports
     8081/8082/8083.
   - `ZTCP_GATEWAY_CONTAINER` and `ZTCP_ROUTE_VOLUME` — can stay at their
     defaults; they are created by this compose as `tenant-gateway`.
   - `PGPASSWORD`, `ZTCP_KEYCLOAK_ADMIN_PASSWORD`, `ZTCP_CH_ADMIN_PASSWORD`,
     `ZTCP_REDIS_ADMIN_PASSWORD`, `ZTCP_ADMIN_TOKEN` — shared-service secrets.
   - Keep `ZTCP_APPLY=false` for the first deployment.
4. Deploy. Health check target: `http://127.0.0.1:8788/healthz`.
5. Open `https://portal.<domain>` → sign in with `ZTCP_OPERATOR_TOKEN`.

## 4. First canary tenant (you)
1. On the public page, create `canary` with a test email, free tier.
2. Watch the real progress counters and pipeline stages. All operations are
   planned (preview), so no live containers change.
3. Try the new forms:
   - **Invite a user** → returns a one-time password (preview stub).
   - **Add a protected app** → renders a per-tenant Rego policy and route snippet.
4. Confirm Stop/Start/Backup/Client key/Rotate/Delete are all previewed.

## 5. Apply rehearsal (together, after review)
1. We review the planned operations for one canary.
2. You set `ZTCP_APPLY=true` and a `ZTCP_CONFIRM` token of 16+ chars in Dokploy.
3. Redeploy, create a second canary, and watch the 12 real steps.
4. Acceptance: three doors answer; first login promotes admin; cross-tenant
   tokens/DB/peers deny; `/explorer` shows only that tenant's rows; suspend/resume
   leaves the other tenant available.

## 6. Rollback
- Set `ZTCP_APPLY=false` and redeploy, or stop the service.
- Never delete volumes before backing up registry + tenant DBs.
- The lead's live project is never touched.

## 7. Status of build items 1–3
- ✅ Dokploy package: `Dockerfile`, `docker-compose.control-plane.yml`, healthz,
  persistent volumes, operator auth, TLS via Traefik labels.
- ✅ Real invites: Keycloak user creation + realm/client role assignment (apply mode).
- ✅ Real add-app: per-tenant applications document, policy re-render, route snippet.
- ✅ Feature toggles reconcile into the tenant audit compose.
- ✅ Tenant-facing portal: one-time handoff page + per-tenant management console
  (users, apps, NetBird setup key, feature toggles).
- ✅ Role-aware entry page at `/`: platform operators vs customer organizations,
  similar to ZeroTier's two-door model. Operator console at `/operator`.
- ⏳ Live execution and live acceptance still require the Dokploy environment.
