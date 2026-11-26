#!/usr/bin/env python3
"""Public signup + operator UI for tenant-control-plane.

Default mode is PREVIEW: jobs record intended operations and never touch live
services. Live mode requires --apply --confirm <token> at startup and secrets
supplied as environment variables (never from a file). No password is stored.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
import re
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import secrets
import sqlite3
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))

from control import registry as reg      # noqa: E402
from control import render as rnd        # noqa: E402
from control import steps as stp         # noqa: E402
from control import lifecycle as life    # noqa: E402
from control import client as cli_client  # noqa: E402
from control import secrets as sec        # noqa: E402
from control import users as usr          # noqa: E402
from control import apps as appctl        # noqa: E402
from control import toggles as tog        # noqa: E402
from control import tokens as tenant_tokens  # noqa: E402

STATE = ROOT / "state"
REGISTRY = ROOT / "config/registry.local.json"
CONFIG = ROOT / "config/portal.example.json"


def load_config():
    """Non-secret config from the mounted example file, overridable by env.

    Only variable NAMES for secrets are read here — never secret values.
    """
    config = json.loads(Path(os.environ.get("ZTCP_CONFIG", str(CONFIG))).read_text(encoding="utf-8"))
    mapping = {
        "ZTCP_KEYCLOAK_ORIGIN": ("keycloak", "origin"),
        "ZTCP_KEYCLOAK_ADMIN_REALM": ("keycloak", "admin_realm"),
        "ZTCP_KEYCLOAK_ADMIN_USER": ("keycloak", "admin_user"),
        "ZTCP_KEYCLOAK_PASSWORD_ENV": ("keycloak", "admin_password_env"),
        "ZTCP_POSTGRES_HOST": ("postgres", "host"),
        "ZTCP_POSTGRES_CONTAINER_HOST": ("postgres", "container_host"),
        "ZTCP_POSTGRES_PORT": ("postgres", "port"),
        "ZTCP_POSTGRES_ADMIN_USER": ("postgres", "admin_user"),
        "ZTCP_POSTGRES_PASSWORD_ENV": ("postgres", "password_env"),
        "ZTCP_POSTGRES_HBA_FILE": ("postgres", "managed_hba_file"),
        "ZTCP_POSTGRES_BASE_HBA_FILE": ("postgres", "base_hba_file"),
        "ZTCP_CLICKHOUSE_ORIGIN": ("clickhouse", "origin"),
        "ZTCP_CLICKHOUSE_ADMIN_USER": ("clickhouse", "admin_user"),
        "ZTCP_CLICKHOUSE_PASSWORD_ENV": ("clickhouse", "password_env"),
        "ZTCP_REDIS_HOST": ("redis", "host"),
        "ZTCP_REDIS_PORT": ("redis", "port"),
        "ZTCP_REDIS_PASSWORD_ENV": ("redis", "password_env"),
        "ZTCP_CADDY_CONTAINER": ("caddy", "container"),
        "ZTCP_CADDY_SNIPPETS": ("caddy", "snippets_dir"),
        "ZTCP_CADDY_UPSTREAM": ("caddy", "upstream_host"),
        "ZTCP_DATABASE_NETWORK": ("database_network", None),
        "ZTCP_API_NETWORK": ("api_network", None),
        "ZTCP_BACKEND_NETWORK": ("backend_network", None),
        "ZTCP_POLICY_VOLUME": ("policy_volume", None),
        "ZTCP_GATEWAY_IP": ("gateway_ip", None),
        "ZTCP_EDGE_HOST": ("edge_host", None),
        "ZTCP_ROUTE_VOLUME": ("route_volume", None),
        "ZTCP_GATEWAY_CONTAINER": ("gateway_container", None),
        "ZTCP_CA_FILE": ("ca_file", None),
        "ZTCP_NETBIRD_TOKEN_ENV": ("netbird", "admin_token_env"),
        "ZTCP_PORTAL_BASE_URL": ("portal_base_url", None),
    }
    for env_name, (section, key) in mapping.items():
        value = os.environ.get(env_name)
        if not value:
            continue
        if key is None:
            config[section] = value
        else:
            config.setdefault(section, {})[key] = value
    if isinstance(config.get("postgres", {}).get("port"), str):
        config["postgres"]["port"] = int(config["postgres"]["port"])
    if isinstance(config.get("redis", {}).get("port"), str):
        config["redis"]["port"] = int(config["redis"]["port"])
    if "ZTCP_LAB" in os.environ:
        config["lab"] = os.environ["ZTCP_LAB"].lower() in ("1", "true", "yes")
    else:
        config["lab"] = config.get("lab", False)
    config["scripts_root"] = str(reg.ZETRIS_DEFAULT)
    return config


class Store:
    def __init__(self):
        STATE.mkdir(mode=0o700, exist_ok=True)
        self.path = STATE / "portal.sqlite3"
        with self.connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS tenants (
                slug TEXT PRIMARY KEY, tier TEXT, email TEXT, status TEXT,
                records TEXT, features TEXT, apps INTEGER, users INTEGER,
                created REAL, updated REAL)""")
            columns = {row[1] for row in conn.execute("PRAGMA table_info(tenants)")}
            if "updated" not in columns:
                conn.execute("ALTER TABLE tenants ADD COLUMN updated REAL")
                conn.execute("UPDATE tenants SET updated=created")
            conn.execute("""CREATE TABLE IF NOT EXISTS tenant_users (
                slug TEXT, email TEXT, role TEXT, status TEXT, created REAL,
                PRIMARY KEY(slug,email))""")
            conn.execute("""CREATE TABLE IF NOT EXISTS tenant_apps (
                slug TEXT, app_id TEXT, host TEXT, groups TEXT, status TEXT, created REAL,
                PRIMARY KEY(slug,app_id))""")
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def add(self, slug, tier, email):
        with self.connect() as conn:
            conn.execute("INSERT OR IGNORE INTO tenants VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (slug, tier, email, "queued", "[]", "{}", 0, 1, time.time(), time.time()))

    def get(self, slug):
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM tenants WHERE slug=?", (slug,)).fetchone()
        if row is None:
            raise KeyError(slug)
        return dict(row)

    def update(self, slug, **fields):
        with self.connect() as conn:
            for key, value in fields.items():
                conn.execute(f"UPDATE tenants SET {key}=?, updated=? WHERE slug=?",
                             (json.dumps(value) if isinstance(value, (dict, list)) else value,
                              time.time(), slug))

    def all(self):
        with self.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM tenants ORDER BY created")]


class Service:
    def __init__(self, apply=False, confirm="", operator_token=""):
        self.store = Store()
        self.apply, self.confirm = apply, confirm
        self.operator_token = operator_token
        self.pending = {}      # slug -> one-time admin password (memory only)
        self.handoffs = {}     # token -> payload, removed after first view
        self.tenant_sessions = {}  # session token -> (slug, created)
        self.wake = threading.Event()
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.loop, daemon=True, name="tenant-provisioner")

    def start(self):
        self.worker.start()

    def close(self):
        self.stop.set()
        self.wake.set()
        if self.worker.ident is not None:
            self.worker.join(timeout=10)

    def submit(self, slug, tier, email, password):
        """Password is used in memory only and never persisted."""
        self.store.add(slug, tier, email)
        self.store.update(slug, features=dict(reg.TIERS[tier]["features"]))
        self.pending[slug] = password
        self.wake.set()

    def context(self, slug, admin_password=None):
        """Build a Context for one tenant (preview or explicit apply mode)."""
        tenants, ext = reg.validate(REGISTRY)
        tenant = next(t for t in tenants if t["id"] == slug)
        config = load_config()
        out = ROOT / "provisioned" / slug
        if not (out / "netbird/compose.json").is_file():
            rnd.render_all(tenant, ext[slug], out=out, features=ext[slug]["features"])
        config["ca_file"] = str(out / "lab-ca/ca.crt")
        config["scripts_root"] = str(reg.ZETRIS_DEFAULT)
        if self.apply:
            secrets_map = {name: os.environ.get(name, "") for name in tenant["secret_refs"].values()}
            for section in ("keycloak", "postgres", "clickhouse", "redis", "netbird"):
                name = config.get(section, {}).get("password_env") or config.get(section, {}).get("admin_token_env")
                if name:
                    secrets_map[name] = os.environ.get(name, "")
            admin_token_env = config.get("netbird", {}).get("admin_token_env", "ZTCP_ADMIN_TOKEN")
            stored = tenant_tokens.load(slug)
            if stored:
                secrets_map[admin_token_env] = stored
            mode, token = "apply", self.confirm
        else:
            secrets_map = rnd.ephemeral_environ(tenant)
            mode, token = "preview", ""
        return stp.Context(tenant=tenant, ext=ext[slug], config=config,
                           secrets=secrets_map, out_dir=out,
                           runner=stp.Runner(mode=mode, apply_token=token),
                           admin_password=admin_password or secrets.token_urlsafe(24))

    def loop(self):
        while not self.stop.is_set():
            for row in self.store.all():
                if row["status"] != "queued":
                    continue
                self.store.update(row["slug"], status="provisioning")
                try:
                    ctx = self.context(row["slug"], self.pending.get(row["slug"]))
                    records = stp.run_all(ctx)
                    self.store.update(row["slug"], status="ready", records=records)
                    handoff_file = ROOT / "provisioned" / row["slug"] / "handoff.json"
                    token = (json.loads(handoff_file.read_text(encoding="utf-8"))["one_time_token"]
                             if handoff_file.is_file() else secrets.token_urlsafe(24))
                    self.handoffs[token] = {
                        "tenant": row["slug"],
                        "urls": {"app": "https://" + ctx.tenant["application_host"],
                                 "audit": "https://" + ctx.tenant["audit_hostname"],
                                 "netbird": ctx.origin},
                        "administrator": ctx.ext["admin_email"],
                        "admin_password": self.pending.pop(row["slug"], "<generated during apply>"),
                    }
                except Exception as error:
                    self.store.update(row["slug"], status="failed",
                                      records=[{"step": "job", "status": "failed",
                                                "detail": type(error).__name__ + "; details withheld"}])
            self.wake.wait(2)
            self.wake.clear()

    def counts(self, slug):
        with self.store.connect() as conn:
            users = conn.execute("SELECT count(*) FROM tenant_users WHERE slug=?", (slug,)).fetchone()[0]
            apps = conn.execute("SELECT count(*) FROM tenant_apps WHERE slug=?", (slug,)).fetchone()[0]
        return users, apps

    def public(self, row):
        users, apps = self.counts(row["slug"])
        return {"slug": row["slug"], "tier": row["tier"], "email": row["email"],
                "status": row["status"], "records": json.loads(row["records"]),
                "features": json.loads(row["features"]), "apps": apps,
                "users": users, "updated": row["updated"],
                "user_limit": reg.TIERS[row["tier"]]["max_users"],
                "app_limit": reg.TIERS[row["tier"]]["max_apps"]}

    def handoff_for(self, slug):
        """Return the one-time handoff URL for a tenant, if still available."""
        for token, payload in self.handoffs.items():
            if payload.get("tenant") == slug:
                return payload.get("handoff_url") or ("/handoff/" + slug + "?token=" + token)
        path = ROOT / "provisioned" / slug / "handoff.json"
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data.get("handoff_url")
        return None

    def state(self):
        """Aggregate REAL persisted backend state — no synthetic measurements."""
        rows = [self.public(row) for row in self.store.all()]
        pipeline = {}
        for row in rows:
            for record in row["records"]:
                stage = record.get("step", "unknown")
                status = record.get("status", "unknown")
                slot = pipeline.setdefault(stage, {"ok": 0, "failed": 0, "skipped": 0})
                if status in slot:
                    slot[status] += 1
        return {
            "server_time": time.time(),
            "mode": "apply" if self.apply else "preview",
            "tiers": {tier: sum(1 for row in rows if row["tier"] == tier) for tier in reg.TIERS},
            "statuses": {status: sum(1 for row in rows if row["status"] == status)
                         for status in ("queued", "provisioning", "ready", "suspended", "failed", "deleted")},
            "users": sum(row["users"] for row in rows),
            "apps": sum(row["apps"] for row in rows),
            "pipeline": pipeline,
            "last_change": max((row["updated"] for row in rows), default=0),
            "tenants": len(rows),
        }


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#020604"><title>Zetris · Security Control Plane</title><style>
:root{--glass:rgba(4,22,13,.68);--glass-2:rgba(8,38,22,.62);--stroke:rgba(52,211,153,.22);
--stroke-2:rgba(52,211,153,.45);--ink:#d9ffe8;--muted:#6ba887;--green:#34d399;--green-2:#22c55e;
--lime:#a3e635;--danger:#fb7185;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
html,body{min-height:100%}
body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink);
background:#020604;overflow-x:hidden}
.bg{position:fixed;inset:0;z-index:-2;background:
 radial-gradient(55% 50% at 10% 0%,rgba(16,185,129,.20),transparent 62%),
 radial-gradient(45% 45% at 92% 12%,rgba(34,197,94,.14),transparent 60%),
 radial-gradient(60% 60% at 60% 100%,rgba(5,150,105,.16),transparent 62%),
 linear-gradient(165deg,#020604,#04120c 55%,#010604)}
.bg:after{content:"";position:absolute;inset:-30%;background:
 conic-gradient(from 180deg at 50% 50%,transparent,rgba(52,211,153,.13),transparent,rgba(163,230,53,.06),transparent);
 filter:blur(80px);animation:spin 40s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.grid{position:fixed;inset:0;z-index:-1;opacity:.32;
background-image:linear-gradient(rgba(52,211,153,.075) 1px,transparent 1px),linear-gradient(90deg,rgba(52,211,153,.075) 1px,transparent 1px);
background-size:46px 46px;mask-image:linear-gradient(to bottom,#000,transparent 85%)}
.scan{position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:.22;
background:repeating-linear-gradient(0deg,transparent 0 3px,rgba(52,211,153,.07) 4px 5px);
animation:scan 9s linear infinite}
@keyframes scan{to{background-position:0 460px}}
/* Cursor-following ambient glow — decoration only, no data meaning */
.glow{position:fixed;width:680px;height:680px;border-radius:50%;z-index:-1;pointer-events:none;
background:radial-gradient(circle,rgba(52,211,153,.13),rgba(163,230,53,.04) 45%,transparent 70%);
transform:translate(calc(var(--mx,50vw) - 50%),calc(var(--my,50vh) - 50%));
transition:transform .16s ease-out;will-change:transform}
.wrap{max-width:1160px;margin:auto;padding:38px 26px 70px}
.glass{background:linear-gradient(145deg,var(--glass-2),var(--glass));border:1px solid var(--stroke);
border-radius:20px;backdrop-filter:blur(24px) saturate(140%);-webkit-backdrop-filter:blur(24px) saturate(140%);
box-shadow:0 20px 65px rgba(0,0,0,.6),inset 0 1px 0 rgba(52,211,153,.10)}
.top{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:18px 24px;margin-bottom:20px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:13px}
.mark{width:44px;height:44px;border-radius:13px;display:grid;place-items:center;font-weight:800;font-size:22px;
font-family:var(--mono);background:linear-gradient(140deg,var(--lime),var(--green));color:#02160d;
box-shadow:0 0 26px rgba(52,211,153,.35)}
h1{font-size:19px;letter-spacing:-.01em;margin:0;font-weight:650}
.sub{color:var(--muted);font-size:11px;margin:3px 0 0;font-family:var(--mono);letter-spacing:.03em}
.right{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.clock{font-family:var(--mono);font-size:12px;color:var(--green);letter-spacing:.06em}
.pill{display:inline-flex;align-items:center;gap:8px;font-family:var(--mono);font-size:10px;font-weight:700;
letter-spacing:.12em;text-transform:uppercase;padding:9px 13px;border-radius:999px;
border:1px solid var(--stroke-2);background:rgba(52,211,153,.09);color:var(--green)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--lime);box-shadow:0 0 12px var(--lime);animation:pulse 1.8s infinite}
@keyframes pulse{50%{opacity:.35;transform:scale(.75)}}
.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}
@media(max-width:700px){.metrics{grid-template-columns:1fr}}
.metric{padding:18px 20px;position:relative;overflow:hidden}
.metric:after{content:"";position:absolute;right:-28px;top:-28px;width:110px;height:110px;border-radius:50%;
background:radial-gradient(circle,rgba(52,211,153,.16),transparent 68%)}
.metric .k{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.metric .v{font-family:var(--mono);font-size:32px;font-weight:700;color:var(--green);margin-top:6px;
text-shadow:0 0 22px rgba(52,211,153,.45)}
.metric .v small{font-size:12px;color:var(--muted);font-weight:500;text-shadow:none}
.grid2{display:grid;grid-template-columns:minmax(300px,370px) 1fr;gap:20px;align-items:start}
.grid3{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px;align-items:start}
@media(max-width:900px){.grid2,.grid3{grid-template-columns:1fr}}
.panel{padding:24px}
h2{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--green);
margin:0 0 18px;font-weight:700;display:flex;align-items:center;gap:9px}
h2:before{content:"";width:7px;height:7px;background:var(--lime);box-shadow:0 0 9px var(--lime);border-radius:2px;transform:rotate(45deg)}
label{display:block;font-size:11px;font-family:var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:15px 0 7px}
input,select{width:100%;font:inherit;font-size:14px;color:var(--ink);padding:12px 14px;border-radius:11px;
border:1px solid var(--stroke);background:rgba(1,10,6,.66);outline:none;transition:.2s}
input:focus,select:focus{border-color:var(--green);box-shadow:0 0 0 3px rgba(52,211,153,.14)}
option{background:#04140c}
button{font:inherit;font-size:11px;font-weight:650;font-family:var(--mono);letter-spacing:.03em;cursor:pointer;color:var(--ink);
padding:9px 12px;border-radius:10px;border:1px solid var(--stroke);background:rgba(52,211,153,.06);transition:.18s;white-space:nowrap}
button:hover{background:rgba(52,211,153,.16);transform:translateY(-1px);border-color:var(--stroke-2);box-shadow:0 4px 14px rgba(52,211,153,.12)}
button.primary{width:100%;margin-top:22px;padding:13px;font-size:13px;color:#02160d;border:none;
background:linear-gradient(120deg,var(--lime),var(--green));box-shadow:0 10px 28px rgba(52,211,153,.24)}
button.warn{color:#ffd9df;border-color:rgba(251,113,133,.4)}
button.warn:hover{background:rgba(251,113,133,.16)}
.note{font-size:11px;color:var(--muted);line-height:1.65;margin:16px 0 0;font-family:var(--mono)}
.tierbar{display:flex;gap:7px;margin-top:16px;flex-wrap:wrap}
.chip{font-family:var(--mono);font-size:10px;padding:6px 9px;border-radius:999px;background:rgba(52,211,153,.07);
border:1px solid var(--stroke);color:var(--muted)}
#msg{min-height:18px;font-size:11px;font-family:var(--mono);color:var(--lime);margin:12px 2px 0;word-break:break-word}
.tablewrap{overflow-x:auto;margin:0 -10px;padding:0 10px}
table{width:100%;border-collapse:separate;border-spacing:0 8px;font-size:12px}
th{text-align:left;font-family:var(--mono);font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);padding:0 12px 6px}
td{padding:12px;background:rgba(52,211,153,.045);border-top:1px solid var(--stroke);border-bottom:1px solid var(--stroke);vertical-align:middle}
td:first-child{border-left:1px solid var(--stroke);border-radius:11px 0 0 11px}
td:last-child{border-right:1px solid var(--stroke);border-radius:0 11px 11px 0}
tr:hover td{background:rgba(52,211,153,.09)}
.svc{font-family:var(--mono);font-weight:700;font-size:13px;color:var(--green)}
.badge{display:inline-block;font-family:var(--mono);font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:5px 9px;border-radius:999px}
.b-ready{background:rgba(52,211,153,.16);color:var(--lime)}
.b-other{background:rgba(96,165,250,.14);color:#93c5fd}
.b-failed{background:rgba(251,113,133,.18);color:var(--danger)}
.steps{color:var(--muted);font-size:10px;font-family:var(--mono);line-height:1.5;max-width:220px}
.prog{height:3px;background:rgba(52,211,153,.13);border-radius:3px;margin-top:7px;overflow:hidden}
.prog i{display:block;height:100%;background:linear-gradient(90deg,var(--green),var(--lime));box-shadow:0 0 8px var(--green);
transition:width .6s ease;width:0}
.act{display:flex;gap:5px;flex-wrap:wrap;max-width:330px}
.act button{padding:6px 8px;font-size:9px}
/* REAL backend state — no synthetic signals or logs */
.statebar{display:flex;align-items:center;gap:20px;flex-wrap:wrap;margin-top:18px;padding-top:16px;
border-top:1px solid var(--stroke)}
.statebar .fact{font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:.05em}
.statebar .fact b{color:var(--lime);font-size:12px;margin-left:5px}
.pipeline{display:flex;gap:5px;flex:1;min-width:260px;align-items:center;flex-wrap:wrap}
.pipe{font-family:var(--mono);font-size:9px;padding:5px 8px;border-radius:7px;border:1px solid var(--stroke);
background:rgba(52,211,153,.05);color:var(--muted);white-space:nowrap}
.pipe b{color:var(--green);font-weight:700}
.pipe.zero{opacity:.45}
.pager{display:flex;align-items:center;justify-content:flex-end;gap:8px;margin-top:10px;
font-family:var(--mono);font-size:10px;color:var(--muted)}
.pager button{padding:4px 9px;font-size:10px}
.empty{color:var(--muted);font-family:var(--mono);font-size:10px}
/* single screen: everything visible without page scrolling */
html,body{height:100%;overflow:hidden}
.wrap{height:100dvh;display:flex;flex-direction:column;padding:12px 26px 10px;gap:9px}
.glass{flex-shrink:0}
.top{padding:11px 20px;margin-bottom:0}
.metrics{margin-bottom:0;gap:12px}
.metric{padding:11px 15px}
.metric .v{font-size:25px;margin-top:2px}
.grid2{flex:1;min-height:0;gap:14px;align-items:stretch}
.panel{padding:15px 18px;display:flex;flex-direction:column;min-height:0;overflow:hidden}
h2{margin-bottom:10px;font-size:10px}
label{margin:8px 0 4px;font-size:10px}
input,select{padding:9px 11px;font-size:13px}
button.primary{margin-top:12px;padding:10px;font-size:12px}
#msg{min-height:14px;margin:7px 0 0;font-size:10px}
.tierbar{margin-top:8px}
.chip{padding:4px 7px;font-size:9px}
.note{font-size:9px;line-height:1.35;margin-top:7px}
th{padding:0 8px 4px}
td{padding:8px}
.tablewrap{flex:1;min-height:0;overflow:hidden;margin:0;padding:0}
.foot{flex-shrink:0;text-align:center;color:var(--muted);font-family:var(--mono);font-size:9px;letter-spacing:.08em}
details.mini{margin-top:8px;border-top:1px solid var(--stroke);padding-top:7px}
details.mini summary{cursor:pointer;font-family:var(--mono);font-size:10px;color:var(--green);letter-spacing:.08em;text-transform:uppercase}
details.mini input,details.mini select{margin-top:5px;padding:6px 8px;font-size:11px}
details.mini button{margin-top:6px;padding:6px 9px;font-size:10px;width:100%}
.login{position:fixed;inset:0;z-index:20;display:grid;place-items:center;background:rgba(1,6,4,.86);backdrop-filter:blur(8px)}
.login[hidden]{display:none}
.login form{width:min(340px,90vw);padding:24px}
.statebar{margin-top:9px;padding-top:9px;gap:14px}
.pager{margin-top:5px}
@media(max-height:820px){.note{display:none}.metrics .metric .v{font-size:22px}}
</style></head><body>
<div class="bg"></div><div class="grid"></div><div class="scan"></div><div class="glow"></div>
<div class="wrap">
 <header class="glass top">
  <div class="brand"><div class="mark">Z</div><div><h1>Zetris Security Control Plane</h1><p class="sub">tenant provisioning · zero-trust network access</p></div></div>
  <div class="right"><div class="clock" id="clock">—</div><div class="pill"><span class="dot"></span> Live · preview</div></div>
 </header>
 <section class="metrics" id="metrics">
  <div class="glass metric"><div class="k">Total tenants</div><div class="v" id="m-total">0 <small>active</small></div></div>
  <div class="glass metric"><div class="k">Provisioning</div><div class="v" id="m-provisioning">0 <small>in progress</small></div></div>
  <div class="glass metric"><div class="k">Ready</div><div class="v" id="m-ready">0 <small>operational</small></div></div>
 </section>
 <div class="grid2">
  <section class="glass panel">
   <h2>Create a tenant</h2>
   <form id="f">
    <label for="slug">Customer ID</label><input id="slug" required pattern="[a-z][a-z0-9-]*" placeholder="acme" autocomplete="off">
    <label for="email">Administrator email</label><input id="email" type="email" required placeholder="admin@acme.com" autocomplete="email">
    <label for="tier">Plan</label><select id="tier"><option value="free">Free · 10 users</option><option value="paid">Paid · 100 users</option></select>
    <button class="primary" type="submit">Provision tenant →</button>
   </form>
   <p id="msg" role="status"></p>
   <div class="tierbar"><span class="chip">10 users</span><span class="chip">1 app</span><span class="chip">shadow mode</span><span class="chip">NetBird CE</span></div>
   <p class="note">Preview only · no live changes · secrets stay in Dokploy.</p>
   <details class="mini"><summary>Invite a user</summary>
    <form id="user-form"><input id="invite-email" type="email" placeholder="dev@xyz.com" required>
     <select id="invite-role"><option value="viewer">viewer</option><option value="developer">developer</option><option value="tenant_admin">tenant admin</option></select>
     <button type="submit">Invite user</button></form>
   </details>
   <details class="mini"><summary>Add a protected app</summary>
    <form id="app-form"><input id="app-id" placeholder="crm" pattern="[a-z][a-z0-9_-]*" required>
     <input id="app-host" placeholder="crm.xyz.com" required>
     <button type="submit">Add app</button></form>
   </details>
  </section>
  <section class="glass panel">
   <h2>Tenants</h2>
   <div class="tablewrap"><table><thead><tr><th>Tenant</th><th>Plan</th><th>Status</th><th>Provisioning</th><th>Actions</th></tr></thead><tbody id="rows"></tbody></table></div>
  </section>
 </div>
 <section class="glass" style="padding:14px 20px">
  <div class="statebar">
   <div class="fact">backend mode <b id="s-mode">—</b></div>
   <div class="fact">last change <b id="s-change">—</b></div>
   <div class="fact">users <b id="s-users">0</b></div>
   <div class="fact">apps <b id="s-apps">0</b></div>
   <div class="pipeline" id="pipeline"><span class="empty">no provisioning records yet</span></div>
  </div>
  <div class="pager"><span id="page-info">0 tenants</span><button id="prev" type="button">◀ prev</button><button id="next" type="button">next ▶</button></div>
 </section>
 <p class="foot">ZETRIS · MULTI-TENANT ZTNA CONTROL PLANE</p>
</div>
<div class="login" id="login" hidden><form class="glass panel" id="login-form">
 <h2>Operator sign-in</h2><label for="operator-token">Operator token</label>
 <input id="operator-token" type="password" required autocomplete="current-password">
 <button class="primary" type="submit">Sign in →</button>
</form></div>
<script src="/app.js" defer></script></body></html>"""

SHARED_TENANT_CSS = """
:root{--glass:rgba(4,22,13,.70);--glass2:rgba(8,38,22,.60);--stroke:rgba(52,211,153,.22);
--ink:#d9ffe8;--muted:#6ba887;--green:#34d399;--lime:#a3e635;--bad:#fb7185;--mono:ui-monospace,Menlo,Consolas,monospace}
*{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:var(--ink);
background:#020604 radial-gradient(50% 50% at 80% 0%,rgba(52,211,153,.16),transparent 60%);padding:2rem}
.bg{position:fixed;inset:0;z-index:-1;opacity:.25;background-image:linear-gradient(rgba(52,211,153,.06) 1px,transparent 1px),
linear-gradient(90deg,rgba(52,211,153,.06) 1px,transparent 1px);background-size:44px 44px}
.wrap{max-width:900px;margin:auto}.glass{background:linear-gradient(145deg,var(--glass2),var(--glass));
border:1px solid var(--stroke);border-radius:20px;backdrop-filter:blur(22px);box-shadow:0 18px 60px rgba(0,0,0,.5)}
.panel{padding:26px;margin-bottom:18px}h1{font-size:22px;margin:0 0 4px}.sub{color:var(--muted);font-size:12px;margin:0 0 22px;font-family:var(--mono)}
h2{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--green);margin:0 0 14px}
.url-card{display:block;padding:14px 16px;margin-bottom:10px;border:1px solid var(--stroke);border-radius:12px;
background:rgba(52,211,153,.05);text-decoration:none;color:var(--ink)}
.url-card .k{display:block;font-family:var(--mono);font-size:10px;text-transform:uppercase;color:var(--muted);letter-spacing:.1em}
.url-card .v{display:block;font-family:var(--mono);font-size:13px;color:var(--lime);margin-top:4px;word-break:break-all}
.url-card .go{float:right;font-size:11px;color:var(--muted)}
.cred{font-family:var(--mono);font-size:15px;color:var(--lime);background:rgba(0,0,0,.35);padding:10px 12px;border-radius:9px;word-break:break-all}
label{display:block;font-family:var(--mono);font-size:10px;text-transform:uppercase;color:var(--muted);margin:12px 0 5px}
input,select{width:100%;padding:10px 12px;border-radius:10px;border:1px solid var(--stroke);
background:rgba(0,0,0,.4);color:var(--ink);font:inherit;font-size:13px;outline:none}
input:focus,select:focus{border-color:var(--green)}button{font:inherit;font-size:12px;cursor:pointer;padding:10px 14px;
border-radius:10px;border:1px solid var(--stroke);background:rgba(52,211,153,.10);color:var(--ink);margin-top:10px}
button:hover{background:rgba(52,211,153,.2)}button.primary{background:linear-gradient(120deg,var(--lime),var(--green));color:#02160d;border:none;width:100%}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:760px){.cols{grid-template-columns:1fr}}
.badge{font-family:var(--mono);font-size:10px;padding:5px 9px;border-radius:999px;background:rgba(96,165,250,.14);color:#93c5fd}
.badge.ok{background:rgba(52,211,153,.16);color:var(--lime)}.badge.bad{background:rgba(251,113,133,.18);color:var(--bad)}
.msg{font-family:var(--mono);font-size:11px;color:var(--lime);min-height:16px;word-break:break-all}
.err{font-family:var(--mono);font-size:11px;color:var(--bad)}
.metrics{display:flex;gap:14px;flex-wrap:wrap;margin:14px 0}
.metric{flex:1;min-width:140px;padding:14px;border:1px solid var(--stroke);border-radius:12px;background:rgba(52,211,153,.04)}
.metric .k{font-family:var(--mono);font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}
.metric .v{font-family:var(--mono);font-size:22px;color:var(--green);margin-top:5px}
.toggle{display:inline-flex;align-items:center;gap:6px;margin:4px 12px 4px 0;text-transform:none}
.toggle input{width:auto}.note{font-family:var(--mono);font-size:10px;color:var(--muted);line-height:1.6;margin-top:14px}
"""

LANDING_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Zetris · Access portal</title>
<style>""" + SHARED_TENANT_CSS + """
.hero{text-align:center;margin-bottom:24px}.hero h1{font-size:30px}
.cards{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:780px){.cards{grid-template-columns:1fr}}
.op{background:linear-gradient(140deg,rgba(163,230,53,.12),rgba(52,211,153,.04))}
.role{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--lime)}
.muted{color:var(--muted);font-size:11px;line-height:1.6}
</style></head><body><div class="bg"></div><div class="wrap">
<section class="glass panel hero"><h1>Zetris Access Portal</h1>
<p class="sub">zero-trust network access · tenant provisioned</p>
<p class="muted">Choose how you are joining: platform operators manage the control plane;
customer organizations manage their own tenant workspace.</p></section>
<div class="cards">
<section class="glass panel op"><div class="role">Platform operator</div><h2>Control plane sign-in</h2>
<p class="muted">For the team designing and running Zetris. Manage all tenants.</p>
<form id="operator-form"><label>Operator token</label>
<input id="operator-token" type="password" required autocomplete="current-password">
<button class="primary" type="submit">Open operator console →</button></form></section>
<section class="glass panel"><div class="role">Customer organization</div><h2>Your workspace</h2>
<p class="muted">Open your tenant console with the one-time link from your handoff, or start a new tenant.</p>
<form id="tenant-form"><label>Tenant ID</label><input id="tenant-slug" placeholder="xyz" required>
<label>One-time handoff token</label><input id="tenant-token" type="password" required>
<button class="primary" type="submit">Open tenant console →</button></form>
<form id="signup-form" style="margin-top:18px;border-top:1px solid var(--stroke);padding-top:14px">
<label>New tenant ID</label><input id="new-slug" pattern="[a-z][a-z0-9-]*" placeholder="xyz" required>
<label>Administrator email</label><input id="new-email" type="email" placeholder="admin@xyz.com" required>
<label>Plan</label><select id="new-tier"><option value="free">Free · 10 users</option><option value="paid">Paid · 100 users</option></select>
<button type="submit">Create tenant</button></form></section>
</div><p class="msg" id="msg"></p></div>
<script src="/landing.js" defer></script></body></html>"""

TENANT_HANDOFF_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Zetris · Tenant handoff</title>
<style>""" + SHARED_TENANT_CSS + """</style></head><body><div class="bg"></div><div class="wrap">
<section class="glass panel"><h1>Welcome to your Zetris workspace</h1>
<p class="sub">One-time handoff · credentials shown once</p>
<div class="cols"><div>
<h2>Your tenant</h2>
<p class="sub">Tenant</p><div class="cred" id="tenant">…</div>
<p class="sub">Administrator</p><div class="cred" id="email">…</div>
<p class="sub">One-time password</p><div class="cred" id="password">…</div>
<p class="note">Change this password at first login. It is not stored by the control plane.</p>
<a class="primary" id="portal-link" style="display:block;text-align:center;text-decoration:none;margin-top:12px">Open management console →</a>
</div><div><h2>Your doors</h2><div id="cards"></div></div></div>
<p class="err" id="error" hidden></p>
</section></div><script src="/tenant-handoff.js" defer></script></body></html>"""

TENANT_PORTAL_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Zetris · Tenant console</title>
<style>""" + SHARED_TENANT_CSS + """</style></head><body><div class="bg"></div><div class="wrap">
<section class="glass panel"><h1>Tenant console · <span id="tenant">…</span></h1>
<p class="sub">Plan <span id="tier">…</span> · status <span id="status">…</span></p>
<div class="metrics"><div class="metric"><div class="k">Users</div><div class="v" id="m-users">0 / 0</div></div>
<div class="metric"><div class="k">Protected apps</div><div class="v" id="m-apps">0 / 0</div></div></div>
<h2>Your doors</h2><div id="cards"></div>
</section>
<div class="cols">
<section class="glass panel"><h2>Invite a user</h2>
<form id="user-form"><label>Email</label><input id="invite-email" type="email" required>
<label>Role</label><select id="invite-role"><option value="viewer">viewer</option><option value="developer">developer</option><option value="tenant_admin">tenant admin</option></select>
<button class="primary" type="submit">Invite user</button></form></section>
<section class="glass panel"><h2>Add a protected app</h2>
<form id="app-form"><label>App ID</label><input id="app-id" pattern="[a-z][a-z0-9_-]*" required>
<label>Hostname</label><input id="app-host" required><button class="primary" type="submit">Add app</button></form></section>
</div>
<section class="glass panel"><h2>Network access</h2>
<button id="setup-key" type="button">Issue one-time client setup key</button>
<h2 style="margin-top:20px">Feature controls</h2><div id="toggles"></div>
<p class="msg" id="msg"></p><p class="err" id="error" hidden></p></section>
</div><script src="/tenant-portal.js" defer></script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ZetrisControlPlane"

    def log_message(self, *args):
        pass  # No URLs, bodies or credentials in logs.

    def respond(self, status, value, mime="application/json", cookie=None):
        content = json.dumps(value).encode() if mime == "application/json" else value.encode()
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'self'")
        self.end_headers()
        self.wfile.write(content)

    def host_matches(self):
        """Accept Host with or without :port, and either http/https Origin.

        This lets the app work behind Traefik (no port, https) or directly via
        the published port (http://host:8788) when no proxy is available.
        """
        host = (self.headers.get("Host") or "").split(":", 1)[0]
        return host == self.server.allowed_host.split(":", 1)[0]

    def authenticated(self):
        token = self.server.service.operator_token
        if not token:
            return True  # local/preview only; Dokploy requires a token
        try:
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
            value = cookie["ztcp_operator"].value
        except (KeyError, ValueError):
            return False
        return secrets.compare_digest(value, token)

    def body(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 4096:
            raise ValueError("invalid body")
        data = json.loads(self.rfile.read(size))
        if not isinstance(data, dict):
            raise ValueError("invalid body")
        return data

    def tenant_session(self):
        """Return the tenant slug for a valid session query token, else None."""
        token = parse_qs(urlparse(self.path).query).get("session", [""])[0]
        entry = self.server.service.tenant_sessions.get(token)
        if not entry:
            return None
        if time.time() - entry[1] > 86400:
            self.server.service.tenant_sessions.pop(token, None)
            return None
        return entry[0]

    def do_GET(self):
        try:
            if not self.host_matches():
                return self.respond(403, {"error": "unexpected host"})
            path = self.path.split("?")[0]
            if path.startswith("/handoff/"):
                if not re.fullmatch(r"/handoff/[a-z0-9-]+", path):
                    return self.respond(404, {"error": "not found"})
                return self.respond(200, TENANT_HANDOFF_PAGE, "text/html; charset=utf-8")
            if re.fullmatch(r"/tenant/[a-z0-9-]+", path):
                return self.respond(200, TENANT_PORTAL_PAGE, "text/html; charset=utf-8")
            if path == "/healthz":
                return self.respond(200, {"ok": True})
            scripts = {
                "/app.js": "app.js",
                "/landing.js": "landing.js",
                "/tenant-handoff.js": "tenant-handoff.js",
                "/tenant-portal.js": "tenant-portal.js",
            }
            if path in scripts:
                script = (Path(__file__).resolve().parent / scripts[path]).read_text(encoding="utf-8")
                return self.respond(200, script, "application/javascript; charset=utf-8")
            if path == "/":
                return self.respond(200, LANDING_PAGE, "text/html; charset=utf-8")
            if path == "/operator":
                return self.respond(200, PAGE, "text/html; charset=utf-8")
            if path == "/api/me":
                return self.respond(200, {"authenticated": self.authenticated()})
            if path.startswith("/api/tenant/"):
                slug = self.tenant_session()
                if not slug:
                    return self.respond(401, {"error": "tenant session required"})
                if path == "/api/tenant/me":
                    row = self.server.service.store.get(slug)
                    return self.respond(200, {"authenticated": True, "slug": slug,
                                              "tier": row["tier"], "status": row["status"]})
                if path == "/api/tenant/state":
                    row = self.server.service.store.get(slug)
                    tenants, ext = reg.validate(REGISTRY)
                    tenant = next(t for t in tenants if t["id"] == slug)
                    return self.respond(200, {
                        **self.server.service.public(row),
                        "urls": {"app": "https://" + tenant["application_host"],
                                 "audit": "https://" + tenant["audit_hostname"],
                                 "netbird": "https://" + tenant["netbird_hostname"]},
                    })
                return self.respond(404, {"error": "not found"})
            if not self.authenticated():
                return self.respond(401, {"error": "operator sign-in required"})
            if path == "/api/tenants":
                return self.respond(200, {"tenants": [self.server.service.public(r) for r in self.server.service.store.all()]})
            if path == "/api/state":
                return self.respond(200, self.server.service.state())
            return self.respond(404, {"error": "not found"})
        except Exception:
            return self.respond(500, {"error": "request failed"})

    def do_POST(self):
        try:
            if not self.host_matches():
                return self.respond(403, {"error": "unexpected host"})
            origin = urlparse(self.headers.get("Origin") or "")
            if origin.hostname != self.server.allowed_host.split(":", 1)[0] or \
                    origin.scheme not in ("http", "https"):
                return self.respond(403, {"error": "unexpected origin"})
            path = self.path.split("?")[0]
            data = self.body()
            if path == "/api/session":
                token = data.get("token", "")
                if not self.server.service.operator_token or not secrets.compare_digest(
                        str(token), self.server.service.operator_token):
                    return self.respond(401, {"error": "invalid operator token"})
                secure = "; Secure" if os.environ.get("ZTCP_PUBLIC_SCHEME", "http") == "https" else ""
                return self.respond(200, {"authenticated": True},
                                    cookie="ztcp_operator=" + str(token) +
                                    "; HttpOnly; SameSite=Strict; Path=/" + secure)

            if path == "/api/tenant/claim":
                slug = str(data.get("slug", ""))
                payload = self.server.service.handoffs.pop(str(data.get("token", "")), None)
                if not payload or payload.get("tenant") != slug:
                    return self.respond(404, {"error": "invalid or used handoff token"})
                session = secrets.token_urlsafe(24)
                self.server.service.tenant_sessions[session] = (slug, time.time())
                return self.respond(200, {"tenant": slug, "session": session})

            if path.startswith("/api/handoff/"):
                slug = path.rsplit("/", 1)[1]
                if not re.fullmatch(r"[a-z0-9-]+", slug):
                    return self.respond(404, {"error": "not found"})
                payload = self.server.service.handoffs.pop(str(data.get("token", "")), None)
                if not payload or payload.get("tenant") != slug:
                    return self.respond(404, {"error": "handoff link is invalid or already used"})
                session = secrets.token_urlsafe(24)
                self.server.service.tenant_sessions[session] = (slug, time.time())
                return self.respond(200, {**payload, "session": session})

            if path.startswith("/api/tenant/"):
                slug = self.tenant_session()
                if not slug:
                    return self.respond(401, {"error": "tenant session required"})
                action = path.rsplit("/", 1)[1]
                row = self.server.service.store.get(slug)
                ctx = self.server.service.context(slug)
                if action == "users":
                    users_count, _ = self.server.service.counts(slug)
                    if users_count >= reg.TIERS[row["tier"]]["max_users"]:
                        return self.respond(403, {"error": "user limit reached for this tier"})
                    email, role = str(data.get("email", "")), str(data.get("role", "viewer"))
                    if not reg.EMAIL.fullmatch(email) or role not in usr.ROLE_MAP:
                        return self.respond(400, {"error": "invalid invite email or role"})
                    result = usr.invite(ctx, email, role)
                    with self.server.service.store.connect() as conn:
                        conn.execute("INSERT OR REPLACE INTO tenant_users VALUES (?,?,?,?,?)",
                                     (slug, email, role, result["mode"], time.time()))
                    return self.respond(202, {"result": result, "mode": ctx.runner.mode,
                                              "planned_operations": len(ctx.runner.operations)})
                if action == "apps":
                    _, apps_count = self.server.service.counts(slug)
                    if apps_count >= reg.TIERS[row["tier"]]["max_apps"]:
                        return self.respond(403, {"error": "app limit reached for this tier"})
                    result = appctl.add_app(ctx, data)
                    with self.server.service.store.connect() as conn:
                        conn.execute("INSERT OR REPLACE INTO tenant_apps VALUES (?,?,?,?,?,?)",
                                     (slug, result["app"], result["host"],
                                      ",".join(result["groups"]), result["mode"], time.time()))
                    return self.respond(202, {"result": result, "mode": ctx.runner.mode,
                                              "planned_operations": len(ctx.runner.operations)})
                if action == "features":
                    features = json.loads(row["features"])
                    name, value = data.get("name"), data.get("value")
                    if name not in features or type(value) is not bool:
                        return self.respond(400, {"error": "unknown feature or invalid value"})
                    if row["tier"] == "free" and value and not reg.TIERS["free"]["features"].get(name, False):
                        return self.respond(403, {"error": "feature is not available on the free tier"})
                    if name == "block_on_critical" and value and not features.get("risk_writes"):
                        return self.respond(403, {"error": "enable score writes before enforcement"})
                    result = tog.apply_toggle(ctx, name, value, features)
                    self.server.service.store.update(slug, features=features)
                    return self.respond(200, {"result": result, "mode": ctx.runner.mode,
                                              "planned_operations": len(ctx.runner.operations)})
                if action == "setup-key":
                    result = cli_client.issue_setup_key(ctx)
                    return self.respond(200, {"result": result, "mode": ctx.runner.mode,
                                              "planned_operations": len(ctx.runner.operations)})
                return self.respond(404, {"error": "not found"})

            if path != "/api/signup" and not self.authenticated():
                return self.respond(401, {"error": "operator sign-in required"})
            if path == "/api/signup":
                slug, email, tier = data.get("slug"), data.get("email"), data.get("tier")
                if not reg.SLUG.fullmatch(str(slug)) or not reg.EMAIL.fullmatch(str(email)):
                    return self.respond(400, {"error": "invalid tenant ID or email"})
                if tier not in reg.TIERS:
                    return self.respond(400, {"error": "unknown tier"})
                tenants, ext = reg.validate(REGISTRY)
                if any(t["id"] == slug for t in tenants):
                    return self.respond(409, {"error": "tenant already exists"})
                # The free wall is 10 users PER TENANT; signup creates exactly
                # one administrator, so it is always within quota. Invite-time
                # enforcement belongs in the self-service users endpoint.
                tenant, extra = reg.build_tenant(
                    slug, str(data.get("domain", "ztna.local.test")), tier, email,
                    slot=len(tenants), description="signup")
                document = json.loads(REGISTRY.read_text(encoding="utf-8"))
                document["tenants"].append(tenant)
                document["tenant_ext"][slug] = extra
                REGISTRY.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                with self.server.service.store.connect() as conn:
                    conn.execute("INSERT OR REPLACE INTO tenant_users VALUES (?,?,?,?,?)",
                                 (slug, email, "tenant_admin", "admin", time.time()))
                self.server.service.submit(slug, tier, email, secrets.token_urlsafe(24))
                return self.respond(202, {"slug": slug, "status": "queued"})
            match = re.fullmatch(
                r"/api/tenants/([a-z0-9-]+)/(users|apps|features|suspend|resume|backup|delete|setup-key|rotate|handoff)", path)
            if match:
                slug, action = match.groups()
                row = self.server.service.store.get(slug)
                if action == "handoff":
                    url = self.server.service.handoff_for(slug)
                    if not url:
                        return self.respond(404, {"error": "handoff is not available for this tenant"})
                    return self.respond(200, {"handoff_url": url})
                if action in ("suspend", "resume", "backup", "delete", "setup-key", "rotate"):
                    ctx = self.server.service.context(slug)
                    if action == "suspend":
                        result = life.suspend(ctx)
                        self.server.service.store.update(slug, status="suspended")
                    elif action == "resume":
                        result = life.resume(ctx)
                        self.server.service.store.update(slug, status="ready")
                    elif action == "backup":
                        result = life.backup(ctx)
                    elif action == "delete":
                        result = life.delete(ctx)
                        self.server.service.store.update(slug, status="deleted")
                    elif action == "setup-key":
                        result = cli_client.issue_setup_key(ctx)
                    else:
                        result = sec.rotate(ctx)
                    return self.respond(200, {"result": result, "mode": ctx.runner.mode,
                                              "planned_operations": len(ctx.runner.operations)})
                if action == "users":
                    users_count, _ = self.server.service.counts(slug)
                    if users_count >= reg.TIERS[row["tier"]]["max_users"]:
                        return self.respond(403, {"error": "user limit reached for this tier"})
                    email = str(data.get("email", ""))
                    role = str(data.get("role", "viewer"))
                    if not reg.EMAIL.fullmatch(email) or role not in usr.ROLE_MAP:
                        return self.respond(400, {"error": "invalid invite email or role"})
                    ctx = self.server.service.context(slug)
                    result = usr.invite(ctx, email, role)
                    with self.server.service.store.connect() as conn:
                        conn.execute("INSERT OR REPLACE INTO tenant_users VALUES (?,?,?,?,?)",
                                     (slug, email, role, result["mode"], time.time()))
                    return self.respond(202, {"result": result, "mode": ctx.runner.mode,
                                              "planned_operations": len(ctx.runner.operations)})
                if action == "apps":
                    _, apps_count = self.server.service.counts(slug)
                    if apps_count >= reg.TIERS[row["tier"]]["max_apps"]:
                        return self.respond(403, {"error": "app limit reached for this tier"})
                    ctx = self.server.service.context(slug)
                    result = appctl.add_app(ctx, data)
                    with self.server.service.store.connect() as conn:
                        conn.execute("INSERT OR REPLACE INTO tenant_apps VALUES (?,?,?,?,?,?)",
                                     (slug, result["app"], result["host"],
                                      ",".join(result["groups"]), result["mode"], time.time()))
                    return self.respond(202, {"result": result, "mode": ctx.runner.mode,
                                              "planned_operations": len(ctx.runner.operations)})
                features = json.loads(row["features"])
                name, value = data.get("name"), data.get("value")
                if name not in features or type(value) is not bool:
                    return self.respond(400, {"error": "unknown feature or invalid value"})
                if row["tier"] == "free" and value and not reg.TIERS["free"]["features"].get(name, False):
                    return self.respond(403, {"error": "feature is not available on the free tier"})
                if name == "block_on_critical" and value and not features.get("risk_writes"):
                    return self.respond(403, {"error": "enable score writes before enforcement"})
                ctx = self.server.service.context(slug)
                result = tog.apply_toggle(ctx, name, value, features)
                self.server.service.store.update(slug, features=features)
                return self.respond(200, {"result": result, "mode": ctx.runner.mode,
                                          "planned_operations": len(ctx.runner.operations)})
            return self.respond(404, {"error": "not found"})
        except ValueError:
            return self.respond(400, {"error": "invalid request"})
        except KeyError:
            return self.respond(404, {"error": "tenant not found"})
        except Exception:
            return self.respond(500, {"error": "request failed"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8788)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.apply and len(args.confirm) < 16:
        raise SystemExit("--apply requires --confirm with a 16+ character token")
    operator_token = os.environ.get("ZTCP_OPERATOR_TOKEN", "")
    if os.environ.get("ZTCP_PUBLIC_HOST") and len(operator_token) < 16:
        raise SystemExit("ZTCP_OPERATOR_TOKEN must be at least 16 characters when publicly exposed")
    service = Service(apply=args.apply, confirm=args.confirm, operator_token=operator_token)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.service = service
    server.allowed_host = os.environ.get("ZTCP_PUBLIC_HOST") or ("127.0.0.1:" + str(server.server_port))
    service.start()
    print("Control plane on http://" + server.allowed_host, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        service.close()


if __name__ == "__main__":
    main()
