#!/usr/bin/env python3
"""Reset LOCAL PREVIEW dashboard data only.

Clears:
  - tenant/user/app rows in the dashboard SQLite store
  - dashboard-created application/feature/rotation state files
  - dashboard-created provisioned tenant folders
  - registry.local.json back to the canary-only baseline

Keeps:
  - canary / other CLI test fixtures
  - vendored renderers, config templates, code, tests
  - NO .env access, NO lead repo access
"""
from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

from . import registry as reg

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "state"
DB = STATE / "portal.sqlite3"
REGISTRY = ROOT / "config/registry.local.json"
KEEP = {"canary", "other"}


def reset() -> dict:
    STATE.mkdir(parents=True, exist_ok=True)

    # 1. Clear dashboard rows. This is what drives metrics 0 / 0 / 0.
    removed = {"tenants": 0, "users": 0, "apps": 0}
    with sqlite3.connect(DB) as conn:
        for table in ("tenants", "tenant_users", "tenant_apps"):
            conn.execute(f"CREATE TABLE IF NOT EXISTS {table} (slug TEXT)")
            row = conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            removed[table] = row
            conn.execute(f"DELETE FROM {table}")
        conn.commit()

    # 2. Reset the dashboard registry to the canary-only baseline.
    tenant, ext = reg.build_tenant(
        "canary", "ztna.local.test", "free", "admin@canary.test", slot=0)
    REGISTRY.write_text(json.dumps({
        "schema_version": 1, "tenants": [tenant],
        "tenant_ext": {tenant["id"]: ext}}, indent=2) + "\n", encoding="utf-8")

    # 3. Remove per-tenant state artifacts created from the dashboard.
    for name in ("applications", "features"):
        folder = STATE / name
        if folder.is_dir():
            for path in folder.glob("*.json"):
                if path.stem not in KEEP:
                    path.unlink()
    for path in STATE.glob("rotation-*.json"):
        path.unlink()

    # 4. Remove provisioned folders for dashboard-created tenants.
    provisioned = ROOT / "provisioned"
    removed_folders = []
    if provisioned.is_dir():
        for path in provisioned.iterdir():
            if path.is_dir() and path.name not in KEEP:
                shutil.rmtree(path)
                removed_folders.append(path.name)

    return {"cleared_rows": removed, "removed_folders": removed_folders,
            "registry": "canary-only baseline", "kept": sorted(KEEP)}


if __name__ == "__main__":
    print(json.dumps(reset(), indent=2))
