"""Per-tenant NetBird automation token storage.

Each tenant has its OWN NetBird server, so each gets its OWN PAT. Tokens are
written with 0600 under state/admin_tokens/ and never printed or logged.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parents[1]
FOLDER = MODULE_ROOT / "state" / "admin_tokens"


def path_for(slug: str) -> Path:
    return FOLDER / (slug + ".json")


def save(slug: str, token: str) -> Path:
    FOLDER.mkdir(parents=True, mode=0o700, exist_ok=True)
    target = path_for(slug)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"tenant": slug, "token": token}, stream)
    return target


def load(slug: str) -> str:
    target = path_for(slug)
    if not target.is_file():
        return ""
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(data.get("token", "")) if data.get("tenant") == slug else ""


def forget(slug: str) -> None:
    path_for(slug).unlink(missing_ok=True)
