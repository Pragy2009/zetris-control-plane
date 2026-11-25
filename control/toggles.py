"""Apply a feature toggle to a tenant's rendered stacks.

Risk flags are injected into the audit compose; changing them re-renders the
tenant and recreates only that audit instance. Other features are recorded in
the tenant's feature document for the next reconciliation pass.
"""
from __future__ import annotations

import json
from pathlib import Path

from .steps import Context, StepError

MODULE_ROOT = Path(__file__).resolve().parents[1]


def apply_toggle(ctx: Context, name: str, value: bool, features: dict):
    if name not in features:
        raise StepError("Unknown feature")
    features[name] = value
    folder = MODULE_ROOT / "state/features"
    folder.mkdir(mode=0o700, exist_ok=True)
    ctx.runner.write(folder / (ctx.tenant["id"] + ".json"),
                     json.dumps(features, indent=2) + "\n")

    if name in ("risk_writes", "block_on_critical"):
        audit = ctx.out_dir / "audit/compose.json"
        if audit.is_file():
            compose = json.loads(audit.read_text(encoding="utf-8"))
            env = compose["services"]["audit"]["environment"]
            env["WRITE_SCORES"] = "true" if features.get("risk_writes") else "false"
            env["BLOCK_ON_CRITICAL"] = "true" if features.get("block_on_critical") else "false"
            ctx.runner.write(audit, json.dumps(compose, indent=2) + "\n")
            ctx.runner.command(["docker", "compose", "-f", str(audit), "up", "-d",
                                "--force-recreate", "audit"], timeout=240)
    return {"tenant": ctx.tenant["id"], "feature": name, "value": value,
            "features": features, "mode": ctx.runner.mode,
            "note": "Reconciled into the tenant's rendered configuration."}
