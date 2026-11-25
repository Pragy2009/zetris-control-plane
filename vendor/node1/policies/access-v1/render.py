"""Render review-only policies. Never modifies live policies or identities."""
import argparse
import json
from pathlib import Path
import re
from application_model import compile_model, strict_load

ROOT = Path(__file__).resolve().parent


def render(tenant, settings, application_document=None):
    if not re.fullmatch(r"[a-z][a-z0-9_-]{1,63}", tenant):
        raise ValueError("Invalid tenant")
    config = dict(settings, tenant=tenant, version="access-v1.1.0", risk_max_age_seconds=600,
                  mfa_max_age_seconds=300, mfa_acrs=["urn:zetris:acr:mfa"])
    model, conditions = compile_model(application_document if application_document is not None else strict_load(ROOT / "applications.json"), settings["host"])
    application_rego = (ROOT / "applications.rego.tmpl").read_text().replace("__APPLICATION_POLICY__", json.dumps(model, sort_keys=True, allow_nan=False)).replace("__APPLICATION_CONDITIONS__", conditions)
    return (ROOT / "policy.rego.tmpl").read_text().replace("__PACKAGE__", tenant.replace("-", "_")).replace("__CONFIG__", json.dumps(config, sort_keys=True)).replace("__APPLICATION_LAYER__", application_rego)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = {tenant:render(tenant, config) for tenant, config in strict_load(ROOT / "tenants.json").items()}
    for tenant, content in rendered.items():
        path = ROOT / (tenant + ".rego")
        if args.check:
            if not path.exists() or path.read_text() != content:
                raise SystemExit("Rendered policy differs: " + tenant)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
    print("Review-only access policies " + ("verified" if args.check else "rendered") + "; live configuration unchanged")
