"""Local, read-only-with-respect-to-live-services tests.

All temporary output stays inside tenant-control-plane/. No secret files are
read; render tests use ephemeral in-memory values.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from control import registry as reg       # noqa: E402
from control import render as rnd         # noqa: E402


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "registry.json"

    def write(self, data):
        self.path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return self.path

    def test_build_and_validate(self):
        data = reg.build_registry([("canary", "ztna.local.test", "free", "admin@canary.test", 0, "canary")])
        tenants, ext = reg.validate(self.write(data))
        self.assertEqual(len(tenants), 1)
        self.assertEqual(ext["canary"]["tier"], "free")
        self.assertEqual(ext["canary"]["features"]["risk_writes"], False)

    def test_secrets_are_references_only(self):
        data = reg.build_registry([("canary", "ztna.local.test", "free", "admin@canary.test", 0, "")])
        for ref in data["tenants"][0]["secret_refs"].values():
            self.assertTrue(ref.startswith("env:"))
            name = ref.split(":", 1)[1]
            self.assertTrue(name.startswith("ZTCP_CANARY_"), name)

    def test_bad_tier_rejected(self):
        data = reg.build_registry([("canary", "ztna.local.test", "free", "admin@canary.test", 0, "")])
        data["tenant_ext"]["canary"]["tier"] = "enterprise"
        with self.assertRaises(reg.ControlError):
            reg.validate(self.write(data))

    def test_two_tenants_port_isolation(self):
        data = reg.build_registry([
            ("canary", "ztna.local.test", "free", "admin@canary.test", 0, ""),
            ("other", "ztna.local.test", "free", "admin@other.test", 1, ""),
        ])
        tenants, _ = reg.validate(self.write(data))
        ports = [t[k] for t in tenants for k in ("dashboard_port", "management_port", "audit_port")]
        self.assertEqual(len(ports), len(set(ports)))


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.tenant, self.ext = reg.build_tenant(
            "canary", "ztna.local.test", "free", "admin@canary.test", description="canary")

    def test_plan_contains_all_planes(self):
        names = {step["step"] for step in rnd.plan(self.tenant, self.ext)}
        for expected in ("database", "identity", "netbird_stack", "access_gateway",
                         "access_connector", "policy", "audit_stack", "routes", "verify", "handoff"):
            self.assertIn(expected, names)

    def test_render_all(self):
        out = Path(self.tmp.name) / "provisioned"
        manifest = rnd.render_all(self.tenant, self.ext, out=out / "canary")
        self.assertTrue(manifest["preview"])
        for key in ("netbird", "policy", "audit", "access-gateway", "access-connector"):
            self.assertTrue(manifest["artifacts"][key], key)
        self.assertTrue((out / "canary/netbird/compose.json").is_file())
        self.assertTrue((out / "canary/audit/compose.json").is_file())
        self.assertTrue((out / "canary/access-connector/compose.json").is_file())
        self.assertTrue((out / "canary/policy/canary.rego").is_file())
        text = (out / "canary/manifest.json").read_text(encoding="utf-8")
        self.assertTrue(all(ref.split(":", 1)[1] not in text for ref in self.tenant["secret_refs"].values()))


class StepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.tenant, self.ext = reg.build_tenant(
            "canary", "ztna.local.test", "free", "admin@canary.test", description="canary")
        self.config = json.loads((ROOT / "config/portal.example.json").read_text(encoding="utf-8"))
        self.out = Path(self.tmp.name) / "provisioned" / "canary"
        rnd.render_all(self.tenant, self.ext, out=self.out)
        self.config["ca_file"] = str(self.out / "lab-ca/ca.crt")
        self.config["scripts_root"] = str(reg.ZETRIS_DEFAULT)
        self.secrets = rnd.ephemeral_environ(self.tenant)

    def test_apply_guard(self):
        from control import steps as stp
        with self.assertRaises(stp.StepError):
            stp.Runner(mode="preview").ensure_apply()

    def test_preview_runs_without_side_effects(self):
        from control import steps as stp
        runner = stp.Runner(mode="preview")
        ctx = stp.Context(tenant=self.tenant, ext=self.ext, config=self.config,
                          secrets=self.secrets, out_dir=self.out, runner=runner,
                          admin_password="preview-only")
        records = stp.run_all(ctx)
        self.assertTrue(records)
        self.assertTrue(all(record["status"] in ("ok", "skipped") for record in records), records)
        self.assertTrue(runner.operations)
        # Preview writes ONLY the one-time handoff token/URLs, never a password.
        handoff = self.out / "handoff.json"
        self.assertTrue(handoff.is_file())
        data = json.loads(handoff.read_text(encoding="utf-8"))
        self.assertGreater(len(data["one_time_token"]), 20)
        self.assertNotIn("admin_password", data)
        self.assertNotIn("preview-only", handoff.read_text(encoding="utf-8"))


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.tenant, self.ext = reg.build_tenant(
            "canary", "ztna.local.test", "free", "admin@canary.test", description="canary")
        self.config = json.loads((ROOT / "config/portal.example.json").read_text(encoding="utf-8"))
        self.out = Path(self.tmp.name) / "provisioned" / "canary"
        rnd.render_all(self.tenant, self.ext, out=self.out)
        self.config["ca_file"] = str(self.out / "lab-ca/ca.crt")
        self.config["scripts_root"] = str(reg.ZETRIS_DEFAULT)

    def context(self):
        from control import steps as stp
        return stp.Context(tenant=self.tenant, ext=self.ext, config=self.config,
                           secrets=rnd.ephemeral_environ(self.tenant), out_dir=self.out,
                           runner=stp.Runner(mode="preview"))

    def test_suspend_resume_preview(self):
        from control import lifecycle as life
        ctx = self.context()
        stopped = life.suspend(ctx)
        started = life.resume(ctx)
        self.assertEqual(stopped["status"], "suspended")
        self.assertEqual(started["status"], "running")
        self.assertTrue(ctx.runner.operations)
        self.assertTrue(all(op["kind"] == "command" for op in ctx.runner.operations))

    def test_delete_preview_preserves_files(self):
        from control import lifecycle as life
        ctx = self.context()
        result = life.delete(ctx)
        self.assertEqual(result["status"], "deletion planned")
        self.assertTrue((self.out / "netbird/compose.json").is_file())

    def test_setup_key_preview(self):
        from control import client as cli_client
        ctx = self.context()
        result = cli_client.issue_setup_key(ctx)
        self.assertTrue(result["one_time_setup_key"].startswith("PREVIEW_ONLY"))
        self.assertIn("https://github.com/netbirdio/netbird/releases", result["download_url"])


class IsolationArtifactTests(unittest.TestCase):
    """Config-level version of the 8-point isolation proof in his build doc.

    Live denial proofs need running services; this verifies the desired state
    that the live tests later assert.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)

    def test_two_tenants_have_disjoint_artifacts(self):
        tenants = []
        for slug, slot in (("alpha", 0), ("beta", 1)):
            tenant, ext = reg.build_tenant(slug, "ztna.local.test", "free",
                                           f"admin@{slug}.test", slot=slot)
            out = Path(self.tmp.name) / "provisioned" / slug
            rnd.render_all(tenant, ext, out=out)
            tenants.append((tenant, ext, out))
        (a, ea, oa), (b, eb, ob) = tenants
        for key in ("id", "realm", "issuer", "netbird_stack", "netbird_database",
                    "netbird_database_role", "application_host", "audit_hostname",
                    "audit_oidc_client_id", "policy_file", "telemetry_user"):
            self.assertNotEqual(a[key], b[key], key)
        rego_a = (oa / "policy" / a["policy_file"]).read_text(encoding="utf-8")
        rego_b = (ob / "policy" / b["policy_file"]).read_text(encoding="utf-8")
        self.assertIn("package alpha", rego_a)
        self.assertIn("package beta", rego_b)
        grants = json.loads((oa / "connector-grants.json").read_text(encoding="utf-8"))
        self.assertEqual(next(iter(grants.values()))["tenants"], ["alpha"])
        snippet_a = (oa / "netbird/Caddyfile.snippet").read_text(encoding="utf-8")
        snippet_b = (ob / "netbird/Caddyfile.snippet").read_text(encoding="utf-8")
        self.assertNotEqual(snippet_a, snippet_b)


class FinalSliceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.tenant, self.ext = reg.build_tenant(
            "canary", "ztna.local.test", "free", "admin@canary.test", description="canary")
        self.config = json.loads((ROOT / "config/portal.example.json").read_text(encoding="utf-8"))
        self.out = Path(self.tmp.name) / "provisioned" / "canary"
        rnd.render_all(self.tenant, self.ext, out=self.out)
        self.config["ca_file"] = str(self.out / "lab-ca/ca.crt")

    def context(self):
        from control import steps as stp
        return stp.Context(tenant=self.tenant, ext=self.ext, config=self.config,
                           secrets=rnd.ephemeral_environ(self.tenant), out_dir=self.out,
                           runner=stp.Runner(mode="preview"))

    def test_rotate_preview_never_writes_values(self):
        from control import secrets as sec
        result = sec.rotate(self.context())
        self.assertEqual(result["mode"], "preview")
        self.assertTrue(result["env_vars_to_update"])
        self.assertNotIn("one_time_file", result)
        self.assertTrue(any("Dokploy" in text for text in result["manual_followups"]))

    def test_acceptance_structural(self):
        from control import acceptance as acc
        second, second_ext = reg.build_tenant(
            "other", "ztna.local.test", "free", "admin@other.test", slot=1)
        out_b = Path(self.tmp.name) / "provisioned" / "other"
        rnd.render_all(second, second_ext, out=out_b)
        results = acc.structural([self.tenant, second], [self.ext, second_ext], [self.out, out_b])
        self.assertTrue(results)
        self.assertTrue(all(item["status"] == "pass" for item in results), results)


class RouteSchemeTests(unittest.TestCase):
    def test_raw_gateway_has_catch_all(self):
        compose = (ROOT / "docker-compose.raw.yml").read_text(encoding="utf-8")
        self.assertIn(":80 {\n          reverse_proxy control-plane:8788\n        }", compose)

    def test_http_site_forces_port_80(self):
        from control import steps as stp
        self.assertEqual(stp._http_site("https://a.example.com {\n}\n"),
                         "http://a.example.com {\n}\n")
        self.assertEqual(stp._http_site("a.example.com {\n}\n"),
                         "http://a.example.com {\n}\n")


class TokenStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.old = None

    def test_save_load_forget(self):
        from control import tokens
        old_folder = tokens.FOLDER
        tokens.FOLDER = Path(self.tmp.name) / "admin_tokens"
        try:
            self.assertEqual(tokens.load("acme"), "")
            target = tokens.save("acme", "preview-token-value")
            self.assertTrue(target.is_file())
            self.assertEqual(tokens.load("acme"), "preview-token-value")
            tokens.forget("acme")
            self.assertEqual(tokens.load("acme"), "")
        finally:
            tokens.FOLDER = old_folder


if __name__ == "__main__":
    unittest.main(verbosity=2)
