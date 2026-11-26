"""HTTP tests for the signup UI. Everything stays inside this folder."""
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from control import registry as reg  # noqa: E402

spec = importlib.util.spec_from_file_location("ztcp_web", ROOT / "web/app.py")
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        work = Path(self.tmp.name)
        self.old_state, self.old_registry = web.STATE, web.REGISTRY
        web.STATE = work / "state"
        web.REGISTRY = work / "registry.json"
        seed = reg.build_registry([("seed", "ztna.local.test", "free", "admin@seed.test", 0, "seed")])
        web.REGISTRY.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
        self.service = web.Service(apply=False, confirm="")
        self.server = web.ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        self.server.service = self.service
        self.server.allowed_host = "127.0.0.1:" + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://" + self.server.allowed_host
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.service.close()
        web.STATE, web.REGISTRY = self.old_state, self.old_registry

    def call(self, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Origin": self.base}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_operator_auth_gate(self):
        self.server.service = web.Service(apply=False, confirm="", operator_token="abcdefghijklmnop")
        status, me = self.call("/api/me")
        self.assertEqual(status, 200)
        self.assertFalse(me["authenticated"])
        status, _ = self.call("/api/tenants")
        self.assertEqual(status, 401)
        status, session = self.call("/api/session", {"token": "abcdefghijklmnop"})
        self.assertEqual(status, 200, session)
        self.assertTrue(session["authenticated"])

    def test_direct_port_host_is_accepted(self):
        self.server.allowed_host = "portal.example.test"
        req = urllib.request.Request(self.base + "/healthz",
                                     headers={"Host": "portal.example.test:8788"})
        with urllib.request.urlopen(req, timeout=10) as response:
            self.assertEqual(response.status, 200)
        self.server.allowed_host = "127.0.0.1:" + str(self.server.server_port)

    def test_health_and_signup(self):
        self.assertEqual(self.call("/healthz")[0], 200)
        status, body = self.call("/api/signup", {"slug": "canary", "email": "admin@canary.test", "tier": "free"})
        self.assertEqual(status, 202, body)
        self.assertEqual(body["slug"], "canary")
        tenants = self.call("/api/tenants")[1]["tenants"]
        self.assertTrue(any(item["slug"] == "canary" for item in tenants))

    def test_state_endpoint_reports_real_store_data(self):
        self.call("/api/signup", {"slug": "canary", "email": "admin@canary.test", "tier": "free"})
        status, invite = self.call("/api/tenants/canary/users", {"email": "user@example.com", "role": "developer"})
        self.assertEqual(status, 202, invite)
        status, added = self.call("/api/tenants/canary/apps", {"id": "one", "host": "one.ztna.local.test"})
        self.assertEqual(status, 202, added)
        status, state = self.call("/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(state["tenants"], 1)
        self.assertEqual(state["users"], 2)
        self.assertEqual(state["apps"], 1)
        self.assertEqual(state["mode"], "preview")
        self.assertIn("queued", state["statuses"])
        self.assertIsInstance(state["last_change"], (int, float))

    def test_free_user_and_app_walls(self):
        self.call("/api/signup", {"slug": "canary", "email": "admin@canary.test", "tier": "free"})
        # one admin exists at signup; 9 more invites fit the limit of 10
        for index in range(9):
            status, _ = self.call("/api/tenants/canary/users",
                                  {"email": f"user{index}@example.com", "role": "viewer"})
            self.assertEqual(status, 202, index)
        status, _ = self.call("/api/tenants/canary/users",
                              {"email": "overflow@example.com", "role": "viewer"})
        self.assertEqual(status, 403)
        status, _ = self.call("/api/tenants/canary/apps",
                              {"id": "second", "host": "second.ztna.local.test"})
        self.assertEqual(status, 202)      # first app is included in free tier
        status, _ = self.call("/api/tenants/canary/apps",
                              {"id": "third", "host": "third.ztna.local.test"})
        self.assertEqual(status, 403)

    def test_lifecycle_and_client_endpoints(self):
        self.call("/api/signup", {"slug": "canary", "email": "admin@canary.test", "tier": "free"})
        for action in ("suspend", "resume", "backup", "setup-key"):
            status, body = self.call(f"/api/tenants/canary/{action}", {})
            self.assertEqual(status, 200, (action, body))
            self.assertEqual(body["mode"], "preview")
        status, body = self.call("/api/tenants/canary/delete", {})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["result"]["status"], "deletion planned")
        tenants = self.call("/api/tenants")[1]["tenants"]
        self.assertEqual(next(t for t in tenants if t["slug"] == "canary")["status"], "deleted")

    def test_rotate_handoff_and_tenant_portal(self):
        self.call("/api/signup", {"slug": "canary", "email": "admin@canary.test", "tier": "free"})
        status, body = self.call("/api/tenants/canary/rotate", {})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["result"]["mode"], "preview")
        self.service.handoffs["one-time-token"] = {
            "tenant": "canary", "urls": {"app": "https://canary-app.ztna.local.test"},
            "admin_password": "never-persisted"}
        status, handoff = self.call("/api/tenants/canary/handoff", {})
        self.assertEqual(status, 200, handoff)
        self.assertIn("/handoff/canary?token=one-time-token", handoff["handoff_url"])
        with urllib.request.urlopen(self.base + "/handoff/canary?token=one-time-token", timeout=10) as response:
            page = response.read().decode()
        self.assertIn("tenant-handoff.js", page)
        status, payload = self.call("/api/handoff/canary", {"token": "one-time-token"})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["admin_password"], "never-persisted")
        session = payload["session"]
        status, me = self.call("/api/tenant/me?session=" + session)
        self.assertTrue(me["authenticated"])
        self.assertEqual(me["slug"], "canary")
        status, state = self.call("/api/tenant/state?session=" + session)
        self.assertEqual(status, 200)
        self.assertEqual(state["slug"], "canary")
        status, invited = self.call("/api/tenant/users?session=" + session,
                                    {"email": "dev@canary.test", "role": "developer"})
        self.assertEqual(status, 202, invited)
        with urllib.request.urlopen(self.base + "/tenant/canary?session=" + session, timeout=10) as response:
            portal = response.read().decode()
        self.assertIn("tenant-portal.js", portal)
        with urllib.request.urlopen(self.base + "/tenant-portal.js", timeout=10) as response:
            self.assertIn("application/javascript", response.headers["Content-Type"])
        status, _ = self.call("/api/handoff/canary", {"token": "one-time-token"})
        self.assertEqual(status, 404)
        self.service.handoffs["claim-token"] = {"tenant": "canary", "urls": {}}
        status, claim = self.call("/api/tenant/claim", {"slug": "canary", "token": "claim-token"})
        self.assertEqual(status, 200, claim)
        self.assertTrue(claim["session"])

    def test_csp_safe_static_script(self):
        with urllib.request.urlopen(self.base + "/app.js", timeout=10) as response:
            body = response.read().decode()
            self.assertIn("application/javascript", response.headers["Content-Type"])
        with urllib.request.urlopen(self.base + "/operator", timeout=10) as response:
            page = response.read().decode()
        self.assertIn('<script src="/app.js" defer></script>', page)
        with urllib.request.urlopen(self.base + "/", timeout=10) as response:
            landing = response.read().decode()
        self.assertIn("landing.js", landing)
        self.assertIn("Customer organization", landing)
        self.assertIn("Platform operator", landing)
        self.assertNotIn("onclick=", page)
        self.assertIn('id="pipeline"', page)
        self.assertIn('id="s-change"', page)
        self.assertIn('id="page-info"', page)
        self.assertNotIn("Live event stream", page)
        self.assertNotIn("System monitor", page)
        self.assertIn("--green", page)
        self.assertIn('<div class="glow"></div>', page)
        script = (ROOT / "web/app.js").read_text(encoding="utf-8")
        self.assertIn("pointermove", script)
        self.assertIn("--mx", script)
        self.assertNotIn("Math.random", script)
        self.assertNotIn("heartbeat", script)
        self.assertIn("/api/state", script)

    def test_paid_feature_wall(self):
        self.call("/api/signup", {"slug": "canary", "email": "admin@canary.test", "tier": "free"})
        status, body = self.call("/api/tenants/canary/features", {"name": "risk_writes", "value": True})
        self.assertEqual(status, 403, body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
