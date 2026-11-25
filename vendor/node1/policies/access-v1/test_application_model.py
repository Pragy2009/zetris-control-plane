"""Authoring/compiler tests, including execution by the repository's pinned OPA."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from application_model import compile_model, strict_load
from render import ROOT, render

NOW = 2000000000
SETTINGS = strict_load(ROOT / "tenants.json")["ztna"]


def model():
    return strict_load(ROOT / "applications.json")


def request():
    return {
        "schema_version":1,"now":NOW,
        "principal":{"verified":True,"subject":"user-1","session":"session-1","tenant":"ztna","issuer":SETTINGS["issuer"],"role_client":SETTINGS["role_client"],"roles":["viewer"],"kind":"human","username":"alice","authorized_party":"node2-app-connector","expires_at":NOW+3600,"not_before":0,"issued_at":NOW-30,"auth_time":NOW-30,"acr":"urn:zetris:acr:mfa"},
        "http":{"host":SETTINGS["host"],"port":"443","protocol":"tcp","method":"GET","path":"/juice/"},
        "resource":{"tenant":"ztna","id":"workspace","kind":"workspace","action":"view","supported":True,"owner_subject":"user-1"},
        "risk":{"available":True,"subject":"user-1","session":"session-1","score":100,"level":"LOW","blocked":False,"updated_at":NOW-10},
        "approval":{"verified":False},"context":{"source_ip":"100.64.0.10","client_type":"envoy_http"},"device":{"verified":False}}


def access_rule(rule_id="allow-workspace", priority=100, action="allow", when=None):
    rule = {"id":rule_id,"priority":priority,"enabled":True,"applications":["workspace"],"application_groups":[],"action":action}
    if when is not None: rule["when"] = when
    return rule


class CompilerValidation(unittest.TestCase):
    def test_typoes_unsafe_fields_duplicates_and_invalid_types_rejected(self):
        changes = [
            lambda d:d.update(typo=True),
            lambda d:d["applications"][0].update(id="workspace; allow=true"),
            lambda d:d["applications"][0].update(ports=[True]),
            lambda d:d["applications"][0].update(ports=[443,443]),
            lambda d:d["applications"][0].update(destinations=["*.127.0.0.1"]),
            lambda d:d["applications"][0].update(destinations=["10.0.1.1/8"]),
            lambda d:d["applications"][0].update(resource_kinds=["workspace_typo"]),
            lambda d:d["access_rules"][1].update(priority=10),
            lambda d:d["access_rules"][1].update(enabled=1),
            lambda d:d["access_rules"][1].update(applications=["unknown"]),
            lambda d:d["access_rules"][1].update(when={"field":"http.headers.x-role","op":"eq","value":"admin"}),
            lambda d:d["access_rules"][1].update(when={"field":{},"op":"eq","value":"admin"}),
            lambda d:d["access_rules"][1].update(when={"field":"identity.attributes.mfa","op":"eq","value":True}),
            lambda d:d["access_rules"][1].update(when={"field":"device.managed","op":"eq","value":1}),
            lambda d:d["access_rules"][1].update(when={"field":"device.age_seconds","op":"lte","value":float("nan")}),
            lambda d:d["access_rules"][1].update(when={"any":[]}),
            lambda d:d["default_timeouts"].update(idle_seconds=0),
            lambda d:d["default_timeouts"].update(max_session_seconds=86401),
        ]
        for change in changes:
            with self.subTest(change=change):
                doc=model(); change(doc)
                with self.assertRaises(ValueError): compile_model(doc,SETTINGS["host"])

    def test_input_is_not_mutated_and_output_is_deterministic(self):
        doc=model(); original=copy.deepcopy(doc)
        first=compile_model(doc,SETTINGS["host"])
        self.assertEqual(doc,original)
        self.assertEqual(first,compile_model(doc,SETTINGS["host"]))

    def test_json_duplicate_keys_and_nonfinite_values_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"input.json"
            for body in ('{"model_version":1,"model_version":1}', '{"value":NaN}'):
                path.write_text(body)
                with self.assertRaises(ValueError): strict_load(path)


class AuthoredPolicySemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.opa=os.environ.get("OPA_BIN","opa")
        version=subprocess.run([cls.opa,"version"],capture_output=True,text=True,check=True)
        if "Version: 0.63.0" not in version.stdout:
            raise RuntimeError("Compiler acceptance requires pinned OPA 0.63.0")

    def evaluate(self,doc=None,req=None,settings=None):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"policy.rego"
            path.write_text(render("ztna",settings or SETTINGS,doc if doc is not None else model()),encoding="utf-8")
            result=subprocess.run([self.opa,"eval","-d",str(path),"--stdin-input","--format=json","data.ztna.decision"],input=json.dumps(req or request()),capture_output=True,text=True,check=True,timeout=20)
            return json.loads(result.stdout)["result"][0]["expressions"][0]["value"]

    def test_default_model_retains_matrix_and_explains_rule_and_conditions(self):
        result=self.evaluate()
        self.assertTrue(result["allow"])
        self.assertEqual(result["application_id"],"workspace")
        self.assertEqual(result["access_rule_id"],"human-application-access")
        self.assertEqual(result["timeout_rule_id"],"default")
        self.assertEqual(result["trace"][0]["result"],"different_application")
        self.assertEqual(result["trace"][1]["result"],"matched")
        self.assertTrue(all(c["matched"] for c in result["trace"][1]["conditions"]))

    def test_allow_rules_cannot_bypass_mandatory_gates(self):
        doc=model(); doc["access_rules"]=[access_rule()]
        changes=[lambda r:r["risk"].update(blocked=True),
                 lambda r:r["risk"].update(level="CRITICAL",score=2),
                 lambda r:r["principal"].update(tenant="ztna-tenant-2"),
                 lambda r:r["resource"].update(tenant="ztna-tenant-2"),
                 lambda r:r["principal"].update(roles=["admin"]),
                 lambda r:r["principal"].update(verified=False),
                 lambda r:r["resource"].update(supported=False),
                 lambda r:r["risk"].update(available=False)]
        for change in changes:
            with self.subTest(change=change):
                req=request(); change(req)
                self.assertFalse(self.evaluate(doc,req)["allow"])

    def test_ordered_deny_disabled_rules_and_no_match(self):
        doc=model(); doc["access_rules"]=[access_rule("deny-first",10,"deny"),access_rule()]
        result=self.evaluate(doc)
        self.assertEqual(result["access_rule_id"],"deny-first")
        self.assertFalse(result["allow"])
        self.assertEqual(result["trace"][1]["result"],"not_reached")
        doc["access_rules"][0]["enabled"]=False
        self.assertTrue(self.evaluate(doc)["allow"])
        doc["access_rules"]=[]
        self.assertFalse(self.evaluate(doc)["allow"])

    def test_exact_application_never_falls_back_to_wildcard(self):
        doc=model(); wide=copy.deepcopy(doc["applications"][0])
        wide.update(id="wide-workspace",destinations=["*.ztna.sc.deeptrustxai.com"])
        doc["applications"].append(wide)
        rule=access_rule(); rule["applications"]=["wide-workspace"]
        doc["access_rules"]=[rule]
        result=self.evaluate(doc)
        self.assertEqual(result["application_id"],"workspace")
        self.assertFalse(result["allow"])

    def test_ambiguous_application_and_wildcard_apex_deny(self):
        doc=model(); duplicate=copy.deepcopy(doc["applications"][0]); duplicate["id"]="duplicate-workspace"
        doc["applications"].append(duplicate)
        self.assertIn("ambiguous_application",self.evaluate(doc)["reasons"])
        doc=model(); doc["applications"][0]["destinations"]=["*."+SETTINGS["host"]]
        self.assertIn("unknown_application",self.evaluate(doc)["reasons"])

    def test_network_selectors_do_not_enable_non_http_adapter(self):
        doc=model(); doc["applications"][0]["protocol"]="udp"
        req=request(); req["http"].update(protocol="udp",port="53")
        doc["applications"][0]["ports"]=[53]
        self.assertIn("invalid_or_untrusted_context",self.evaluate(doc,req)["reasons"])

    def test_cidr_prefix_then_port_specificity_and_exact_address(self):
        doc=model(); doc["applications"][0].update(destinations=["10.0.0.0/8"],ports=[443,8443])
        narrow=copy.deepcopy(doc["applications"][0]); narrow.update(id="narrow-workspace",destinations=["10.2.0.0/16"])
        port_specific=copy.deepcopy(narrow); port_specific.update(id="narrow-port-workspace",ports=[443])
        doc["applications"] += [narrow,port_specific]
        settings=dict(SETTINGS,host="10.2.3.4")
        req=request(); req["http"]["host"]=settings["host"]
        self.assertEqual(self.evaluate(doc,req,settings)["application_id"],"narrow-port-workspace")
        doc["applications"][0]["destinations"]=[settings["host"]]
        self.assertEqual(self.evaluate(doc,req,settings)["application_id"],"workspace")

    def test_longer_dns_suffix_wins(self):
        doc=model(); doc["applications"][0]["destinations"]=["*.deeptrustxai.com"]
        narrow=copy.deepcopy(doc["applications"][0]); narrow.update(id="narrow-workspace",destinations=["*.ztna.sc.deeptrustxai.com"])
        doc["applications"].append(narrow)
        self.assertEqual(self.evaluate(doc)["application_id"],"narrow-workspace")

    def test_nested_conditions_cidr_and_missing_fields(self):
        doc=model(); doc["access_rules"]=[access_rule(when={"all":[
            {"field":"identity.roles","op":"contains_any","value":["viewer"]},
            {"any":[{"field":"context.source_ip","op":"cidr","value":["100.64.0.0/10"]},{"field":"identity.subject","op":"eq","value":"operator"}]}]})]
        self.assertTrue(self.evaluate(doc)["allow"])
        req=request(); req["context"]["source_ip"]="192.0.2.10"
        self.assertFalse(self.evaluate(doc,req)["allow"])
        req["context"]={}
        self.assertFalse(self.evaluate(doc,req)["allow"])

    def posture_model(self):
        doc=model(); doc["access_rules"]=[access_rule(when={"all":[
            {"field":"device.managed","op":"eq","value":True},
            {"field":"device.checks.edr_healthy","op":"eq","value":True},
            {"field":"device.age_seconds","op":"lte","value":60}]})]
        req=request(); req["device"]={"verified":True,"tenant":"ztna","subject":"user-1","session":"session-1","managed":True,"checks":{"edr_healthy":True},"observed_at":NOW-10,"expires_at":NOW+1000}
        return doc,req

    def test_posture_requires_verified_bound_fresh_evidence(self):
        doc,req=self.posture_model()
        self.assertTrue(self.evaluate(doc,req)["allow"])
        changes=[lambda d:d.update(verified=False),lambda d:d.update(tenant="ztna-tenant-2"),lambda d:d.update(subject="other"),lambda d:d.update(session="other"),lambda d:d.update(observed_at=NOW+1),lambda d:d.update(observed_at=NOW-61),lambda d:d.update(expires_at=NOW),lambda d:d.update(managed=1),lambda d:d["checks"].update(edr_healthy=False)]
        for change in changes:
            with self.subTest(change=change):
                bad=copy.deepcopy(req); change(bad["device"])
                self.assertFalse(self.evaluate(doc,bad)["allow"])

    def test_posture_deadline_uses_configured_60_seconds_not_300(self):
        doc,req=self.posture_model()
        result=self.evaluate(doc,req)
        self.assertEqual(result["decision_valid_until"],NOW+50)
        req["now"]+=51
        self.assertFalse(self.evaluate(doc,req)["allow"])

    def test_earlier_deny_becoming_true_also_bounds_validity(self):
        doc,req=self.posture_model()
        doc["access_rules"]=[access_rule("deny-at-age-20",10,"deny",{"field":"device.age_seconds","op":"gte","value":20}),access_rule()]
        result=self.evaluate(doc,req)
        self.assertTrue(result["allow"])
        self.assertEqual(result["decision_valid_until"],NOW+10)
        req["now"]+=10
        self.assertFalse(self.evaluate(doc,req)["allow"])

    def test_absolute_lifetime_is_checked_by_the_evaluator(self):
        doc=model(); doc["default_timeouts"]["max_session_seconds"]=50
        req=request(); req["principal"]["auth_time"]=NOW-100
        result=self.evaluate(doc,req)
        self.assertEqual(result["action"],"reauthenticate")
        self.assertIn("maximum_session_expired",result["reasons"])
        req["principal"].update(issued_at=NOW,expires_at=NOW+10000)
        self.assertFalse(self.evaluate(doc,req)["allow"])

    def test_timeout_order_and_exact_boundaries(self):
        doc=model(); doc["timeout_rules"]=[{"id":"workspace-short","priority":1,"enabled":True,"applications":["workspace"],"application_groups":[],"timeouts":{"reauth_seconds":50,"idle_seconds":10,"max_session_seconds":100}}]
        req=request(); req["principal"]["auth_time"]=NOW-49
        self.assertTrue(self.evaluate(doc,req)["allow"])
        req["principal"]["auth_time"]=NOW-50
        result=self.evaluate(doc,req)
        self.assertEqual(result["action"],"reauthenticate")
        self.assertEqual(result["timeout_rule_id"],"workspace-short")
        req["risk"]["blocked"]=True
        self.assertEqual(self.evaluate(doc,req)["action"],"deny")


if __name__ == "__main__":
    unittest.main(verbosity=2)
