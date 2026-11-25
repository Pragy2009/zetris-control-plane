"""Run pinned OPA tests and explicitly reject empty, failed or skipped suites."""
import argparse
import json
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--opa", default="opa")
parser.add_argument("--report", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent
consistency = subprocess.run([sys.executable, str(root / "render.py"), "--check"], capture_output=True, text=True)
if consistency.returncode:
    print(consistency.stdout + consistency.stderr)
    raise SystemExit(consistency.returncode)
result = subprocess.run([args.opa, "test", str(root), "--format=json"], capture_output=True, text=True)
if result.returncode:
    print(result.stdout + result.stderr)
    raise SystemExit(result.returncode)
tests = json.loads(result.stdout)
if not tests or any(t.get("fail") or t.get("error") or t.get("skip") for t in tests):
    raise SystemExit("OPA suite empty, failed or skipped")
matrix = subprocess.run([args.opa, "eval", "-d", str(root), "--format=raw", "count(data.access_v1_test.matrix) * 6 * 2"], capture_output=True, text=True, check=True)
cells = int(matrix.stdout.strip())
if cells < 1:
    raise SystemExit("Permission matrix empty")
report = {"named_rego_tests_passed":len(tests), "role_action_tenant_matrix_cells":cells, "tests":tests}
os.environ["OPA_BIN"] = args.opa
stream = io.StringIO()
compiler_tests = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.defaultTestLoader.discover(str(root), pattern="test_application_model.py"))
if not compiler_tests.wasSuccessful() or not compiler_tests.testsRun or compiler_tests.skipped:
    print(stream.getvalue())
    raise SystemExit("Authoring/compiler suite empty, failed or skipped")
report.update(authoring_compiler_tests_passed=compiler_tests.testsRun, authoring_compiler_log=stream.getvalue())
if args.report:
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
print(f"PASS: {len(tests)} Rego tests, including {cells} role/action/tenant matrix cells; {compiler_tests.testsRun} authoring/compiler tests; no skips")
