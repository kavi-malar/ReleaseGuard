"""Build & test verification: runs the project's own test-suite."""
import json
import os
import subprocess
import sys

from .base import finding, iter_files, make_result


def _run(cmd, cwd, timeout=180):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)[-600:]
    except subprocess.TimeoutExpired:
        return 124, "Test run timed out"
    except FileNotFoundError as e:
        return 127, str(e)


def scan(root, run_tests=True, **_):
    if not run_tests:
        return make_result("Build & Test Verification", "pytest/npm", [], status="SKIPPED",
                           note="Test execution disabled for this scan.")
    out, ran = [], False
    has_py_tests = os.path.isdir(os.path.join(root, "tests")) or any(
        os.path.basename(p).startswith("test_") for p in iter_files(root, exts=(".py",)))
    if has_py_tests:
        ran = True
        code, tail = _run([sys.executable, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider"], root)
        if code == 5:
            out.append(finding("build_test", "MEDIUM", "pytest collected no tests", None, None, "Add unit tests."))
        elif code != 0:
            out.append(finding("build_test", "HIGH", "Automated tests failed", None, None,
                               "Fix failing tests before deploying. Output tail: " + tail.strip().replace("\n", " | ")[-300:]))
    pkg = os.path.join(root, "package.json")
    if os.path.exists(pkg):
        try:
            scripts = json.load(open(pkg)).get("scripts", {})
        except ValueError:
            scripts = {}
        if "test" in scripts and os.path.isdir(os.path.join(root, "node_modules")):
            ran = True
            code, tail = _run(["npm", "test", "--silent"], root)
            if code != 0:
                out.append(finding("build_test", "HIGH", "npm test failed", None, None, tail.strip()[-300:]))
    if not ran:
        out.append(finding("build_test", "MEDIUM", "No automated tests found", None, None,
                           "Add a test-suite so releases can be verified automatically."))
    return make_result("Build & Test Verification", "pytest/npm", out)
