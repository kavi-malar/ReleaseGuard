"""Code quality + insecure-pattern analysis. Also queries SonarQube when configured."""
import ast
import base64
import json
import os
import re
import urllib.request

from .base import finding, iter_files, read_text, rel, make_result

BRANCH_NODES = (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.BoolOp, ast.IfExp, ast.comprehension)
MAX_COMPLEXITY, MAX_LENGTH = 15, 80
JS_PATTERNS = [
    (re.compile(r"\beval\s*\("), "HIGH", "Use of eval()", "Avoid eval(); parse data with JSON.parse or use safe APIs."),
    (re.compile(r"\.innerHTML\s*="), "MEDIUM", "Assignment to innerHTML (XSS risk)", "Use textContent or sanitise the input."),
]


def _py_file(path, root):
    out, f = [], rel(path, root)
    src = read_text(path)
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return [finding("quality", "HIGH", f"Syntax error: {e.msg}", f, e.lineno, "Fix the syntax error - the build will fail.")]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cx = 1 + sum(isinstance(n, BRANCH_NODES) for n in ast.walk(node))
            length = (node.end_lineno or node.lineno) - node.lineno + 1
            if cx > MAX_COMPLEXITY:
                out.append(finding("quality", "MEDIUM", f"Function '{node.name}' is too complex (complexity {cx})", f, node.lineno, "Split into smaller functions."))
            if length > MAX_LENGTH:
                out.append(finding("quality", "LOW", f"Function '{node.name}' is {length} lines long", f, node.lineno, "Refactor into smaller units."))
        elif isinstance(node, ast.ExceptHandler) and node.type is None:
            out.append(finding("quality", "LOW", "Bare 'except:' swallows all errors", f, node.lineno, "Catch specific exceptions."))
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else "")
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            if name in ("eval", "exec") and isinstance(fn, ast.Name):
                out.append(finding("quality", "HIGH", f"Dangerous call to {name}()", f, node.lineno, "Never evaluate untrusted input; use ast.literal_eval or explicit parsing."))
            if isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True:
                out.append(finding("quality", "HIGH", "subprocess call with shell=True", f, node.lineno, "Pass an argument list and omit shell=True."))
            if name == "loads" and isinstance(fn, ast.Attribute) and getattr(fn.value, "id", "") == "pickle":
                out.append(finding("quality", "HIGH", "pickle.loads on possibly untrusted data", f, node.lineno, "Use JSON or another safe format."))
            if name == "load" and getattr(getattr(fn, "value", None), "id", "") == "yaml" and "Loader" not in kw:
                out.append(finding("quality", "MEDIUM", "yaml.load without an explicit Loader", f, node.lineno, "Use yaml.safe_load."))
            if isinstance(kw.get("verify"), ast.Constant) and kw["verify"].value is False:
                out.append(finding("quality", "MEDIUM", "TLS verification disabled (verify=False)", f, node.lineno, "Keep certificate verification enabled."))
            if name == "run" and isinstance(kw.get("debug"), ast.Constant) and kw["debug"].value is True:
                out.append(finding("quality", "MEDIUM", "Flask debug mode enabled", f, node.lineno, "Never enable debug mode in production."))
    return out


def _sonar():
    host, token, key = (os.environ.get(k) for k in ("SONAR_HOST_URL", "SONAR_TOKEN", "SONAR_PROJECT_KEY"))
    if not (host and token and key):
        return None
    try:
        req = urllib.request.Request(f"{host.rstrip('/')}/api/qualitygates/project_status?projectKey={key}")
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{token}:".encode()).decode())
        with urllib.request.urlopen(req, timeout=15) as r:
            st = json.load(r)["projectStatus"]
    except Exception as e:
        return [finding("quality", "LOW", f"SonarQube unreachable: {e}", None, None, "Check SONAR_HOST_URL / SONAR_TOKEN.", tool="sonarqube")]
    if st.get("status") == "OK":
        return []
    failed = [c for c in st.get("conditions", []) if c.get("status") == "ERROR"]
    msg = ", ".join(c["metricKey"] for c in failed) or "quality gate failed"
    return [finding("quality", "HIGH", f"SonarQube quality gate failed ({msg})", None, None,
                    "Open the SonarQube project and fix the failing conditions.", tool="sonarqube")]


def scan(root, **_):
    out, tool = [], "builtin-ast"
    for p in iter_files(root, exts=(".py", ".js")):
        if p.endswith(".py"):
            out += _py_file(p, root)
        else:
            for no, line in enumerate(read_text(p).splitlines(), 1):
                for rx, sev, title, rec in JS_PATTERNS:
                    if rx.search(line):
                        out.append(finding("quality", sev, title, rel(p, root), no, rec))
    s = _sonar()
    if s is not None:
        out += s
        tool = "builtin-ast + sonarqube"
    return make_result("Code Quality & Static Analysis", tool, out)
