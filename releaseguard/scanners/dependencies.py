"""Dependency vulnerability scanning: Trivy (if installed) else offline advisory list."""
import json
import os
import re
import shutil
import subprocess

from .base import EXCLUDE_DIRS, finding, iter_files, read_text, rel, make_result

# Small offline advisory list so the demo works without internet / Trivy.
# For real coverage install Trivy - ReleaseGuard uses it automatically.
ADVISORIES = {
    "pypi": {
        "pyyaml": [("5.4", "CRITICAL", "CVE-2020-14343", "Arbitrary code execution via full_load")],
        "flask": [("2.2.5", "HIGH", "CVE-2023-30861", "Session cookie disclosure behind caching proxies")],
        "requests": [("2.31.0", "MEDIUM", "CVE-2023-32681", "Proxy-Authorization header leak on redirect")],
        "django": [("3.2.24", "HIGH", "CVE-2024-24680", "Denial of service in intcomma filter")],
        "jinja2": [("3.1.3", "MEDIUM", "CVE-2024-22195", "XSS via xmlattr filter")],
        "urllib3": [("1.26.18", "MEDIUM", "CVE-2023-45803", "Request body not stripped on redirect")],
        "pillow": [("10.0.1", "HIGH", "CVE-2023-4863", "libwebp heap buffer overflow")],
    },
    "npm": {
        "lodash": [("4.17.21", "HIGH", "CVE-2021-23337", "Command injection via template()")],
        "minimist": [("1.2.6", "CRITICAL", "CVE-2021-44906", "Prototype pollution")],
        "express": [("4.19.2", "MEDIUM", "CVE-2024-29041", "Open redirect in res.location")],
        "axios": [("1.6.0", "HIGH", "CVE-2023-45857", "CSRF token exposure")],
    },
}


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def _check(eco, name, version, file, line):
    out = []
    for fixed, sev, cve, summary in ADVISORIES[eco].get(name.lower(), []):
        if vtuple(version) < vtuple(fixed):
            out.append(finding(
                "dependencies", sev, f"{name} {version} - {cve}: {summary}", file, line,
                f"Upgrade {name} to {fixed} or later.", tool="builtin-advisories", ref=cve))
    return out


def _builtin(root):
    out = []
    for path in iter_files(root, names={"requirements.txt", "package.json"}):
        fn = os.path.basename(path)
        if fn == "requirements.txt":
            for no, line in enumerate(read_text(path).splitlines(), 1):
                m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(==|~=)\s*([0-9][^\s;,#]*)", line)
                if m:
                    out += _check("pypi", m.group(1), m.group(3), rel(path, root), no)
        elif fn == "package.json":
            try:
                data = json.loads(read_text(path))
            except ValueError:
                continue
            for sect in ("dependencies", "devDependencies"):
                for name, ver in (data.get(sect) or {}).items():
                    if re.search(r"\d", ver):
                        out += _check("npm", name, ver, rel(path, root), None)
    return out


def _trivy(root):
    exe = shutil.which("trivy")
    if not exe:
        return None
    try:
        skip = [a for d in sorted(EXCLUDE_DIRS) for a in ("--skip-dirs", f"**/{d}")]
        p = subprocess.run([exe, "fs", "--quiet", "--format", "json", "--scanners", "vuln", *skip, root],
                           capture_output=True, text=True, timeout=300)
        data = json.loads(p.stdout or "{}")
    except Exception:
        return None
    out = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "MEDIUM").upper()
            fixed = v.get("FixedVersion")
            out.append(finding(
                "dependencies", sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "INFO",
                f"{v.get('PkgName')} {v.get('InstalledVersion')} - {v.get('VulnerabilityID')}: {v.get('Title', '')}",
                res.get("Target"), None,
                f"Upgrade to {fixed}." if fixed else "No fixed version yet - consider an alternative package.",
                tool="trivy", ref=v.get("VulnerabilityID")))
    return out


def scan(root, **_):
    t = _trivy(root)
    if t is not None:
        return make_result("Dependency Vulnerabilities", "trivy", t)
    return make_result("Dependency Vulnerabilities", "builtin-advisories", _builtin(root),
                       note="Trivy not found - used offline advisory list (limited coverage).")