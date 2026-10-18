"""Secret detection: built-in regex rules + Gitleaks (if installed)."""
import json
import os
import re
import shutil
import subprocess
import tempfile

from .base import finding, is_excluded, iter_files, read_text, rel, make_result

RULES = [
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CRITICAL"),
    ("GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "CRITICAL"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "CRITICAL"),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "HIGH"),
    ("Hard-coded credential",
     re.compile(r"""(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["']([^"'\s]{8,})["']"""),
     "HIGH"),
]
PLACEHOLDERS = ("changeme", "example", "your_", "your-", "<", "${", "xxxx",
                "os.environ", "getenv", "placeholder", "dummy", "test")
SKIP_FILES = {"package-lock.json", "yarn.lock", "poetry.lock", ".env.example"}
TEXT_EXTS = (".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".cfg", ".ini",
             ".conf", ".properties", ".sh", ".txt", ".md", ".toml", ".xml", ".java",
             ".go", ".rb", ".php", ".tf", ".pem", ".key")


def _redact(text):
    text = text.strip()
    return text[:4] + "…" + "*" * 6 if len(text) > 8 else "******"


def _builtin(root):
    out = []
    for path in iter_files(root, exts=TEXT_EXTS, names={"Dockerfile", ".env"}):
        if os.path.basename(path) in SKIP_FILES:
            continue
        for no, line in enumerate(read_text(path).splitlines(), 1):
            low = line.lower()
            for title, rx, sev in RULES:
                m = rx.search(line)
                if not m:
                    continue
                if title == "Hard-coded credential" and any(p in m.group(2).lower() for p in PLACEHOLDERS):
                    continue
                out.append(finding(
                    "secrets", sev, f"{title} detected ({_redact(m.group(0))})",
                    rel(path, root), no,
                    "Remove the secret from source, rotate it immediately, and load it "
                    "from an environment variable or secret manager (e.g. GitHub Secrets).",
                    tool="builtin-regex"))
                break
    return out


def _gitleaks(root):
    exe = shutil.which("gitleaks")
    if not exe:
        return None
    report = os.path.join(tempfile.mkdtemp(), "gitleaks.json")
    try:
        subprocess.run([exe, "detect", "--no-git", "--source", root,
                        "--report-format", "json", "--report-path", report,
                        "--exit-code", "0"], capture_output=True, timeout=180)
        data = json.load(open(report)) if os.path.exists(report) else []
    except Exception:
        return None
    return [finding("secrets", "CRITICAL",
                    f"{d.get('Description', d.get('RuleID'))} (rule {d.get('RuleID')})",
                    rel(d.get("File", ""), root) if d.get("File") else None,
                    d.get("StartLine"),
                    "Rotate the leaked credential and remove it from the repository history.",
                    tool="gitleaks") for d in (data or [])
            if not (d.get("File") and is_excluded(rel(d["File"], root)))]


def scan(root, **_):
    found = _builtin(root)
    tool = "builtin-regex"
    extra = _gitleaks(root)
    if extra is not None:
        tool = "gitleaks + builtin-regex"
        seen = {(f["file"], f["line"]) for f in found}
        found += [f for f in extra if (f["file"], f["line"]) not in seen]
    return make_result("Secret Scanning", tool, found)