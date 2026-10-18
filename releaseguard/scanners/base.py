"""Shared helpers for all ReleaseGuard scanners."""
import os

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
EXCLUDE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox",
    "dist", "build", ".idea", ".pytest_cache", "instance", ".mypy_cache",
}


_BASE_EXCLUDES = set(EXCLUDE_DIRS)


def set_excludes(extra):
    """Reset the skip-list to defaults plus project-specific directories."""
    EXCLUDE_DIRS.clear()
    EXCLUDE_DIRS.update(_BASE_EXCLUDES)
    EXCLUDE_DIRS.update(extra or [])


def is_excluded(path):
    """True if any folder in this path is on the skip-list (used for external tools)."""
    parts = os.path.normpath(path).replace("\\", "/").split("/")
    return any(part in EXCLUDE_DIRS for part in parts[:-1])


def finding(scanner, severity, title, file=None, line=None,
            recommendation="", tool="builtin", ref=None):
    return {
        "scanner": scanner,
        "severity": severity,
        "title": title,
        "file": file,
        "line": line,
        "recommendation": recommendation,
        "tool": tool,
        "ref": ref,
    }


def iter_files(root, exts=None, names=None, max_size=1_000_000):
    """Yield absolute paths of candidate files, skipping vendor/build dirs."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if exts and not fn.lower().endswith(tuple(exts)):
                if not (names and fn in names):
                    continue
            try:
                if os.path.getsize(full) > max_size:
                    continue
            except OSError:
                continue
            yield full


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def rel(path, root):
    return os.path.relpath(path, root).replace("\\", "/")


def make_result(name, tool, findings, status=None, note=""):
    if status is None:
        sevs = {f["severity"] for f in findings}
        if sevs & {"CRITICAL", "HIGH"}:
            status = "FAIL"
        elif sevs & {"MEDIUM", "LOW"}:
            status = "WARN"
        else:
            status = "PASS"
    return {"name": name, "tool": tool, "status": status,
            "findings": findings, "note": note}