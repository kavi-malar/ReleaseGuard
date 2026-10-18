"""Orchestrates all scanners and produces the deployment-readiness decision."""
import json
import os
import time
from datetime import datetime, timezone

from .scanners import secrets, dependencies, quality, dockerfile, image, build_test
from .scanners.base import SEV_ORDER, set_excludes

DEFAULT_CONFIG = {
    "block_on": ["CRITICAL", "HIGH"],   # any finding of these severities blocks the release
    "min_score": 60,                    # score below this also blocks
    "exclude_dirs": [],                 # extra directories to skip
    "weights": {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0},
}
SCANNERS = [secrets, dependencies, quality, dockerfile, image, build_test]


def load_config(root):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    path = os.path.join(root, "releaseguard.json")
    if os.path.exists(path):
        try:
            cfg.update(json.load(open(path)))
        except ValueError:
            pass
    return cfg


def run_scan(path, project=None, commit=None, branch=None, run_tests=True, image_name=None, config=None):
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise FileNotFoundError(f"Path not found: {root}")
    cfg = config or load_config(root)
    set_excludes(cfg.get("exclude_dirs"))
    started = time.time()
    checks = []
    for mod in SCANNERS:
        try:
            checks.append(mod.scan(root, run_tests=run_tests, image=image_name))
        except Exception as exc:  # a crashing scanner must never silently approve a release
            checks.append({"name": mod.__name__.split(".")[-1], "tool": "internal", "status": "FAIL",
                           "findings": [{"scanner": mod.__name__, "severity": "HIGH",
                                         "title": f"Scanner crashed: {exc}", "file": None, "line": None,
                                         "recommendation": "Investigate scanner failure.", "tool": "internal", "ref": None}],
                           "note": ""})
    all_f = [f for c in checks for f in c["findings"]]
    counts = {s: sum(1 for f in all_f if f["severity"] == s) for s in SEV_ORDER}
    score = max(0, 100 - sum(cfg["weights"].get(s, 0) * n for s, n in counts.items()))
    blockers = [f for f in all_f if f["severity"] in cfg["block_on"]]

    if blockers or score < cfg["min_score"]:
        status = "BLOCKED"
    elif counts["MEDIUM"] or counts["LOW"]:
        status = "APPROVED_WITH_WARNINGS"
    else:
        status = "APPROVED"

    blockers.sort(key=lambda f: SEV_ORDER.index(f["severity"]))
    recs = []
    for f in blockers + [x for x in all_f if x not in blockers]:
        if f["recommendation"] and f["recommendation"] not in recs:
            recs.append(f["recommendation"])
    return {
        "project": project or os.path.basename(root),
        "commit": commit, "branch": branch,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_sec": round(time.time() - started, 2),
        "status": status, "score": score, "counts": counts,
        "reason": _reason(status, blockers, score, cfg),
        "checks": checks, "blockers": blockers, "recommendations": recs[:15],
    }


def _reason(status, blockers, score, cfg):
    if status == "BLOCKED":
        if blockers:
            return f"Deployment blocked: {len(blockers)} blocking issue(s) ({'/'.join(cfg['block_on'])}) found."
        return f"Deployment blocked: readiness score {score} is below the minimum {cfg['min_score']}."
    if status == "APPROVED_WITH_WARNINGS":
        return "Deployment approved - non-blocking warnings should be addressed soon."
    return "All validation checks passed. Deployment approved."

KEY = "AKIAIOSFODNN7EXAMPLE"