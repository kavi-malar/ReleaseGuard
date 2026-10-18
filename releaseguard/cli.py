"""ReleaseGuard command line: the CI/CD gate.  Exit code 1 = deployment BLOCKED."""
import argparse
import json
import os
import sys
import urllib.request

from .engine import run_scan

COL = {"CRITICAL": "\033[91m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[96m", "INFO": "", "END": "\033[0m"}


def render_html(rep):
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")), autoescape=True)
    return env.get_template("report.html").render(r=rep, rid=None)


def print_text(rep):
    print(f"\n=== ReleaseGuard report: {rep['project']} ===")
    for c in rep["checks"]:
        print(f"[{c['status']:<7}] {c['name']}  ({c['tool']})  - {len(c['findings'])} finding(s)"
              + (f"  [{c['note']}]" if c["note"] else ""))
        for f in c["findings"]:
            loc = f"{f['file']}:{f['line']}" if f["file"] and f["line"] else (f["file"] or "")
            print(f"    {COL[f['severity']]}{f['severity']:<8}{COL['END']} {f['title']}  {loc}")
    print(f"\nScore : {rep['score']}/100\nStatus: {rep['status']}\n{rep['reason']}")
    if rep["recommendations"]:
        print("\nRecommended actions:")
        for r in rep["recommendations"][:8]:
            print("  -", r)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="releaseguard", description="Secure release validation gate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a project directory")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--project"); s.add_argument("--commit"); s.add_argument("--branch")
    s.add_argument("--image", help="docker image to scan with Trivy")
    s.add_argument("--skip-tests", action="store_true")
    s.add_argument("--json", dest="json_out", help="write JSON report to file")
    s.add_argument("--html", dest="html_out", help="write HTML report to file")
    s.add_argument("--server", help="dashboard URL, e.g. http://localhost:5000")
    s.add_argument("--api-key", default=os.environ.get("RG_API_KEY"))
    a = ap.parse_args(argv)

    rep = run_scan(a.path, a.project, a.commit, a.branch, run_tests=not a.skip_tests, image_name=a.image)
    print_text(rep)
    if a.json_out:
        json.dump(rep, open(a.json_out, "w"), indent=2)
    if a.html_out:
        open(a.html_out, "w", encoding="utf-8").write(render_html(rep))
    if a.server:
        req = urllib.request.Request(a.server.rstrip("/") + "/api/reports", data=json.dumps(rep).encode(),
                                     headers={"Content-Type": "application/json", **({"X-API-Key": a.api_key} if a.api_key else {})})
        try:
            urllib.request.urlopen(req, timeout=15)
            print(f"\nReport uploaded to {a.server}")
        except Exception as e:
            print(f"\nWarning: could not upload report: {e}", file=sys.stderr)
    return 1 if rep["status"] == "BLOCKED" else 0


if __name__ == "__main__":
    sys.exit(main())
