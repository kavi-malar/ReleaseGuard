"""ReleaseGuard web dashboard + REST API."""
import os
import re
import shutil
import subprocess
import tempfile

from flask import Flask, abort, jsonify, render_template, request

from . import db
from .engine import run_scan

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "sample_projects")
GITHUB_RX = re.compile(r"^https://github\.com/[\w.\-]+/[\w.\-]+?(\.git)?/?$")


def create_app():
    app = Flask(__name__)

    def _auth():
        key = os.environ.get("RG_API_KEY")
        if key and request.headers.get("X-API-Key") != key:
            abort(401)

    @app.get("/")
    def index():
        return render_template("dashboard.html", samples=sorted(os.listdir(SAMPLES)) if os.path.isdir(SAMPLES) else [])

    @app.get("/report/<int:rid>")
    def report_page(rid):
        rep = db.get_report(rid)
        if not rep:
            abort(404)
        return render_template("report.html", r=rep, rid=rid)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/reports")
    def reports():
        return jsonify(db.list_reports())

    @app.get("/api/reports/<int:rid>")
    def report_json(rid):
        rep = db.get_report(rid)
        return (jsonify(rep), 200) if rep else abort(404)

    @app.get("/api/stats")
    def stats():
        return jsonify(db.stats())

    @app.post("/api/reports")
    def ingest():
        """CI pipelines (GitHub Actions) POST their finished report here."""
        _auth()
        rep = request.get_json(silent=True)
        if not rep or "status" not in rep or "score" not in rep:
            abort(400, "invalid report")
        return jsonify({"id": db.save_report(rep)}), 201

    @app.post("/api/scan")
    def trigger_scan():
        """Dashboard-triggered scan of a bundled sample or a public GitHub repo."""
        body = request.get_json(silent=True) or {}
        tmp = None
        try:
            if body.get("sample"):
                name = os.path.basename(body["sample"])
                path = os.path.join(SAMPLES, name)
                if not os.path.isdir(path):
                    abort(404, "unknown sample")
                run_tests = name == "clean_app"
                rep = run_scan(path, project=name, branch="local", commit="demo", run_tests=run_tests)
            elif body.get("repo_url"):
                url = body["repo_url"].strip()
                if not GITHUB_RX.match(url):
                    abort(400, "only public https://github.com/<owner>/<repo> URLs are allowed")
                tmp = tempfile.mkdtemp()
                subprocess.run(["git", "clone", "--depth", "1", url, tmp], check=True,
                               capture_output=True, timeout=120)
                # Tests of third-party code are NOT executed on the server.
                rep = run_scan(tmp, project=url.rstrip("/").split("/")[-1].removesuffix(".git"),
                               branch="default", run_tests=False)
            else:
                abort(400, "provide 'sample' or 'repo_url'")
        except subprocess.CalledProcessError:
            abort(400, "could not clone repository")
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)
        rid = db.save_report(rep)
        return jsonify({"id": rid, "status": rep["status"], "score": rep["score"]}), 201

    return app
