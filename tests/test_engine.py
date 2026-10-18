import os
import pytest
from releaseguard.engine import run_scan
from releaseguard.scanners.dependencies import vtuple
from releaseguard.app import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "sample_projects")


def test_version_compare():
    assert vtuple("1.0.2") < vtuple("2.2.5")
    assert vtuple("4.17.21") == vtuple("4.17.21")


def test_vulnerable_app_is_blocked():
    rep = run_scan(os.path.join(SAMPLES, "vulnerable_app"), run_tests=False)
    assert rep["status"] == "BLOCKED"
    names = {c["name"]: c for c in rep["checks"]}
    assert names["Secret Scanning"]["status"] == "FAIL"
    assert names["Dependency Vulnerabilities"]["findings"]
    assert names["Dockerfile Validation"]["findings"]
    assert rep["recommendations"]


def test_clean_app_is_approved():
    rep = run_scan(os.path.join(SAMPLES, "clean_app"), run_tests=False)
    assert rep["status"] in ("APPROVED", "APPROVED_WITH_WARNINGS")
    assert rep["counts"]["CRITICAL"] == 0 and rep["counts"]["HIGH"] == 0


def test_clean_app_tests_actually_run():
    rep = run_scan(os.path.join(SAMPLES, "clean_app"), run_tests=True)
    bt = [c for c in rep["checks"] if c["name"].startswith("Build")][0]
    assert bt["status"] == "PASS"


@pytest.fixture
def client(tmp_path, monkeypatch):
    from releaseguard import db
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "t.db"))
    return create_app().test_client()


def test_api_flow(client):
    assert client.get("/api/health").json["status"] == "ok"
    r = client.post("/api/scan", json={"sample": "vulnerable_app"})
    assert r.status_code == 201 and r.json["status"] == "BLOCKED"
    assert client.get("/api/stats").json["blocked"] == 1
    assert client.get(f"/report/{r.json['id']}").status_code == 200
    assert client.get("/").status_code == 200


def test_rejects_bad_repo_url(client):
    assert client.post("/api/scan", json={"repo_url": "file:///etc"}).status_code == 400
