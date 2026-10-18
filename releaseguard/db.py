import json
import os
import sqlite3

DB_PATH = os.environ.get("RG_DB", os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance", "releaseguard.db"))


def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT, branch TEXT, commit_sha TEXT,
        status TEXT, score INTEGER, created_at TEXT, payload TEXT)""")
    return c


def save_report(rep):
    with _conn() as c:
        cur = c.execute("INSERT INTO reports(project,branch,commit_sha,status,score,created_at,payload) VALUES(?,?,?,?,?,?,?)",
                        (rep.get("project"), rep.get("branch"), rep.get("commit"), rep["status"], rep["score"],
                         rep["created_at"], json.dumps(rep)))
        return cur.lastrowid


def list_reports(limit=100):
    with _conn() as c:
        rows = c.execute("SELECT id,project,branch,commit_sha,status,score,created_at FROM reports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_report(rid):
    with _conn() as c:
        r = c.execute("SELECT payload FROM reports WHERE id=?", (rid,)).fetchone()
    return json.loads(r["payload"]) if r else None


def stats():
    reps = list_reports(500)
    total = len(reps)
    return {
        "total": total,
        "approved": sum(r["status"].startswith("APPROVED") for r in reps),
        "blocked": sum(r["status"] == "BLOCKED" for r in reps),
        "avg_score": round(sum(r["score"] for r in reps) / total) if total else 0,
        "trend": [r["score"] for r in reversed(reps[:20])],
    }
