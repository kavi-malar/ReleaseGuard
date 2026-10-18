import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app import app, add


def test_add():
    assert add(2, 3) == 5


def test_health():
    assert app.test_client().get("/health").json == {"status": "ok"}
