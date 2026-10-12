import os
import tempfile

# Must be set before the app is imported.
_db_file = os.path.join(tempfile.mkdtemp(), "test_portal.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_db_file}"
os.environ["PORTAL_API_KEY"] = "test-key"

import pytest
from fastapi.testclient import TestClient

from app import models
from app.auth import hash_password
from app.database import Base, SessionLocal, engine
from app.main import app


def add_user(email, role="manager", projects="", name=None, password="password123"):
    with SessionLocal() as db:
        u = models.User(email=email, name=name or email.split("@")[0], role=role, projects=projects,
                        password_hash=hash_password(password))
        db.add(u)
        db.commit()
        return u.id


def sign_in(client, email, password="password123"):
    token = client.post("/api/auth/login", json={"email": email, "password": password}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def client():
    """A client signed in as a manager (sees every project). Use anon_client for a signed-out one."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    add_user("boss@example.com")
    with TestClient(app) as c:
        c.headers.update(sign_in(c, "boss@example.com"))
        yield c


AUTH = {"X-API-Key": "test-key"}


def scan_payload(findings, run_id="100", tool="semgrep", tool_type="SAST"):
    return {
        "repo": "team/demo",
        "branch": "main",
        "commit_sha": "abc123",
        "run_id": run_id,
        "tool": tool,
        "tool_type": tool_type,
        "findings": findings,
    }


def finding(rule="py.sql-injection", severity="high", file="app.py", line=10):
    return {
        "rule_id": rule,
        "title": rule,
        "severity": severity,
        "cwe": "CWE-89",
        "file": file,
        "line": line,
    }
