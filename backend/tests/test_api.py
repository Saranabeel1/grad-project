from conftest import AUTH, finding, scan_payload


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_ingest_requires_api_key(client):
    r = client.post("/api/ingest/scan", json=scan_payload([finding()]))
    assert r.status_code == 401
    r = client.post("/api/ingest/scan", json=scan_payload([finding()]), headers={"X-API-Key": "wrong"})
    assert r.status_code == 401


def test_ingest_creates_findings(client):
    r = client.post("/api/ingest/scan", json=scan_payload([finding(), finding("py.xss", "medium", line=20)]), headers=AUTH)
    assert r.status_code == 200
    assert r.json() == {"created": 2, "updated": 0}
    assert len(client.get("/api/findings").json()) == 2


def test_rescan_does_not_duplicate(client):
    payload = scan_payload([finding()])
    client.post("/api/ingest/scan", json=payload, headers=AUTH)
    r = client.post("/api/ingest/scan", json={**payload, "run_id": "101"}, headers=AUTH)
    assert r.json() == {"created": 0, "updated": 1}
    findings = client.get("/api/findings").json()
    assert len(findings) == 1
    assert findings[0]["run_id"] == "101"


def test_duplicates_inside_one_payload(client):
    r = client.post("/api/ingest/scan", json=scan_payload([finding(), finding()]), headers=AUTH)
    assert r.json() == {"created": 1, "updated": 1}


def test_invalid_severity_rejected(client):
    r = client.post("/api/ingest/scan", json=scan_payload([finding(severity="scary")]), headers=AUTH)
    assert r.status_code == 422


def test_findings_filters_and_order(client):
    client.post(
        "/api/ingest/scan",
        json=scan_payload(
            [
                finding("a", "low", line=1),
                finding("b", "critical", line=2),
                finding("c", "high", line=3),
            ]
        ),
        headers=AUTH,
    )
    ordered = [f["severity"] for f in client.get("/api/findings").json()]
    assert ordered == ["critical", "high", "low"]
    assert len(client.get("/api/findings?severity=high").json()) == 1
    assert len(client.get("/api/findings?tool_type=DAST").json()) == 0


def test_run_upsert_and_list(client):
    run = {"repo": "team/demo", "run_id": "100", "branch": "main", "commit_sha": "abc123", "status": "in_progress"}
    client.post("/api/ingest/run", json=run, headers=AUTH)
    client.post("/api/ingest/run", json={**run, "status": "success"}, headers=AUTH)
    runs = client.get("/api/runs").json()
    assert len(runs) == 1
    assert runs[0]["status"] == "success"


def test_summary(client):
    client.post(
        "/api/ingest/scan",
        json=scan_payload([finding("a", "critical", line=1), finding("b", "high", line=2), finding("c", "high", line=3)]),
        headers=AUTH,
    )
    client.post(
        "/api/ingest/run",
        json={"repo": "team/demo", "run_id": "100", "branch": "main", "commit_sha": "abc123", "status": "success"},
        headers=AUTH,
    )
    s = client.get("/api/summary").json()
    assert s["open_findings"] == 3
    assert s["critical_open"] == 1
    assert s["by_severity"]["high"] == 2
    assert s["last_run"]["status"] == "success"


def test_past_runs_keep_their_real_dates(client):
    old = {**scan_payload([finding()], run_id="1"), "scanned_at": "2023-09-01T10:00:00Z"}
    new = {**scan_payload([finding()], run_id="2"), "scanned_at": "2023-09-08T10:00:00Z"}
    client.post("/api/ingest/scan", json=new, headers=AUTH)
    client.post("/api/ingest/scan", json=old, headers=AUTH)  # arrives late
    f = client.get("/api/findings").json()[0]
    assert f["first_seen"].startswith("2023-09-01")
    assert f["last_seen"].startswith("2023-09-08")
    assert f["run_id"] == "2"  # the newest run stays the latest


def test_run_started_at(client):
    run = {"repo": "team/demo", "run_id": "7", "branch": "main", "commit_sha": "abc", "status": "success",
           "started_at": "2023-10-22T02:12:37Z"}
    client.post("/api/ingest/run", json=run, headers=AUTH)
    assert client.get("/api/runs").json()[0]["started_at"].startswith("2023-10-22T02:12:37")


def test_findings_search_tool_filter_and_total(client):
    client.post("/api/ingest/scan", json=scan_payload([finding("py.sql-injection"), finding("py.eval", line=20)]), headers=AUTH)
    client.post("/api/ingest/scan", json=scan_payload([finding("CVE-1", file="requirements.txt")], tool="trivy", tool_type="SCA"), headers=AUTH)
    r = client.get("/api/findings", params={"tool": "trivy"})
    assert [f["rule_id"] for f in r.json()] == ["CVE-1"]
    r = client.get("/api/findings", params={"q": "EVAL", "limit": 1})
    assert len(r.json()) == 1 and r.headers["x-total-count"] == "1"
    assert client.get("/api/findings", params={"limit": 1}).headers["x-total-count"] == "3"


def test_dashboard(client):
    old = {**scan_payload([finding("a", severity="critical"), finding("b", line=2)], run_id="1"), "scanned_at": "2026-10-01T00:00:00Z"}
    new = {**scan_payload([finding("a", severity="critical")], run_id="2"), "scanned_at": "2026-10-03T00:00:00Z"}
    client.post("/api/ingest/scan", json=old, headers=AUTH)
    client.post("/api/ingest/scan", json=new, headers=AUTH)
    other = scan_payload([finding("x", severity="low")], tool="trivy", tool_type="SCA")
    other["repo"] = "team/other"
    client.post("/api/ingest/scan", json=other, headers=AUTH)
    for run_id, status in [("1", "success"), ("2", "failure")]:
        client.post("/api/ingest/run", json={"repo": "team/demo", "run_id": run_id, "branch": "main",
                                             "commit_sha": "abc", "status": status}, headers=AUTH)

    d = client.get("/api/dashboard", params={"repo": "team/demo"}).json()
    assert d["projects"] == ["team/demo", "team/other"]
    assert d["open_findings"] == 2 and d["critical_open"] == 1
    assert d["still_reported"] == 1 and d["resolved"] == 1  # "b" missing from the latest scan
    assert d["mean_days_to_fix"] == 0.0
    assert d["pass_rate"] == 50
    assert d["by_tool"][0]["tool"] == "semgrep" and d["by_tool"][0]["total"] == 2
    assert [t["date"] for t in d["trend"]] == ["2026-10-01", "2026-10-02", "2026-10-03"]
    assert d["trend"][0]["high"] == 1 and d["trend"][2]["high"] == 0 and d["trend"][2]["critical"] == 1
    assert [c["repo"] for c in d["compare"]] == ["team/demo", "team/other"]
    assert client.get("/api/dashboard").json()["open_findings"] == 3


def test_risk_insights(client):
    sqli = {"rule_id": "py.sqli", "title": "SQL injection", "severity": "high", "cwe": "CWE-89", "file": "app.py"}
    for repo in ["Project A", "Project B"]:
        p = scan_payload([{**sqli, "line": 1}])
        p["repo"] = repo
        client.post("/api/ingest/scan", json=p, headers=AUTH)
    for i in range(3):
        client.post("/api/ingest/run", json={"repo": "Project B", "run_id": str(i), "branch": "main", "commit_sha": "c",
                                             "status": "failure", "started_at": f"2026-10-0{i + 1}T00:00:00Z"}, headers=AUTH)
    d = client.get("/api/dashboard").json()
    titles = [i["title"] for i in d["insights"]]
    assert "SQL injection in 2 projects" in titles
    assert "Project B failed 3 runs in a row" in titles
    assert d["repeated_types"][0] == {"type": "SQL injection", "count": 2}
    b = next(c for c in d["compare"] if c["repo"] == "Project B")
    assert b["last_run"] == "failure" and b["pass_rate"] == 0


def test_auto_fetch_needs_repo_and_token(monkeypatch):
    from app import auto_fetch
    monkeypatch.delenv("AUTO_FETCH_REPO", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert auto_fetch.start() is None
    monkeypatch.setenv("AUTO_FETCH_REPO", "me/repo")
    assert auto_fetch.settings() is None  # still no token
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    cmd = auto_fetch.command(auto_fetch.settings())
    assert cmd[1].endswith("fetch_daily.py") and cmd[2:] == ["--repo", "me/repo", "--send", "http://127.0.0.1:8000", "test-key"]


# ---------------------------------------------------------------- sign in and the developer view
from fastapi.testclient import TestClient  # noqa: E402

from app.auth import make_token, read_token  # noqa: E402
from app.main import app  # noqa: E402
from conftest import add_user, sign_in  # noqa: E402


def other_project_payload(findings):
    return {**scan_payload(findings), "repo": "team/other"}


def test_reading_needs_sign_in(client):
    anon = TestClient(app)
    assert anon.get("/api/findings").status_code == 401
    assert anon.get("/api/dashboard").status_code == 401
    assert anon.get("/api/findings", headers={"Authorization": "Bearer 1.9999999999.forged"}).status_code == 401
    assert anon.get("/health").status_code == 200


def test_login(client):
    anon = TestClient(app)
    assert anon.post("/api/auth/login", json={"email": "boss@example.com", "password": "nope"}).status_code == 401
    r = anon.post("/api/auth/login", json={"email": "BOSS@example.com ", "password": "password123"})
    assert r.status_code == 200
    assert r.json()["user"]["role"] == "manager"
    me = anon.get("/api/auth/me", headers={"Authorization": f"Bearer {r.json()['token']}"}).json()
    assert me["email"] == "boss@example.com"


def test_token_cannot_be_changed():
    token = make_token(5)
    assert read_token(token) == 5
    user_id, expires, sig = token.split(".")
    assert read_token(f"6.{expires}.{sig}") is None


def test_developer_sees_only_their_projects(client):
    client.post("/api/ingest/scan", json=scan_payload([finding()]), headers=AUTH)
    client.post("/api/ingest/scan", json=other_project_payload([finding("x"), finding("y", line=2)]), headers=AUTH)
    add_user("dev@example.com", role="developer", projects="team/demo")
    dev = TestClient(app)
    dev.headers.update(sign_in(dev, "dev@example.com"))
    assert {f["repo"] for f in dev.get("/api/findings").json()} == {"team/demo"}
    assert dev.get("/api/findings", params={"repo": "team/other"}).status_code == 403
    assert dev.get("/api/dashboard").json()["projects"] == ["team/demo"]
    assert len(client.get("/api/findings").json()) == 3  # the manager sees both projects


def test_assign_fix_and_team(client):
    client.post("/api/ingest/scan", json=scan_payload([finding(), finding("py.xss", "medium", line=20)]), headers=AUTH)
    dev_id = add_user("dev@example.com", role="developer", projects="team/demo", name="Dana")
    outsider = add_user("out@example.com", role="developer", projects="team/other")
    dev = TestClient(app)
    dev.headers.update(sign_in(dev, "dev@example.com"))
    fid = dev.get("/api/findings").json()[0]["id"]

    assert dev.patch(f"/api/findings/{fid}", json={"assignee_id": outsider}).status_code == 400
    r = dev.patch(f"/api/findings/{fid}", json={"assignee_id": dev_id})
    assert r.json()["assignee_name"] == "Dana"
    assert [f["id"] for f in dev.get("/api/findings", params={"assignee": "me"}).json()] == [fid]
    dev.patch(f"/api/findings/{fid}", json={"status": "fixed"})

    detail = dev.get(f"/api/findings/{fid}").json()
    assert detail["status"] == "fixed"
    assert [e["kind"] for e in detail["events"]] == ["assigned", "status"]
    assert detail["type_name"] == "SQL injection"
    assert detail["members"] == [{"id": dev_id, "name": "Dana"}]

    t = dev.get("/api/team", params={"repo": "team/demo"}).json()
    assert t["members"][0]["fixed_30d"] == 1 and t["members"][0]["you"] is True
    assert "marked py.sql-injection as fixed" in t["activity"][0]["text"]
    assert dev.get("/api/team", params={"repo": "team/other"}).status_code == 403
