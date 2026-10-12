"""Unified DevSecOps Telemetry Portal: backend API (starter version).

Flow: the pipeline POSTs scan results and run status to /api/ingest/* (with the API key),
this app stores them, and people who signed in read them from /api/dashboard, /api/findings,
/api/runs and /api/team. Managers see every project, developers only their own.
"""
import hashlib
import hmac
import os
from contextlib import asynccontextmanager
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from . import auto_fetch
from .auth import allowed_repos, check_password, check_repo, current_user, make_token
from . import insights as risk
from . import models, schemas
from .database import get_db, upgrade

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Starter shortcut: create tables on startup. Switch to Alembic migrations later.
    upgrade()  # also adds columns that new versions need to an existing database
    stop = auto_fetch.start()  # only runs when AUTO_FETCH_REPO and GITHUB_TOKEN are set
    yield
    if stop:
        stop.set()


app = FastAPI(
    title="Unified DevSecOps Telemetry Portal",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count"],  # lets the dashboard read the total for paging
)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """The pipeline proves who it is with a shared secret in the X-API-Key header."""
    expected = os.getenv("PORTAL_API_KEY")
    if not expected:
        raise HTTPException(status_code=503, detail="PORTAL_API_KEY is not configured on the server")
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def as_utc(value: datetime | None) -> datetime:
    """Store every time as UTC without a timezone, so old and new values compare cleanly."""
    if value is None:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def make_fingerprint(repo: str, tool: str, f: schemas.FindingIn) -> str:
    """Same problem in the same place gives the same fingerprint, so re-scans don't duplicate it.
    Starter version: refine later (for example, ignore line shifts)."""
    raw = "|".join([repo, tool, f.rule_id, f.file or "", str(f.line or "")])
    return hashlib.sha256(raw.encode()).hexdigest()


def finding_out(f: models.Finding, names: dict[int, str]) -> dict:
    data = schemas.FindingOut.model_validate(f).model_dump()
    data["assignee_name"] = names.get(f.assignee_id) if f.assignee_id else None
    return data


def user_names(db: Session) -> dict[int, str]:
    return dict(db.execute(select(models.User.id, models.User.name)).all())


def user_out(u: models.User) -> dict:
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role, "projects": u.project_list}


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------- sign in
@app.post("/api/auth/login")
def login(body: schemas.LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(models.User).where(models.User.email == body.email.lower().strip()))
    if not user or not check_password(body.password, user.password_hash):
        if not db.scalar(select(func.count()).select_from(models.User)):
            raise HTTPException(status_code=401, detail="No accounts yet: make one with  python -m app.users add")
        raise HTTPException(status_code=401, detail="Wrong email or password")
    return {"token": make_token(user.id), "user": user_out(user)}


@app.get("/api/auth/me")
def me(user: models.User = Depends(current_user)):
    return user_out(user)


# ---------------------------------------------------------------- ingest
@app.post(
    "/api/ingest/scan",
    response_model=schemas.IngestResult,
    dependencies=[Depends(require_api_key)],
)
def ingest_scan(payload: schemas.ScanIngest, db: Session = Depends(get_db)):
    now = as_utc(payload.scanned_at)
    created = updated = 0

    for f in payload.findings:
        fp = make_fingerprint(payload.repo, payload.tool, f)
        existing = db.scalar(
            select(models.Finding).where(
                models.Finding.repo == payload.repo,
                models.Finding.fingerprint == fp,
            )
        )
        if existing:
            first, last = as_utc(existing.first_seen), as_utc(existing.last_seen)
            existing.first_seen = min(first, now)  # past runs may arrive out of order
            if now >= last:
                existing.last_seen = now
                existing.run_id = payload.run_id
                existing.commit_sha = payload.commit_sha
                if existing.status == "fixed":  # it came back
                    existing.status = "open"
            updated += 1
        else:
            db.add(
                models.Finding(
                    fingerprint=fp,
                    repo=payload.repo,
                    run_id=payload.run_id,
                    commit_sha=payload.commit_sha,
                    tool=payload.tool,
                    tool_type=payload.tool_type,
                    rule_id=f.rule_id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    cwe=f.cwe,
                    file=f.file,
                    line=f.line,
                    first_seen=now,
                    last_seen=now,
                )
            )
            db.flush()  # so duplicates inside one payload are seen as existing
            created += 1

    db.commit()
    return {"created": created, "updated": updated}


@app.post(
    "/api/ingest/run",
    response_model=schemas.RunOut,
    dependencies=[Depends(require_api_key)],
)
def ingest_run(payload: schemas.RunIn, db: Session = Depends(get_db)):
    run = db.scalar(
        select(models.PipelineRun).where(
            models.PipelineRun.repo == payload.repo,
            models.PipelineRun.run_id == payload.run_id,
        )
    )
    if run:
        run.status = payload.status
        run.run_url = payload.run_url
        if payload.started_at:
            run.started_at = as_utc(payload.started_at)
    else:
        data = payload.model_dump()
        data["started_at"] = as_utc(payload.started_at)
        run = models.PipelineRun(**data)
        db.add(run)
    db.commit()
    db.refresh(run)
    return run


# ---------------------------------------------------------------- read (dashboard)
@app.get("/api/findings", response_model=list[schemas.FindingOut])
def list_findings(
    response: Response,
    assignee: str | None = Query(None, description='"me", "none", or a user id'),
    severity: schemas.Severity | None = None,
    tool_type: schemas.ToolType | None = None,
    tool: str | None = None,
    status: str | None = None,
    repo: str | None = None,
    q: str | None = Query(None, description="text search in title, rule, file and CWE"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: models.User = Depends(current_user),
):
    check_repo(user, repo)
    severity_rank = case(
        {s: i for i, s in enumerate(SEVERITIES)},
        value=models.Finding.severity,
        else_=len(SEVERITIES),
    )
    query = select(models.Finding)
    if severity:
        query = query.where(models.Finding.severity == severity)
    if tool_type:
        query = query.where(models.Finding.tool_type == tool_type)
    if status:
        query = query.where(models.Finding.status == status)
    if repo:
        query = query.where(models.Finding.repo == repo)
    elif allowed_repos(user) is not None:
        query = query.where(models.Finding.repo.in_(allowed_repos(user)))
    if assignee == "me":
        query = query.where(models.Finding.assignee_id == user.id)
    elif assignee == "none":
        query = query.where(models.Finding.assignee_id.is_(None))
    elif assignee and assignee.isdigit():
        query = query.where(models.Finding.assignee_id == int(assignee))
    if tool:
        query = query.where(models.Finding.tool == tool)
    if q:
        like = f"%{q.strip()}%"
        query = query.where(
            or_(
                models.Finding.title.ilike(like),
                models.Finding.rule_id.ilike(like),
                models.Finding.file.ilike(like),
                models.Finding.cwe.ilike(like),
            )
        )
    response.headers["X-Total-Count"] = str(db.scalar(select(func.count()).select_from(query.subquery())))
    query = query.order_by(severity_rank, models.Finding.first_seen.desc()).limit(limit).offset(offset)
    names = user_names(db)
    return [finding_out(f, names) for f in db.scalars(query).all()]


@app.get("/api/runs", response_model=list[schemas.RunOut])
def list_runs(
    repo: str | None = None,
    limit: int = Query(20, ge=1, le=200),
    db: Session = Depends(get_db),
    user: models.User = Depends(current_user),
):
    check_repo(user, repo)
    query = select(models.PipelineRun)
    if repo:
        query = query.where(models.PipelineRun.repo == repo)
    elif allowed_repos(user) is not None:
        query = query.where(models.PipelineRun.repo.in_(allowed_repos(user)))
    query = query.order_by(models.PipelineRun.started_at.desc(), models.PipelineRun.updated_at.desc()).limit(limit)
    return db.scalars(query).all()


@app.get("/api/summary", response_model=schemas.Summary)
def summary(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    rows = db.execute(
        select(models.Finding.severity, func.count())
        .where(models.Finding.status == "open")
        .group_by(models.Finding.severity)
    ).all()
    by_severity = {s: 0 for s in SEVERITIES}
    for sev, count in rows:
        by_severity[sev] = count

    last_run = db.scalar(
        select(models.PipelineRun)
        .order_by(models.PipelineRun.started_at.desc(), models.PipelineRun.updated_at.desc())
        .limit(1)
    )
    return {
        "open_findings": sum(by_severity.values()),
        "critical_open": by_severity["critical"],
        "by_severity": by_severity,
        "last_run": last_run,
    }


@app.get("/api/dashboard", response_model=schemas.Dashboard)
def dashboard(repo: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    """Everything the dashboard page draws, for one project (repo) or for all projects.

    "Still reported" means the latest scan by that tool on that project still lists the finding.
    A finding missing from the latest scan is counted as resolved for the trend and the
    mean time to fix (estimated from first_seen to last_seen), even if its status is still open.
    """
    check_repo(user, repo)
    allowed = allowed_repos(user)
    all_findings = [f for f in db.scalars(select(models.Finding)).all() if allowed is None or f.repo in allowed]
    run_repos = set(db.scalars(select(models.PipelineRun.repo).distinct()))
    projects = sorted({f.repo for f in all_findings} | {r for r in run_repos if allowed is None or r in allowed})

    # latest scan time per project + tool, from all findings (needed for "still reported")
    latest: dict[tuple[str, str], datetime] = {}
    for f in all_findings:
        key = (f.repo, f.tool)
        if key not in latest or f.last_seen > latest[key]:
            latest[key] = f.last_seen

    findings = [f for f in all_findings if repo is None or f.repo == repo]
    open_f = [f for f in findings if f.status == "open"]

    by_severity = {s: 0 for s in SEVERITIES}
    by_tool: dict[str, dict] = {}
    by_tool_type: Counter = Counter()
    compare: dict[str, dict] = defaultdict(lambda: {**{s: 0 for s in SEVERITIES}, "open": 0, "tools": set()})
    for f in open_f:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        t = by_tool.setdefault(f.tool, {"tool": f.tool, "tool_type": f.tool_type, "total": 0, **{s: 0 for s in SEVERITIES}})
        t["total"] += 1
        t[f.severity] = t.get(f.severity, 0) + 1
        by_tool_type[f.tool_type] += 1
    for f in (x for x in all_findings if x.status == "open"):  # comparison always shows every project
        c = compare[f.repo]
        c["open"] += 1
        c[f.severity] = c.get(f.severity, 0) + 1
        c["tools"].add(f.tool)

    # trend: findings reported on each day, by severity
    trend = []
    if findings:
        start = min(f.first_seen for f in findings).date()
        end = max(f.last_seen for f in findings).date()
        if (end - start).days > 180:
            start = end - timedelta(days=180)
        spans = []
        for f in findings:
            current = f.last_seen >= latest[(f.repo, f.tool)] and f.status == "open"
            spans.append((f.first_seen.date(), end if current else f.last_seen.date(), f.severity))
        day = start
        while day <= end:
            row = {"date": day.isoformat(), **{s: 0 for s in SEVERITIES}}
            for first, last, sev in spans:
                if first <= day <= last:
                    row[sev] += 1
            trend.append(row)
            day += timedelta(days=1)

    resolved = [f for f in findings if f.last_seen < latest[(f.repo, f.tool)] or f.status == "fixed"]
    mean_days = (
        round(sum((f.last_seen - f.first_seen).total_seconds() for f in resolved) / len(resolved) / 86400, 1)
        if resolved
        else None
    )

    all_runs = [r for r in db.scalars(select(models.PipelineRun)).all() if allowed is None or r.repo in allowed]
    runs = [r for r in all_runs if repo is None or r.repo == repo]
    finished = [r for r in runs if r.status in ("success", "failure")]
    passed = sum(1 for r in finished if r.status == "success")

    # per project: pass rate and last run, for the comparison table
    for p in projects:
        compare[p]  # every project gets a row, even with no open findings
    for r in sorted(all_runs, key=lambda r: (r.started_at or r.created_at)):
        c = compare[r.repo]
        c["last_run"] = r.status
        if r.status in ("success", "failure"):
            c["runs"] = c.get("runs", 0) + 1
            c["passed"] = c.get("passed", 0) + (r.status == "success")

    insights, repeated = risk.compute(open_f, findings, runs, latest)
    data_end = max((f.last_seen for f in findings), default=None)
    data_start = min((f.first_seen for f in findings), default=None)
    # "new this week" only means something when there is older data to compare with
    has_history = data_end is not None and data_end - data_start > timedelta(days=7)

    return {
        "projects": projects,
        "repo": repo,
        "open_findings": len(open_f),
        "found_total": len(findings),
        "new_last_7d": sum(1 for f in open_f if f.first_seen > data_end - timedelta(days=7)) if has_history else 0,
        "critical_open": by_severity["critical"],
        "high_open": by_severity["high"],
        "still_reported": sum(1 for f in open_f if f.last_seen >= latest[(f.repo, f.tool)]),
        "resolved": len(resolved),
        "mean_days_to_fix": mean_days,
        "runs_total": len(finished),
        "runs_passed": passed,
        "pass_rate": round(100 * passed / len(finished)) if finished else None,
        "by_severity": by_severity,
        "by_tool": sorted(by_tool.values(), key=lambda t: -t["total"]),
        "by_tool_type": dict(by_tool_type.most_common()),
        "trend": trend,
        "compare": [
            {
                **c,
                "repo": r,
                "tools": sorted(c["tools"]),
                "last_run": c.get("last_run"),
                "pass_rate": round(100 * c["passed"] / c["runs"]) if c.get("runs") else None,
            }
            for r, c in sorted(compare.items())
        ],
        "insights": insights,
        "repeated_types": repeated,
    }


# ---------------------------------------------------------------- developer view: one finding, assigning, team
def members_of(db: Session, repo: str) -> list[models.User]:
    users = db.scalars(select(models.User).where(models.User.role == "developer").order_by(models.User.name)).all()
    return [u for u in users if repo in u.project_list]


def get_finding(db: Session, user: models.User, finding_id: int) -> models.Finding:
    f = db.get(models.Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    check_repo(user, f.repo)
    return f


@app.get("/api/findings/{finding_id}")
def finding_detail(finding_id: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    f = get_finding(db, user, finding_id)
    names = user_names(db)
    latest_scan = db.scalar(
        select(func.max(models.Finding.last_seen)).where(models.Finding.repo == f.repo, models.Finding.tool == f.tool)
    )
    key, label = risk.type_of(f)
    events = db.scalars(
        select(models.FindingEvent).where(models.FindingEvent.finding_id == f.id).order_by(models.FindingEvent.created_at)
    ).all()
    return {
        **finding_out(f, names),
        "still_reported": f.last_seen >= latest_scan,
        "type_name": label,
        "how_to_fix": risk.action_for(key),
        "members": [{"id": u.id, "name": u.name} for u in members_of(db, f.repo)],
        "events": [
            {"kind": e.kind, "detail": e.detail, "at": e.created_at, "by": names.get(e.user_id) if e.user_id else None}
            for e in events
        ],
    }


@app.patch("/api/findings/{finding_id}")
def update_finding(
    finding_id: int, body: schemas.FindingUpdate, db: Session = Depends(get_db), user: models.User = Depends(current_user)
):
    """Assign a finding to someone (or nobody), or change its status. Every change is kept as an event."""
    f = get_finding(db, user, finding_id)
    names = user_names(db)
    if "assignee_id" in body.model_fields_set and body.assignee_id != f.assignee_id:
        if body.assignee_id is not None:
            target = db.get(models.User, body.assignee_id)
            if not target or (target.role != "manager" and f.repo not in target.project_list):
                raise HTTPException(status_code=400, detail="That person is not a member of this project")
            db.add(models.FindingEvent(finding_id=f.id, user_id=user.id, kind="assigned", detail=target.name))
        else:
            db.add(models.FindingEvent(finding_id=f.id, user_id=user.id, kind="unassigned", detail=""))
        f.assignee_id = body.assignee_id
    if body.status and body.status != f.status:
        db.add(models.FindingEvent(finding_id=f.id, user_id=user.id, kind="status", detail=body.status))
        f.status = body.status
    db.commit()
    return finding_out(f, user_names(db) | names)


@app.get("/api/team")
def team(repo: str, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    """The developers of one project: their open findings, what they fixed lately, and recent activity."""
    check_repo(user, repo)
    month_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
    members = members_of(db, repo)
    findings = db.scalars(select(models.Finding).where(models.Finding.repo == repo)).all()
    by_id = {f.id: f for f in findings}
    events = db.scalars(
        select(models.FindingEvent)
        .where(models.FindingEvent.finding_id.in_(list(by_id) or [0]))
        .order_by(models.FindingEvent.created_at.desc())
    ).all()
    names = user_names(db)

    cards = []
    for m in members:
        mine = [e for e in events if e.user_id == m.id]
        cards.append({
            "id": m.id,
            "name": m.name,
            "you": m.id == user.id,
            "open": sum(1 for f in findings if f.assignee_id == m.id and f.status == "open"),
            "fixed_30d": sum(1 for e in mine if e.kind == "status" and e.detail == "fixed" and e.created_at >= month_ago),
            "last_active": mine[0].created_at if mine else None,
        })

    activity = []
    for e in events[:25]:
        f = by_id[e.finding_id]
        who = names.get(e.user_id, "Someone") if e.user_id else "Someone"
        what = {
            "assigned": f"assigned {f.title} to {e.detail}",
            "unassigned": f"unassigned {f.title}",
            "status": f"marked {f.title} as {e.detail}",
        }.get(e.kind, e.kind)
        activity.append({"at": e.created_at, "who": who, "text": what, "finding_id": f.id, "status": None})
    runs = db.scalars(
        select(models.PipelineRun).where(models.PipelineRun.repo == repo)
        .order_by(models.PipelineRun.started_at.desc()).limit(10)
    ).all()
    for r in runs:
        activity.append({"at": r.started_at or r.created_at, "who": None, "text": f"Pipeline run on {r.branch} ({r.commit_sha[:7]})",
                         "finding_id": None, "status": r.status})
    activity.sort(key=lambda a: a["at"], reverse=True)
    return {"repo": repo, "members": cards, "activity": activity[:25]}


# The built dashboard (frontend/dist, made by "npm run build"). When it exists, the backend serves it at "/",
# so the dashboard and its data share one address: http://localhost:8000 here, or the ngrok link for the team.
# Added last so the API routes above always win. check_dir=False: the build may appear after the backend starts.
DASHBOARD = Path(__file__).resolve().parents[2] / "frontend" / "dist"


class Dashboard(StaticFiles):
    async def __call__(self, scope, receive, send):
        if not DASHBOARD.is_dir():
            reply = Response("Dashboard not built yet: run npm run build in frontend/", status_code=404)
            return await reply(scope, receive, send)
        return await super().__call__(scope, receive, send)


app.mount("/", Dashboard(directory=DASHBOARD, html=True, check_dir=False), name="dashboard")
