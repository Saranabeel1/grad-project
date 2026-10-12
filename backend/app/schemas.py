"""Request and response shapes (what the API accepts and returns)."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

Severity = Literal["critical", "high", "medium", "low", "info"]
ToolType = Literal["SAST", "DAST", "SCA", "IAC", "SECRETS"]
RunStatus = Literal["success", "failure", "in_progress"]


# ---------- incoming (from the pipeline) ----------
class FindingIn(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    description: str | None = None
    cwe: str | None = None
    file: str | None = None
    line: int | None = None


class ScanIngest(BaseModel):
    repo: str
    branch: str
    commit_sha: str
    run_id: str
    tool: str
    tool_type: ToolType
    # When the scan ran. Leave empty for live pipelines (the server uses "now");
    # set it when loading past runs, so trends use the real dates.
    scanned_at: datetime | None = None
    findings: list[FindingIn]


class RunIn(BaseModel):
    repo: str
    run_id: str
    branch: str
    commit_sha: str
    status: RunStatus
    run_url: str | None = None
    started_at: datetime | None = None  # when the run started; empty means "now"


# ---------- outgoing (to the dashboard) ----------
class IngestResult(BaseModel):
    created: int
    updated: int


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    repo: str
    run_id: str
    tool: str
    tool_type: str
    rule_id: str
    title: str
    description: str | None
    severity: str
    cwe: str | None
    file: str | None
    line: int | None
    status: str
    first_seen: datetime
    last_seen: datetime
    assignee_id: int | None = None
    assignee_name: str | None = None


class RunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    repo: str
    run_id: str
    branch: str
    commit_sha: str
    status: str
    run_url: str | None
    started_at: datetime | None
    created_at: datetime
    updated_at: datetime


class Summary(BaseModel):
    open_findings: int
    critical_open: int
    by_severity: dict[str, int]
    last_run: RunOut | None


class Dashboard(BaseModel):
    projects: list[str]
    repo: str | None
    open_findings: int
    found_total: int
    new_last_7d: int
    critical_open: int
    high_open: int
    still_reported: int
    resolved: int
    mean_days_to_fix: float | None
    runs_total: int
    runs_passed: int
    pass_rate: int | None
    by_severity: dict[str, int]
    by_tool: list[dict]
    by_tool_type: dict[str, int]
    trend: list[dict]
    compare: list[dict]
    insights: list[dict]
    repeated_types: list[dict]


# ---------- people ----------
class LoginIn(BaseModel):
    email: str
    password: str


class FindingUpdate(BaseModel):
    assignee_id: int | None = None  # leave out to keep, null to unassign
    status: Literal["open", "fixed", "ignored"] | None = None
