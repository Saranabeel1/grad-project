"""Risk Insights: rule-based warnings (no AI) computed from the stored findings and runs.

Rules (shown on the Risk Insights page):
- the same vulnerability type is open in 2 or more projects
- the same vulnerability type is open 3 or more times in one project
- a project's last 3 or more pipeline runs all failed
- a project has fewer open findings than a week ago (a "good" insight)
A vulnerability type is the CWE when the scanner gives one, otherwise the rule id.
"""
from collections import defaultdict
from datetime import timedelta

# Short names and a suggested action for common CWEs. Anything else is shown as its CWE id.
CWE_INFO = {
    "CWE-89": ("SQL injection", "add a parameterized-query check to code review"),
    "CWE-78": ("Command injection", "avoid shell=True and pass arguments as a list"),
    "CWE-77": ("Command injection", "avoid building shell commands from input"),
    "CWE-79": ("Cross-site scripting", "escape output and use the framework's templates"),
    "CWE-22": ("Path traversal", "check file paths against an allowed folder"),
    "CWE-798": ("Hard-coded secrets", "move secrets to environment variables"),
    "CWE-259": ("Hard-coded password", "move passwords to environment variables"),
    "CWE-327": ("Weak cryptography", "use a modern algorithm such as AES-GCM or SHA-256"),
    "CWE-328": ("Weak hash", "use SHA-256, or bcrypt/argon2 for passwords"),
    "CWE-502": ("Unsafe deserialization", "use safe loaders such as yaml.safe_load"),
    "CWE-918": ("Server-side request forgery", "allow-list the hosts the server may call"),
    "CWE-352": ("Missing CSRF protection", "turn on CSRF tokens for forms"),
    "CWE-200": ("Information exposure", "remove debug output and detailed errors"),
    "CWE-489": ("Debug mode left on", "turn off debug mode in production settings"),
    "CWE-94": ("Code injection", "never pass input to eval or exec"),
    "CWE-95": ("Code injection (eval)", "never pass input to eval"),
    "CWE-611": ("XML external entities", "turn off external entities in the XML parser"),
    "CWE-693": ("Missing security header", "add the header in the web server or app"),
    "CWE-1021": ("Clickjacking", "send X-Frame-Options or a frame-ancestors CSP"),
    "CWE-319": ("Unencrypted traffic", "use HTTPS everywhere"),
    "CWE-732": ("Too-wide permissions", "give files and roles only the access they need"),
    "CWE-250": ("Running as root", "run the container as a normal user"),
    "CWE-284": ("Weak access control", "check permissions on every request"),
    "CWE-306": ("Missing authentication", "require login on this endpoint"),
    "CWE-400": ("Resource exhaustion", "add limits and timeouts"),
    "CWE-1357": ("Untrusted third-party component", "pin third-party actions and images to a fixed version"),
    "CWE-1104": ("Outdated dependency", "update the package to a fixed version"),
    "CWE-937": ("Outdated dependency", "update the package to a fixed version"),
}

RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def type_of(f) -> tuple[str, str]:
    """(key, readable name) for a finding's vulnerability type."""
    if f.tool_type == "SCA" and f.rule_id.upper().startswith(("CVE-", "GHSA-")):
        return "dependency", "Vulnerable dependency"
    cwe = (f.cwe or "").split(",")[0].strip().upper()
    if cwe.startswith("CWE-"):
        return cwe, CWE_INFO.get(cwe, (cwe, ""))[0]
    return f.rule_id, f.title[:80]


def action_for(key: str) -> str:
    if key == "dependency":
        return "update the affected packages to fixed versions"
    return CWE_INFO.get(key, ("", "review these findings together and fix the shared cause"))[1]


def level(findings) -> str:
    worst = min(RANK.get(f.severity, 4) for f in findings)
    return "high" if worst <= 1 else "medium"


def names(items, limit=4) -> str:
    items = sorted(items)
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def compute(open_findings, all_findings, runs, latest) -> tuple[list[dict], list[dict]]:
    """Returns (insights, most repeated types). Ignores info-level findings."""
    by_type = defaultdict(list)
    for f in open_findings:
        if f.severity != "info":
            by_type[type_of(f)].append(f)

    insights = []
    for (key, name), fs in by_type.items():
        projects = {f.repo for f in fs}
        if len(projects) >= 2:
            insights.append({
                "level": level(fs),
                "title": f"{name} in {len(projects)} projects",
                "detail": f"{len(fs)} open findings in {names(projects)}.",
                "action": action_for(key),
                "count": len(fs),
            })
        else:
            if len(fs) >= 3:
                insights.append({
                    "level": level(fs),
                    "title": f"{name} found {len(fs)} times in {fs[0].repo}",
                    "detail": f"Spread over {plural(len({f.file for f in fs if f.file}), 'page' if fs[0].tool_type == 'DAST' else 'file')}, found by {names({f.tool for f in fs})}.",
                    "action": action_for(key),
                    "count": len(fs),
                })

    runs_by_repo = defaultdict(list)
    for r in runs:
        if r.status in ("success", "failure") and r.started_at:
            runs_by_repo[r.repo].append(r)
    for repo, rs in runs_by_repo.items():
        rs.sort(key=lambda r: r.started_at, reverse=True)
        streak = 0
        for r in rs:
            if r.status != "failure":
                break
            streak += 1
        if streak >= 3:
            insights.append({
                "level": "high",
                "title": f"{repo} failed {streak} runs in a row",
                "detail": f"The last {streak} pipeline runs did not pass.",
                "action": f"check in with the {repo} team",
                "count": streak,
            })

    # good news: fewer findings reported now than 7 days before the latest scan
    per_repo = defaultdict(list)
    for f in all_findings:
        per_repo[f.repo].append(f)
    for repo, fs in per_repo.items():
        end = max(f.last_seen for f in fs)
        week_ago = end - timedelta(days=7)
        now_count = sum(1 for f in fs if f.status == "open" and f.last_seen >= latest[(f.repo, f.tool)])
        before = sum(1 for f in fs if f.first_seen <= week_ago <= f.last_seen)
        if before and now_count < before:
            insights.append({
                "level": "good",
                "title": f"{repo} is improving",
                "detail": f"{before - now_count} fewer findings reported than a week before its latest scan ({before} → {now_count}).",
                "action": "",
                "count": before - now_count,
            })

    order = {"high": 0, "medium": 1, "good": 2}
    insights.sort(key=lambda i: (order[i["level"]], -i["count"]))
    repeated = sorted(
        ({"type": name, "count": len(fs)} for (key, name), fs in by_type.items()),
        key=lambda t: -t["count"],
    )[:6]
    return insights, repeated
