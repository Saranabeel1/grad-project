#!/usr/bin/env python3
"""Turn real GHALogs scanner logs into findings for the portal.

Usage:
  python parse_logs.py fetched_runs.csv                 # just convert; writes out/ and findings.csv
  python parse_logs.py fetched_runs.csv fetched_overlap.csv   # several lists at once (duplicates skipped)
  python parse_logs.py fetched_runs.csv --send URL KEY  # also send every run to the portal

Reads the logs saved by fetch_logs.py (paths are in fetched_runs.csv), pulls the
findings out of each tool's printed output, and keeps the real project name,
run ID, commit, branch and date of each run. Standard library only.

What each tool gives us in its log:
  Semgrep  rule, file, line, message           (no severity in text output -> estimated from the rule name)
  Trivy    CVE, library, versions, severity     (UNKNOWN -> "info")
  ZAP      alert name and ID, URLs, WARN/FAIL   (severity from ZAP's own risk for known alerts)
  Checkov  check ID and name, resource, file    (no severity in free Checkov -> "medium", secrets "high")
"""
import argparse
import csv
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

TS = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ?")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
CATEGORY = {"semgrep": "SAST", "trivy": "SCA", "zap": "DAST", "checkov": "IAC"}


def clean_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = ANSI.sub("", TS.sub("", raw.rstrip("\r\n")))
            yield line.replace("##[error]", "").replace("##[warning]", "")


def indent(s):
    return len(s) - len(s.lstrip(" "))


# ------------------------------------------------------------------ Semgrep (text output)
HIGH_WORDS = ("injection", "sqli", "xss", "command", "exec", "deserial", "eval", "hardcoded", "secret",
              "password", "credential", "private-key", "ssrf", "xxe", "path-traversal", "rce")


def semgrep_severity(rule, blocking):
    """Text output has no severity, so guess from the rule name (documented as an estimate)."""
    r = rule.lower()
    if blocking or any(w in r for w in HIGH_WORDS):
        return "high"
    return "medium" if ".security." in r else "low"


def parse_semgrep(lines):
    findings, in_block, new_finding, blocking = [], False, True, False
    file = rule = None
    rule_parts, msg_parts, mode = [], [], None
    for line in lines:
        s = line.strip()
        if re.search(r"\d+ (Non-blocking|Blocking) Code Findings?", s):
            in_block = True
            continue
        if not in_block:
            continue
        if re.match(r"^(Found \d+ findings?|Ran \d+ rules)", s) or re.search(r"(Scan Summary|Supply Chain Findings|Secrets Findings)", s):
            in_block = False
            continue
        if s.startswith("⋮┆"):  # separator between two findings of the same rule
            new_finding = True
            continue
        if not s or s.startswith(("┌", "└", "│")) or "Autofix" in s:
            continue
        m = re.match(r"^\s*(\d+)┆", line)
        if m:
            if rule_parts:  # first code line after a rule: finish rule id and message
                rule = "".join(rule_parts)
                rule_parts = []
                new_finding = True
            if rule and file and new_finding:
                new_finding = False
                msg = " ".join(msg_parts)
                findings.append({
                    "rule_id": rule,
                    "title": rule.split(".")[-1],
                    "severity": semgrep_severity(rule, blocking),
                    "description": re.sub(r"\s*Details: \S+", "", msg).strip() or None,
                    "file": file,
                    "line": int(m.group(1)),
                })
            mode = "code"
            continue
        ind = indent(line)
        if ind == 4:  # a file path
            file, rule, rule_parts, msg_parts, mode = s, None, [], [], None
        elif ind == 7 or (ind == 2 and mode == "rule"):
            if mode != "rule":  # a new rule starts
                rule_parts, msg_parts = [], []
                blocking = bool(re.match(r"[❯❱]", s))
            rule_parts.append(s.lstrip("❯❱ "))
            mode = "rule"
        elif ind >= 10 or (ind == 2 and mode == "msg"):
            msg_parts.append(s)
            mode = "msg"
    return findings


# ------------------------------------------------------------------ Trivy (table output)
TRIVY_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}
IAC_TARGETS = ("(dockerfile)", "(terraform)", "(kubernetes)", "(cloudformation)", "(helm)", "(azure-arm)", "(yaml)", "(json)")


def parse_trivy(lines):
    """Library vulnerabilities come as tables; secrets and misconfigurations as 'HIGH: title (id)' blocks."""
    lines = list(lines)
    findings, target, cols, cur, prev, block = [], "unknown", None, None, {}, None
    for i, line in enumerate(lines):
        if line.startswith("Total: "):
            j = i - 1
            while j >= 0 and (not lines[j].strip() or set(lines[j].strip()) == {"="}):
                j -= 1
            target = lines[j].strip() if j >= 0 else "unknown"
            cols, cur, prev, block = None, None, {}, None
            continue
        m = re.match(r"^(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN): (.+?)(?: \(([^)]+)\))?$", line.strip())
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if m and target != "unknown" and nxt.startswith("═"):
            kind = "SECRETS" if target.endswith("(secrets)") else "IAC" if target.endswith(IAC_TARGETS) else "SCA"
            block = {"rule_id": m.group(3) or m.group(2), "title": m.group(2), "severity": TRIVY_SEV[m.group(1)],
                     "description": None, "file": target.rsplit(" (", 1)[0], "line": None, "tool_type": kind}
            findings.append(block)
            continue
        if block is not None:
            loc = re.match(r"^\s*(\S+?):(\d+)(?:-\d+)?\s*$", line)
            if loc and block["line"] is None:
                block["file"], block["line"] = loc.group(1), int(loc.group(2))
            continue
        if not line.startswith("│") or "─" in line:  # skip text and table borders
            continue
        cells = [c.strip() for c in line.strip().strip("│").split("│")]
        if cols is None:
            if "Severity" in cells:
                cols = cells
            continue
        row = dict(zip(cols, cells))
        for k, v in row.items():  # empty merged cells repeat the value above
            if v:
                prev[k] = v
        vid = row.get("Vulnerability")
        if vid:
            lib = prev.get("Library", "")
            cur = {
                "rule_id": vid,
                "title": f"{vid} in {lib}" if lib else vid,
                "severity": TRIVY_SEV.get(prev.get("Severity", "").upper(), "info"),
                "description": None,
                "file": f"{target} :: {lib}" if lib else target,
                "line": None,
            }
            fixed = prev.get("Fixed Version")
            cur["_extra"] = f"Installed {prev.get('Installed Version', '?')}" + (f", fixed in {fixed}." if fixed else ".")
            findings.append(cur)
        title = row.get("Title", "")
        if cur is not None and title and not title.startswith("http"):
            cur["description"] = ((cur["description"] or "") + " " + title).strip()
    for f in findings:
        extra = f.pop("_extra", None)
        if extra:
            f["description"] = f"{f['description'] or ''} {extra}".strip()
    return findings


# ------------------------------------------------------------------ ZAP (baseline/full scan output)
# ZAP's own risk level and CWE for common passive-scan alerts
ZAP_RULES = {
    "10020": ("medium", "CWE-1021"), "10021": ("low", "CWE-693"), "10038": ("medium", "CWE-693"),
    "10035": ("low", "CWE-319"), "10036": ("low", "CWE-200"), "10037": ("low", "CWE-200"),
    "10096": ("low", "CWE-200"), "10027": ("info", "CWE-200"), "10015": ("info", "CWE-525"),
    "10017": ("low", "CWE-829"), "10010": ("low", "CWE-1004"), "10011": ("low", "CWE-614"),
    "10054": ("low", "CWE-1275"), "10098": ("medium", "CWE-264"), "10202": ("medium", "CWE-352"),
    "10063": ("low", "CWE-693"), "10049": ("info", "CWE-524"), "10109": ("info", None),
    "10055": ("medium", "CWE-693"), "90022": ("low", "CWE-200"), "90033": ("info", "CWE-565"),
    "10003": ("medium", "CWE-829"), "10031": ("info", "CWE-20"), "10110": ("low", "CWE-749"),
    "2": ("low", "CWE-200"), "3": ("medium", "CWE-200"), "10024": ("medium", "CWE-200"),
}


def parse_zap(lines):
    findings, cur = [], None
    for line in lines:
        m = re.match(r"^(WARN|FAIL)-(NEW|INPROG): (.+?) \[(\d+)\] x (\d+)", line.strip())
        if m:
            level, _, name, rid, count = m.groups()
            sev, cwe = ZAP_RULES.get(rid, ("high" if level == "FAIL" else "medium", None))
            cur = {"rule_id": f"zap-{rid}", "title": name, "severity": sev, "cwe": cwe,
                   "description": f"{name} found on {count} URL(s).", "file": None, "line": None}
            findings.append(cur)
            continue
        if cur and line.startswith("\t") and "http" in line:
            if cur["file"] is None:
                url = line.strip().split(" ")[0]
                cur["file"] = url.split("?")[0]
            continue
        if not line.startswith("\t"):
            cur = None
    return findings


# ------------------------------------------------------------------ Checkov (CLI output)
def parse_checkov(lines):
    findings, check, name, resource = [], None, None, None
    for line in lines:
        s = line.strip()
        m = re.match(r'^Check: (CKV2?_[A-Z0-9_]+): "(.*)"?$', s)
        if m:
            check, name, resource = m.group(1), m.group(2).rstrip('"'), None
            continue
        m = re.match(r"^FAILED for resource: (.+)$", s)
        if m and check:
            resource = m.group(1)
            continue
        if s.startswith("PASSED for resource") or s.startswith("SKIPPED for resource"):
            check = None
            continue
        m = re.match(r"^File: (\S+?):(\d+)-(\d+)", s)
        if m and check and resource:
            findings.append({"rule_id": check, "title": name[:300],
                             "severity": "high" if check.startswith("CKV_SECRET") else "medium",
                             "description": f"Failed for resource {resource}",
                             "file": m.group(1).lstrip("/"), "line": int(m.group(2))})
            check = resource = None
    return findings


PARSERS = {"semgrep": parse_semgrep, "trivy": parse_trivy, "zap": parse_zap, "checkov": parse_checkov}


def post(base, path, key, payload):
    req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "X-API-Key": key}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_files", nargs="+", help="fetched_runs.csv (and more lists) from fetch_logs.py")
    ap.add_argument("--send", nargs=2, metavar=("PORTAL_URL", "API_KEY"))
    args = ap.parse_args()

    base_dir = Path(args.csv_files[0]).resolve().parent
    rows, seen = [], set()
    for name in args.csv_files:
        for r in csv.DictReader(open(name, newline="", encoding="utf-8")):
            if (r["tool"], r["run_id"]) not in seen:
                seen.add((r["tool"], r["run_id"]))
                rows.append(r)
    rows.sort(key=lambda r: r["started_at"])  # oldest first, so the portal sees runs in order
    out_dir = base_dir / "out"
    summary = {}
    with open(base_dir / "findings.csv", "w", newline="", encoding="utf-8") as fcsv:
        w = csv.writer(fcsv)
        w.writerow(["tool", "category", "repo", "run_id", "started_at", "commit_sha", "severity", "rule_id",
                    "title", "cwe", "file", "line"])
        for r in rows:
            log = base_dir / r["saved_as"].replace("\\", "/")
            if not log.exists():
                print("missing log:", log)
                continue
            tool = r["tool"]
            findings = PARSERS[tool](clean_lines(log))
            groups = {}  # Trivy can report secrets and misconfigurations too; keep them in their own category
            for f in findings:
                f.setdefault("cwe", None)
                f["rule_id"], f["title"] = f["rule_id"][:300], f["title"][:300]  # fit the database columns
                f["file"] = f["file"][:500] if f["file"] else None
                kind = f.pop("tool_type", CATEGORY[tool])
                groups.setdefault(kind, []).append(f)
                w.writerow([tool, kind, r["repo"], r["run_id"], r["started_at"], r["commit_sha"],
                            f["severity"], f["rule_id"], f["title"], f["cwe"], f["file"], f["line"]])
            run = {"repo": r["repo"], "run_id": r["run_id"], "branch": r["branch"], "commit_sha": r["commit_sha"],
                   "status": "success" if r["conclusion"] == "success" else "failure",
                   "run_url": r["run_url"], "started_at": r["started_at"]}
            scans = [{"repo": r["repo"], "branch": r["branch"], "commit_sha": r["commit_sha"], "run_id": r["run_id"],
                      "tool": tool, "tool_type": kind, "scanned_at": r["started_at"], "findings": items}
                     for kind, items in (groups or {CATEGORY[tool]: []}).items()]
            target = out_dir / tool / (Path(r["saved_as"].replace("\\", "/")).stem + ".json")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps({"run": run, "scans": scans}, indent=2), encoding="utf-8")
            s = summary.setdefault(tool, {"runs": 0, "runs_with_findings": 0, "findings": 0})
            s["runs"] += 1
            s["findings"] += len(findings)
            s["runs_with_findings"] += bool(findings)
            if args.send:
                try:
                    post(args.send[0], "/api/ingest/run", args.send[1], run)
                    for scan in scans:
                        res = post(args.send[0], "/api/ingest/scan", args.send[1], scan)
                        print(f"sent {r['repo']} run {r['run_number']} ({tool}, {scan['tool_type']}): {res}")
                except urllib.error.HTTPError as e:
                    sys.exit(f"Portal said HTTP {e.code}: {e.read().decode()}")
                except urllib.error.URLError as e:
                    sys.exit(f"Could not reach the portal: {e.reason}")

    print(f"\n{'Tool':10}{'Runs':>6}{'With findings':>15}{'Findings':>10}")
    for tool, s in summary.items():
        print(f"{tool:10}{s['runs']:>6}{s['runs_with_findings']:>15}{s['findings']:>10}")
    print("\nSaved: findings.csv (all findings) and out/<tool>/*.json (one file per run, ready for the portal).")


if __name__ == "__main__":
    main()
