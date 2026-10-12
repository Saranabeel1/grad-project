#!/usr/bin/env python3
"""Find GHALogs runs where Semgrep, Trivy, ZAP or Checkov really ran, and list them.

Usage:  python find_scan_runs.py runs.json.gz
Needs only Python 3. Writes scan_runs.csv (one row per run and tool) and prints a summary.

A run counts only if one of its steps actually calls the tool (a GitHub Action
like aquasecurity/trivy-action, or a shell command like `trivy fs .`), not just
when the tool's name appears somewhere. It also notes whether the run's logs
are in the dataset, and whether the tool printed results to the log or only
saved them to a file (SARIF/JSON).
"""
import csv
import gzip
import json
import re
import sys
from collections import Counter, defaultdict

# GitHub Actions that run each tool: (owner, action name)
ACTIONS = {
    "semgrep": [("returntocorp", "semgrep-action"), ("semgrep", "semgrep-action")],
    "trivy": [("aquasecurity", "trivy-action")],
    "zap": [("zaproxy", "action-baseline"), ("zaproxy", "action-full-scan"), ("zaproxy", "action-api-scan"),
            ("zaproxy", "action-af")],
    "checkov": [("bridgecrewio", "checkov-action")],
}
# Shell commands that run each tool
SHELL = {
    "semgrep": re.compile(r"(^|[\s;&|/])semgrep\s+(ci|scan|--config|-c\b|--sarif|--json)", re.M),
    "trivy": re.compile(r"(^|[\s;&|/])trivy\s+(fs|filesystem|image|rootfs|repo|repository|config|k8s|sbom|vm)\b", re.M),
    "zap": re.compile(r"zap-(baseline|full-scan|api-scan)\.py|zap\.sh\s+-cmd|zaproxy/zap-(stable|weekly)|owasp/zap2docker"),
    "checkov": re.compile(r"(^|[\s;&|/])checkov\s+(-d|--directory|-f|--file|--framework|-o|--output)", re.M),
}
CATEGORY = {"semgrep": "SAST", "trivy": "SCA", "zap": "DAST", "checkov": "IAC"}


def records(path):
    """Yield one run at a time without loading the whole file into memory."""
    with open(path, "rb") as raw:
        packed = raw.read(2) == b"\x1f\x8b"
    opener = gzip.open if packed else open
    decoder = json.JSONDecoder()
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        buf = ""
        while True:
            chunk = f.read(1 << 20)
            buf += chunk
            while True:
                buf = buf.lstrip(" \r\n\t,[]")
                if not buf:
                    break
                try:
                    obj, end = decoder.raw_decode(buf)
                except json.JSONDecodeError:
                    break
                buf = buf[end:]
                if isinstance(obj, list):
                    yield from obj
                elif isinstance(obj, dict) and "_id" not in obj and all(isinstance(v, dict) for v in obj.values()):
                    yield from obj.values()  # a file like examples.json: {tool: run}
                else:
                    yield obj
            if not chunk:
                return


def output_style(tool, step):
    """Guess whether results were printed to the log ('printed') or only saved to a file."""
    if step.get("type") == "action":
        w = {k.lower(): str(v).lower() for k, v in (step.get("with") or {}).items()}
        fmt = w.get("format") or w.get("output_format") or ""
        if tool == "semgrep":
            return "printed"  # semgrep-action prints findings even when it also makes SARIF
        if tool == "zap":
            return "printed"  # ZAP actions print WARN/FAIL lines per alert
        if tool == "checkov" and w.get("quiet") == "true" and "cli" not in fmt and fmt:
            return "file:" + fmt
        if fmt and fmt not in ("table", "cli"):
            return "file:" + fmt
        return "printed"
    code = (step.get("code") or "").lower()
    m = re.search(r"(--format|-f|-o|--output-format)\s+(sarif|json|cyclonedx|spdx|template)", code)
    if m and tool in ("trivy", "checkov") or re.search(r"--(sarif|json)\b", code):
        return "file:" + (m.group(2) if m else "sarif/json")
    return "printed"


def find_tools(rec):
    found = {}
    for li in rec.get("log_insights") or []:
        for step in li.get("steps") or []:
            for tool in ACTIONS:
                if tool in found:
                    continue
                hit = False
                if step.get("type") == "action":
                    owner = str(step.get("repository", "")).lower()
                    name = str(step.get("action", "")).lower()
                    hit = (owner, name) in ACTIONS[tool]
                    how = f"{owner}/{name}"
                else:
                    hit = bool(SHELL[tool].search(step.get("code") or ""))
                    how = "shell command"
                if hit:
                    found[tool] = {"how": how, "log_file": li.get("file", ""), "output": output_style(tool, step)}
    return found


def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python find_scan_runs.py runs.json.gz")
    runs, with_logs, printed = Counter(), Counter(), Counter()
    projects = defaultdict(set)
    total = 0
    cols = ["tool", "category", "repo", "run_id", "run_number", "run_attempt", "workflow", "branch", "commit_sha",
            "started_at", "conclusion", "event", "run_url", "how_it_ran", "output", "logs_in_dataset", "log_path",
            "log_file"]
    with open("scan_runs.csv", "w", newline="", encoding="utf-8") as out:
        w = csv.writer(out)
        w.writerow(cols)
        for rec in records(sys.argv[1]):
            total += 1
            if total % 50000 == 0:
                print(f"...{total} runs read", file=sys.stderr)
            if not isinstance(rec, dict):
                continue
            found = find_tools(rec)
            if not found:
                continue
            meta = rec.get("metadata") or {}
            logs = rec.get("logs_archive") or {}
            has_logs = "path" in logs
            for tool, info in found.items():
                runs[tool] += 1
                projects[tool].add(rec.get("repository_name"))
                if has_logs:
                    with_logs[tool] += 1
                    if info["output"] == "printed":
                        printed[tool] += 1
                w.writerow([tool, CATEGORY[tool], rec.get("repository_name"), meta.get("id"), rec.get("run_number"),
                            rec.get("run_attempt"), rec.get("workflow_path"), meta.get("head_branch"),
                            meta.get("head_sha"), meta.get("run_started_at") or meta.get("created_at"),
                            meta.get("conclusion"), meta.get("event"), meta.get("html_url"), info["how"],
                            info["output"], "yes" if has_logs else "no", logs.get("path", ""), info["log_file"]])

    lines = [f"Total runs read: {total}", "",
             f"{'Tool':10}{'Real runs':>11}{'Projects':>10}{'With logs':>11}{'Printed results':>17}"]
    for tool in ACTIONS:
        lines.append(f"{tool:10}{runs[tool]:>11}{len(projects[tool]):>10}{with_logs[tool]:>11}{printed[tool]:>17}")
    lines += ["", "'Printed results' = runs with logs where the tool most likely printed its findings into the log.",
              "Saved the full list to scan_runs.csv. Send scan_runs.csv back in the chat."]
    out = "\n".join(lines)
    print(out)
    with open("scan_summary.txt", "w") as f:
        f.write(out + "\n")


if __name__ == "__main__":
    main()
