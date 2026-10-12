#!/usr/bin/env python3
"""Send scanner results / pipeline status to the portal. Standard library only.

Usage:
  send_results.py scan semgrep.json [--dry-run]
  send_results.py run --status success [--dry-run]

Environment:
  PORTAL_URL, PORTAL_API_KEY            where to send and how to authenticate
  GITHUB_REPOSITORY, GITHUB_REF_NAME,   set automatically by GitHub Actions
  GITHUB_SHA, GITHUB_RUN_ID,
  GITHUB_SERVER_URL
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def first_cwe(value):
    """Semgrep's metadata.cwe is a string or list like 'CWE-89: SQL Injection'."""
    items = value if isinstance(value, list) else [value] if value else []
    for item in items:
        m = re.search(r"CWE-\d+", str(item))
        if m:
            return m.group(0)
    return None


def convert_semgrep(data):
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        rule_id = r.get("check_id", "unknown")
        findings.append(
            {
                "rule_id": rule_id,
                "title": rule_id.split(".")[-1],
                "description": extra.get("message"),
                "severity": SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), "info"),
                "cwe": first_cwe(meta.get("cwe")),
                "file": r.get("path"),
                "line": (r.get("start") or {}).get("line"),
            }
        )
    return findings


def context():
    env = os.environ
    return {
        "repo": env.get("GITHUB_REPOSITORY", "local/dev"),
        "branch": env.get("GITHUB_REF_NAME", "local"),
        "commit_sha": env.get("GITHUB_SHA", "0" * 7),
        "run_id": env.get("GITHUB_RUN_ID", "0"),
    }


def post(path, payload, dry_run):
    if dry_run:
        print(f"[dry-run] POST {path}")
        print(json.dumps(payload, indent=2))
        return
    url = os.environ["PORTAL_URL"].rstrip("/") + path
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": os.environ["PORTAL_API_KEY"]},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            print(resp.status, resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Could not reach portal: {e.reason}", file=sys.stderr)
        sys.exit(1)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("file")
    s.add_argument("--tool", default="semgrep")
    s.add_argument("--tool-type", default="SAST")
    s.add_argument("--dry-run", action="store_true")
    r = sub.add_parser("run")
    r.add_argument("--status", required=True, choices=["success", "failure", "cancelled", "in_progress"])
    r.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    ctx = context()
    if args.cmd == "scan":
        with open(args.file) as f:
            data = json.load(f)
        payload = {**ctx, "tool": args.tool, "tool_type": args.tool_type, "findings": convert_semgrep(data)}
        post("/api/ingest/scan", payload, args.dry_run)
    else:
        run_url = None
        if os.environ.get("GITHUB_SERVER_URL") and os.environ.get("GITHUB_REPOSITORY"):
            run_url = f"{os.environ['GITHUB_SERVER_URL']}/{ctx['repo']}/actions/runs/{ctx['run_id']}"
        post("/api/ingest/run", {**ctx, "status": args.status, "run_url": run_url}, args.dry_run)


if __name__ == "__main__":
    main()
