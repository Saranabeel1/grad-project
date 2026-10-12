#!/usr/bin/env python3
"""Bring the results of our own daily scans (.github/workflows/daily-scan.yml) into the portal.

Usage:
  python fetch_daily.py --repo YOUR_NAME/YOUR_REPO                         # save to live-data/daily_findings.csv
  python fetch_daily.py --repo YOUR_NAME/YOUR_REPO --send URL API_KEY      # also send to the portal

Each daily run scans a few public projects and saves one results file per project.
This script downloads the runs it has not seen yet and reads those files with the same
readers as fetch_live.py. Needs the same GitHub token as fetch_live.py (asked for, hidden).
"""
import argparse
import csv
import getpass
import http.client
import io
import json
import os
import sys
import urllib.error
import urllib.parse
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from github_api import OUT, gh, post  # noqa: E402  (same downloading as fetch_live.py)
from report_readers import category, read_report  # noqa: E402  (same readers)

WORKFLOW = "daily-scan.yml"
STATE = OUT / "daily_state.json"  # remembers which daily runs were already brought in


def list_daily_runs(token, repo):
    q = urllib.parse.urlencode({"status": "completed", "per_page": 100})  # about 4 days of hourly runs
    return gh(token, f"/repos/{repo}/actions/workflows/{WORKFLOW}/runs?{q}")["workflow_runs"]


def read_artifact(data):
    """One project's results: (details of the scanned version, {tool: findings})."""
    target, found = None, {}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            if name.endswith("target.json"):
                target = json.loads(z.read(name))
            elif name.lower().endswith(".json"):
                for tool, items in read_report(name, z.read(name)).items():
                    found.setdefault(tool, []).extend(items)
    for tool, items in found.items():  # the same finding from two reports counts once
        found[tool] = list({(f["rule_id"], f["file"], f["line"]): f for f in items}.values())
    return target, found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="your GitHub repository that runs daily-scan, like sara/portal")
    ap.add_argument("--send", nargs=2, metavar=("PORTAL_URL", "API_KEY"))
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or getpass.getpass("Paste your GitHub token (it stays hidden): ").strip()
    if not token:
        sys.exit("Nothing was pasted. Run again and paste with a right-click, then press Enter.")

    OUT.mkdir(exist_ok=True)
    done = set(json.loads(STATE.read_text())) if STATE.exists() else set()
    try:
        runs = sorted(list_daily_runs(token, args.repo), key=lambda r: r["created_at"])
    except urllib.error.HTTPError as e:
        sys.exit(f"Could not find the daily scans in {args.repo} (HTTP {e.code}). "
                 "Check the name, and that daily-scan.yml is in .github/workflows/ there.")
    if not runs:
        print("No finished daily scans yet. Start one: Actions tab > daily-scan > Run workflow.")

    csv_path = OUT / "daily_findings.csv"
    new_file = not csv_path.exists()
    total_new = 0
    with open(csv_path, "a", newline="", encoding="utf-8") as fcsv:
        fw = csv.writer(fcsv)
        if new_file:
            fw.writerow(["tool", "category", "repo", "run_id", "started_at", "commit_sha", "severity", "rule_id",
                         "title", "cwe", "file", "line"])
        for run in runs:
            if run["id"] in done:
                continue
            try:
                arts = gh(token, f"/repos/{args.repo}/actions/runs/{run['id']}/artifacts")["artifacts"]
                for art in arts:
                    if not art["name"].startswith("daily-") or art.get("expired"):
                        continue
                    target, found = read_artifact(gh(token, art["archive_download_url"], raw=True))
                    if not target:
                        continue
                    alias, when = target["alias"], target["scanned_at"]
                    counts = ", ".join(f"{t} {len(v)}" for t, v in found.items()) or "no findings"
                    print(f"{when[:10]}  {alias}: {counts}")
                    groups = {}
                    for tool, items in found.items():
                        for f in items:
                            cat = category(tool, f)
                            groups.setdefault((tool, cat), []).append(f)
                            fw.writerow([tool, cat, alias, run["id"], when, target["commit_sha"], f["severity"],
                                         f["rule_id"], f["title"], f["cwe"], f["file"], f["line"]])
                            total_new += 1
                    if args.send:
                        common = {"repo": alias, "run_id": str(run["id"]), "branch": target["branch"],
                                  "commit_sha": target["commit_sha"]}
                        post(args.send[0], "/api/ingest/run", args.send[1], {
                            **common, "status": "success" if run["conclusion"] == "success" else "failure",
                            "run_url": run["html_url"], "started_at": when})
                        for (tool, cat), items in groups.items():
                            post(args.send[0], "/api/ingest/scan", args.send[1], {
                                **common, "tool": tool, "tool_type": cat, "scanned_at": when, "findings": items})
            except (urllib.error.URLError, zipfile.BadZipFile, http.client.HTTPException,
                    ConnectionError, TimeoutError) as e:
                print(f"Daily run {run['id']}: skipped for now ({e}). Run the script again later.")
                continue
            done.add(run["id"])
            STATE.write_text(json.dumps(sorted(done)))

    print(f"\n{total_new} findings brought in. Saved in {csv_path}.")


if __name__ == "__main__":
    main()
