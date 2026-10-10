#!/usr/bin/env python3
"""Send one scan's reports straight to the portal (real-time push). Runs at the end of daily-scan.yml.

Usage (inside GitHub Actions):
  python portal/scripts/push_reports.py reports --run-id 123 --run-url https://... --status success

Reads PORTAL_URL and PORTAL_API_KEY from the environment (GitHub secrets). Without them it does
nothing, so the workflow works the same as before. Reads the reports with the same readers as
fetch_live.py / fetch_daily.py (report_readers.py), so pushed results and fetched results are identical; if the same
run is later fetched too, the portal just updates the same findings (no duplicates).
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from report_readers import category, read_report  # noqa: E402  (same readers as fetch_daily.py)


def read_folder(folder: Path):
    """(details of the scanned version, {tool: findings}) from a folder of reports."""
    target = json.loads((folder / "target.json").read_text(encoding="utf-8"))
    found = {}
    for path in sorted(folder.glob("*.json")):
        if path.name == "target.json":
            continue
        for tool, items in read_report(path.name, path.read_bytes()).items():
            found.setdefault(tool, []).extend(items)
    for tool, items in found.items():  # the same finding from two reports counts once
        found[tool] = list({(f["rule_id"], f["file"], f["line"]): f for f in items}.values())
    return target, found


def post(base, path, key, payload):
    req = urllib.request.Request(
        base.rstrip("/") + path, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": key,
                 "ngrok-skip-browser-warning": "1", "User-Agent": "secflow-push"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode() or "{}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder", help="folder with target.json and the scanners' reports")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--run-url")
    ap.add_argument("--status", default="success", help="the job's status: success or failure")
    args = ap.parse_args()

    url, key = os.getenv("PORTAL_URL", "").strip(), os.getenv("PORTAL_API_KEY", "").strip()
    if not url or not key:
        print("PORTAL_URL / PORTAL_API_KEY secrets are not set: not sending (the results are still saved as files).")
        return

    target, found = read_folder(Path(args.folder))
    alias, when = target["alias"], target["scanned_at"]
    common = {"repo": alias, "run_id": str(args.run_id), "branch": target["branch"], "commit_sha": target["commit_sha"]}
    try:
        post(url, "/api/ingest/run", key, {
            **common, "status": "success" if args.status == "success" else "failure",
            "run_url": args.run_url, "started_at": when})
        groups = {}
        for tool, items in found.items():
            for f in items:
                groups.setdefault((tool, category(tool, f)), []).append(f)
        for (tool, cat), items in groups.items():
            r = post(url, "/api/ingest/scan", key, {**common, "tool": tool, "tool_type": cat,
                                                     "scanned_at": when, "findings": items})
            print(f"{alias} {tool} ({cat}): {len(items)} findings sent, {r.get('created', 0)} new")
    except urllib.error.HTTPError as e:
        sys.exit(f"The portal answered {e.code}. Check that the PORTAL_API_KEY secret matches the backend's key.")
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        sys.exit(f"Could not reach the portal at {url} ({e}). Is the backend and the tunnel running? "
                 "The results are still saved; fetch_daily.py can bring them in later.")
    print(f"Done: {alias} is up to date in the portal.")


if __name__ == "__main__":
    main()
