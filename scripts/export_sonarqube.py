#!/usr/bin/env python3
"""Save one project's SonarQube results to a JSON file. Standard library only.

Usage:
  python export_sonarqube.py --project project-g --out reports/sonarqube.json

Environment:
  SONAR_HOST_URL   the SonarQube server, like http://localhost:9000
  SONAR_TOKEN      a SonarQube *user* token (My Account > Security); an analysis token cannot read results

SonarQube keeps its results on its server, not in a file, so this script asks the server for them.
It first waits until the server has finished processing the scan, then saves:
  - issues that affect security (SonarQube's "vulnerabilities")
  - security hotspots (code that may be risky and needs a person to check it)
Code smells and plain bugs are left out: the portal is about security.
fetch_live.py / fetch_daily.py read the saved file like the other tools' reports.
"""
import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PAGE = 500  # the most SonarQube gives per page
LIMIT = 10000  # SonarQube will not page past 10,000 results


def api(path, **params):
    url = os.environ["SONAR_HOST_URL"].rstrip("/") + path + "?" + urllib.parse.urlencode(params)
    login = base64.b64encode((os.environ["SONAR_TOKEN"] + ":").encode()).decode()
    req = urllib.request.Request(url, headers={"Authorization": "Basic " + login})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def wait_for_processing(project, minutes):
    """After a scan, SonarQube needs a little time before the results can be read."""
    for _ in range(minutes * 12):
        ce = api("/api/ce/component", component=project)
        current = (ce.get("current") or {}).get("status")
        if not ce.get("queue") and current:
            if current != "SUCCESS":
                sys.exit(f"SonarQube could not process the scan of {project} (status {current}).")
            return
        time.sleep(5)
    sys.exit(f"SonarQube was still processing {project} after {minutes} minutes.")


def all_pages(path, key, **params):
    """Returns (items, rule names). Rule names come with issues and give a readable title."""
    items, rules, page = [], {}, 1
    while True:
        data = api(path, p=page, ps=PAGE, **params)
        items += data.get(key, [])
        rules.update({r["key"]: r.get("name") for r in data.get("rules", [])})
        if page * PAGE >= min(data.get("paging", {}).get("total", 0), LIMIT):
            return items, rules
        page += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, help="the SonarQube project key used in the scan")
    ap.add_argument("--out", default="sonarqube.json")
    ap.add_argument("--wait-minutes", type=int, default=10)
    args = ap.parse_args()

    try:
        wait_for_processing(args.project, args.wait_minutes)
        issues, rules = all_pages("/api/issues/search", "issues", componentKeys=args.project,
                                  impactSoftwareQualities="SECURITY", resolved="false", additionalFields="rules")
        hotspots, _ = all_pages("/api/hotspots/search", "hotspots", projectKey=args.project, status="TO_REVIEW")
    except urllib.error.HTTPError as e:
        sys.exit(f"SonarQube said HTTP {e.code} ({e.read().decode()[:200]}). "
                 "Check SONAR_TOKEN is a user token and the project key is right.")
    except urllib.error.URLError as e:
        sys.exit(f"Could not reach SonarQube at {os.environ['SONAR_HOST_URL']}: {e.reason}")

    doc = {"sonarqube": {"project": args.project}, "rules": rules, "issues": issues, "hotspots": hotspots}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    print(f"{args.project}: {len(issues)} security issues, {len(hotspots)} hotspots saved in {args.out}")


if __name__ == "__main__":
    main()
