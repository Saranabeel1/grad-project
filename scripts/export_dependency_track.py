#!/usr/bin/env python3
"""Run one project's parts list (SBOM) through a throwaway OWASP Dependency-Track server and save
its findings to a JSON file. Standard library only.

Usage (inside daily-scan.yml, after starting the server):
  python export_dependency_track.py --sbom sbom.cdx.json --project project-g --out reports/dependency-track.json

Environment:
  DT_URL   the Dependency-Track API server, like http://localhost:8081

Dependency-Track is not a scanner you point at code. It is a server that keeps a project's list of
libraries (an SBOM, made here by Trivy) and matches it against vulnerability databases. Like SonarQube,
it keeps its results on the server, so this script:
  1. signs in as the built-in admin and sets a new random password (the server is thrown away after the run)
  2. turns on Google's OSV database for the common ecosystems and turns off the slow NVD download,
     then restarts the server (the download only starts when the server starts)
  3. waits until the vulnerability data has been downloaded
  4. uploads the SBOM, waits for the analysis, and saves the findings
fetch_daily.py / push_reports.py read the saved file like the other tools' reports.
"""
import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ECOSYSTEMS = "npm;Maven;PyPI;Go;NuGet;RubyGems;Packagist;crates.io"
TOKEN = None


def call(method, path, body=None, form=None, raw=False):
    url = os.environ.get("DT_URL", "http://localhost:8081").rstrip("/") + path
    headers = {"Accept": "application/json, text/plain, */*"}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if TOKEN:
        headers["Authorization"] = "Bearer " + TOKEN
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:
        text = r.read().decode()
        if raw:
            return text, r.headers
        return json.loads(text) if text.strip().startswith(("{", "[")) else text


def wait_until_up(minutes):
    for _ in range(minutes * 12):
        try:
            call("GET", "/api/version")
            return
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(5)
    sys.exit(f"Dependency-Track did not start within {minutes} minutes.")


def first_sign_in():
    """The server starts with admin/admin and asks for a new password first."""
    password = "Dt-" + secrets.token_hex(16)
    print(f"::add-mask::{password}")
    call("POST", "/api/v1/user/forceChangePassword",
         form={"username": "admin", "password": "admin", "newPassword": password, "confirmPassword": password})
    sign_in(password)
    return password


def sign_in(password):
    global TOKEN
    TOKEN = None
    TOKEN = call("POST", "/api/v1/user/login", form={"username": "admin", "password": password}).strip()
    print(f"::add-mask::{TOKEN}")


def set_property(group, name, value):
    call("POST", "/api/v1/configProperty", body={"groupName": group, "propertyName": name, "propertyValue": value})


def vulnerability_count():
    _, headers = call("GET", "/api/v1/vulnerability?pageSize=1&pageNumber=1", raw=True)
    return int(headers.get("X-Total-Count") or 0)


def wait_for_mirror(minutes):
    """OSV data arrives in the background. Wait until the number of known vulnerabilities stops growing."""
    last, steady = -1, 0
    for i in range(minutes * 4):
        n = vulnerability_count()
        steady = steady + 1 if n == last and n > 0 else 0
        if i % 4 == 0:
            print(f"  {n} vulnerabilities downloaded so far")
        if steady >= 8:  # no change for 2 minutes
            print(f"Vulnerability data ready: {n} entries.")
            return
        last = n
        time.sleep(15)
    print(f"Still downloading after {minutes} minutes ({last} entries); using what is there.")


def wait_for_task(token, minutes):
    for _ in range(minutes * 12):
        try:
            busy = call("GET", f"/api/v1/event/token/{token}").get("processing")
        except urllib.error.HTTPError:  # older servers
            busy = call("GET", f"/api/v1/bom/token/{token}").get("processing")
        if not busy:
            return
        time.sleep(5)
    sys.exit(f"Dependency-Track was still working after {minutes} minutes.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sbom", required=True, help="CycloneDX SBOM, for example from: trivy fs --format cyclonedx")
    ap.add_argument("--project", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mirror-minutes", type=int, default=25)
    ap.add_argument("--container", default="dtrack", help="the server's Docker container, restarted once")
    args = ap.parse_args()

    wait_until_up(10)
    password = first_sign_in()
    set_property("vuln-source", "nvd.enabled", "false")      # the full NVD download takes hours
    set_property("scanner", "ossindex.enabled", "false")     # OSS Index now needs an account
    set_property("vuln-source", "google.osv.enabled", ECOSYSTEMS)
    print("Restarting Dependency-Track so it starts downloading the OSV data...")
    subprocess.run(["docker", "restart", args.container], check=True, stdout=subprocess.DEVNULL)
    time.sleep(10)
    wait_until_up(10)
    sign_in(password)
    wait_for_mirror(args.mirror_minutes)

    bom = base64.b64encode(open(args.sbom, "rb").read()).decode()
    up = call("PUT", "/api/v1/bom", body={"projectName": args.project, "projectVersion": "daily",
                                          "autoCreate": True, "bom": bom})
    wait_for_task(up["token"], 15)
    project = call("GET", "/api/v1/project/lookup?" + urllib.parse.urlencode({"name": args.project, "version": "daily"}))
    again = call("POST", f"/api/v1/finding/project/{project['uuid']}/analyze")  # make sure it ran on the full data
    if isinstance(again, dict) and again.get("token"):
        wait_for_task(again["token"], 15)
    findings = call("GET", f"/api/v1/finding/project/{project['uuid']}?suppressed=false")

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"dependency-track": True, "project": args.project, "findings": findings}, f)
    print(f"Saved {len(findings)} Dependency-Track findings to {args.out}")


if __name__ == "__main__":
    main()
