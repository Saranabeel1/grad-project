"""Talking to GitHub (and to the portal) for the fetch scripts: retries, downloads in pieces, curl fallback.

Shared by fetch_live.py and fetch_daily.py. Holds no project names, so it is safe in a public repository.
"""
import gzip
import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

API = os.environ.get("GITHUB_API", "https://api.github.com")
OUT = Path("live-data")


# ------------------------------------------------------------------ talking to GitHub
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # we follow download links ourselves, without sending the token to the storage server


OPENER = urllib.request.build_opener(NoRedirect)


RETRY_ERRORS = (http.client.IncompleteRead, ConnectionError, TimeoutError, urllib.error.URLError)
PIECE = 256 * 1024  # some networks cut long downloads, so files come down in 256 KB pieces


def retry(what, fn):
    """Run fn(); if the connection drops, wait a little and try again (up to 6 times)."""
    for attempt in range(6):
        try:
            return fn()
        except RETRY_ERRORS as e:
            if isinstance(e, urllib.error.HTTPError) and e.code < 500:
                raise
            if attempt == 5:
                raise
            print(f"  connection dropped while reading {what} ({type(e).__name__}), trying again...")
            time.sleep(2 * (attempt + 1))


CURL = shutil.which("curl.exe") or shutil.which("curl")
# Some networks interrupt secure connections with a "renegotiation" request that Python cannot
# handle, but curl can. So when curl is installed (it is on Windows 10/11), it does the downloading.
USE_CURL = bool(CURL) and os.environ.get("FETCH_NO_CURL") != "1"


def curl_get(url, headers):
    """Download url with curl. Returns (http code, download link if GitHub sent one, body)."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "body"
        config = "".join(f'header = "{h}"\n' for h in headers)  # via stdin: the token never shows on screen
        for attempt in range(6):
            res = subprocess.run([CURL, "-sS", "--compressed", "--max-time", "300", "-K", "-",
                                  "-o", str(out), "-w", "%{http_code} %{redirect_url}", url],
                                 input=config.encode(), capture_output=True)
            code, _, link = res.stdout.decode().strip().partition(" ")
            if res.returncode == 0 and code.isdigit():
                return code, link.strip(), (out.read_bytes() if out.exists() else b"")
            err = res.stderr.decode(errors="replace").strip()
            if attempt == 5:
                raise ConnectionError(f"curl failed: {err}")
            print(f"  connection dropped ({err[:80]}), trying again...")
            time.sleep(2 * (attempt + 1))


def gh_curl(token, url, raw):
    """Same as gh(), done by curl."""
    code, link, body = curl_get(url, [f"Authorization: Bearer {token}", "Accept: application/vnd.github+json",
                                      "X-GitHub-Api-Version: 2022-11-28"])
    if code in ("301", "302", "303", "307", "308") and link:
        code, _, body = curl_get(link, [])  # a download link: fetched without the token
    if code == "401":
        sys.exit("GitHub says the token is wrong or expired. Make a new one and try again.")
    if code == "403" and b"rate limit" in body.lower():
        sys.exit("GitHub's hourly limit is used up. Wait an hour and run the script again.")
    if not code.startswith("2"):
        raise urllib.error.HTTPError(url, int(code), body[:200].decode(errors="replace"), None, None)
    return body if raw else json.loads(body)


def gh(token, path, raw=False):
    """Ask GitHub for something. Answers come compressed (much smaller); files come in pieces."""
    url = path if path.startswith("http") else API + path
    if USE_CURL:
        return gh_curl(token, url, raw)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
                                               "Accept": "application/vnd.github+json",
                                               "Accept-Encoding": "gzip",
                                               "X-GitHub-Api-Version": "2022-11-28"})

    def once():
        try:
            with OPENER.open(req, timeout=60) as r:
                data = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return ("data", data)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):  # a download link
                return ("link", e.headers["Location"])
            if e.code == 401:
                sys.exit("GitHub says the token is wrong or expired. Make a new one and try again.")
            if e.code == 403 and e.headers.get("X-RateLimit-Remaining") == "0":
                sys.exit("GitHub's hourly limit is used up. Wait an hour and run the script again.")
            raise

    kind, value = retry("GitHub's answer", once)
    if kind == "link":
        return download(value)  # without the token: the link itself gives access
    return value if raw else json.loads(value)


def download(url):
    """Download a file piece by piece, so a dropped connection only loses one small piece."""
    data, total = b"", None
    while total is None or len(data) < total:
        start = len(data)

        def piece():
            req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{start + PIECE - 1}"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, r.headers.get("Content-Range"), r.read()

        status, content_range, chunk = retry("a file", piece)
        if status == 200:  # the server ignored the piece request and sent the whole file
            return chunk
        data += chunk
        total = int(content_range.rsplit("/", 1)[1]) if content_range and "/" in content_range else len(data)
        if not chunk:
            break
    return data


def post(base, path, key, payload):
    req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "X-API-Key": key}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode()
