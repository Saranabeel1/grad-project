#!/usr/bin/env python3
"""Download only the logs we need from the big GHALogs zip (142 GB) without downloading all of it.

Usage:  python fetch_logs.py scan_runs.csv [--per-tool 30]
Needs only Python 3 and internet. Reads scan_runs.csv (made by find_scan_runs.py),
picks some good runs for each tool, and pulls just those logs out of the zip on
Zenodo. Saves them in a "logs" folder: logs/<tool>/<project>__run<number>.txt
"""
import argparse
import csv
import http.client
import io
import re
import sys
import tarfile
import time
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path

ZIP_URL = "https://zenodo.org/records/14796970/files/github_run_logs.zip?download=1"
BLOCK = 1 << 20  # read the remote file in 1 MB pieces
PIECE = 8 << 20  # big reads (the zip's table of contents, ~100 MB) go in 8 MB pieces
CACHE = Path("zip_cache")  # big pieces are saved here, so a second try doesn't download them again


class RemoteFile(io.RawIOBase):
    """Lets zipfile read a file on a web server piece by piece (HTTP Range requests)."""

    def __init__(self, url):
        self.url, self.pos, self.cache = url, 0, {}
        req = urllib.request.Request(url, headers={"Range": "bytes=0-0"})
        for attempt in range(6):
            try:
                r = urllib.request.urlopen(req, timeout=60)
                break
            except (OSError, http.client.HTTPException):
                if attempt == 5:
                    sys.exit("Could not reach Zenodo. Check your internet and try again later.")
                time.sleep(5 * (attempt + 1))
        with r:
            if r.status != 206:
                sys.exit("The server does not allow partial downloads, so this method won't work. Tell Claude.")
            self.url = r.url  # follow redirects once
            self.size = int(r.headers["Content-Range"].split("/")[-1])

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        self.pos = {0: offset, 1: self.pos + offset, 2: self.size + offset}[whence]
        return self.pos

    def _get(self, start, end):  # inclusive range
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={start}-{end}"})
        for attempt in range(8):
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    data = r.read()
                if len(data) == end - start + 1:
                    return data
                raise http.client.IncompleteRead(data)
            except (OSError, http.client.HTTPException) as e:
                if attempt == 7:
                    sys.exit("Zenodo keeps failing right now. Wait a while and run the same command again; "
                             "pieces already downloaded are kept in the zip_cache folder.")
                wait = 5 * (attempt + 1)
                print(f"  network hiccup ({type(e).__name__}), retrying in {wait}s...", file=sys.stderr)
                time.sleep(wait)

    def _get_big(self, start, n):
        """Download a big range in 8 MB pieces, keeping each piece on disk."""
        CACHE.mkdir(exist_ok=True)
        parts, pos, end = [], start, start + n
        while pos < end:
            size = min(PIECE, end - pos)
            piece = CACHE / f"{pos}_{size}.bin"
            if piece.exists() and piece.stat().st_size == size:
                data = piece.read_bytes()
            else:
                data = self._get(pos, pos + size - 1)
                piece.write_bytes(data)
                print(f"  table of contents: {min(pos + size, end) - start >> 20} of {n >> 20} MB", file=sys.stderr)
            parts.append(data)
            pos += size
        return b"".join(parts)

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        n = min(n, self.size - self.pos)
        if n <= 0:
            return b""
        if n > 4 * BLOCK:  # big read: fetch in pieces
            data = self._get_big(self.pos, n)
        else:
            parts = []
            first, last = self.pos // BLOCK, (self.pos + n - 1) // BLOCK
            for b in range(first, last + 1):
                if b not in self.cache:
                    if len(self.cache) > 64:
                        self.cache.clear()
                    self.cache[b] = self._get(b * BLOCK, min(self.size, (b + 1) * BLOCK) - 1)
                parts.append(self.cache[b])
            blob = b"".join(parts)
            off = self.pos - first * BLOCK
            data = blob[off:off + n]
        self.pos += len(data)
        return data

    def readinto(self, b):
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)


def key(path):
    """'/data/logs/Owner/Repo/Workflow_ab12/979-1.tar.gz' -> 'owner/repo/workflow_ab12/979-1.tar.gz'"""
    p = path.replace("\\", "/").lower()
    return p.split("logs/", 1)[1] if "logs/" in p else p.lstrip("/")


def safe(text):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text)[:120]


def pick_runs(rows, per_tool):
    """Prefer runs that printed results; spread across projects; keep a few runs per project for trends."""
    by_tool = defaultdict(list)
    for r in rows:
        if r["logs_in_dataset"] == "yes":
            by_tool[r["tool"]].append(r)
    chosen = []
    for tool, items in by_tool.items():
        items.sort(key=lambda r: (r["output"] != "printed", r["repo"], r["started_at"]))
        per_repo, picked = defaultdict(int), []
        for r in items:
            if len(picked) >= per_tool:
                break
            if per_repo[r["repo"]] < 3:
                per_repo[r["repo"]] += 1
                picked.append(r)
        chosen += picked
        print(f"{tool}: picked {len(picked)} runs from {len(per_repo)} projects")
    return chosen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_file")
    ap.add_argument("--per-tool", type=int, default=30)
    ap.add_argument("--url", default=ZIP_URL)
    ap.add_argument("--out", default="fetched_runs.csv", help="name of the list file to write")
    args = ap.parse_args()

    with open(args.csv_file, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    chosen = pick_runs(rows, args.per_tool)

    print("Opening the big zip on Zenodo (reads only its table of contents, may take a few minutes)...")
    zf = zipfile.ZipFile(RemoteFile(args.url))
    index = {key(n): n for n in zf.namelist() if n.endswith((".tar.gz", ".tgz"))}
    print(f"The zip lists {len(index)} log files.")

    out_root = Path("logs")
    saved = 0
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) + ["saved_as"])
        w.writeheader()
        for i, r in enumerate(chosen, 1):
            name = index.get(key(r["log_path"]))
            if not name:
                print(f"[{i}/{len(chosen)}] not in zip: {r['log_path']}")
                continue
            try:
                tar_bytes = zf.read(name)
            except Exception as e:  # one bad download shouldn't stop the rest
                print(f"[{i}/{len(chosen)}] skipped {r['repo']} run {r['run_number']}: {e}")
                continue
            texts = []
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
                for m in tar.getmembers():
                    if m.isfile() and m.name.endswith(".txt") and "/" not in m.name.strip("./"):
                        texts.append((m.name, tar.extractfile(m).read()))
                if not texts:  # fall back to any .txt inside
                    texts = [(m.name, tar.extractfile(m).read()) for m in tar.getmembers()
                             if m.isfile() and m.name.endswith(".txt")]
            wanted = [t for t in texts if Path(t[0]).name == r["log_file"]] or texts
            folder = out_root / r["tool"]
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / f"{safe(r['repo'])}__run{r['run_number']}.txt"
            target.write_bytes(b"\n".join(t[1] for t in wanted))
            r["saved_as"] = str(target)
            w.writerow(r)
            saved += 1
            print(f"[{i}/{len(chosen)}] saved {target}")
    if saved == 0:
        print("Nothing matched. First names in the zip (send this to Claude):")
        for n in list(index.values())[:5] or zf.namelist()[:5]:
            print("  ", n)
    print(f"\nDone: {saved} logs saved in the 'logs' folder. List in {args.out}.")


if __name__ == "__main__":
    main()
