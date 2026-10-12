#!/usr/bin/env python3
"""Count how many GHALogs runs mention each security scanner.

Usage:  python count_tools.py runs.json.gz   (or an unpacked runs.json)
Needs only Python 3 (no installs). Works whether the file is one big JSON
list or one JSON record per line. Prints a small table and writes
tool_counts.txt next to where you ran it.
"""
import gzip
import json
import sys
from collections import Counter

# Words that show a run used the tool (action names or commands), lowercase.
TOOLS = {
    "Semgrep (code)": ["semgrep"],
    "Trivy (libraries)": ["trivy"],
    "ZAP (website)": ["zaproxy", "owasp zap", "zap-baseline", "zap-full-scan", "action-baseline", "action-full-scan"],
    "Checkov (infrastructure)": ["checkov"],
    "CodeQL (extra)": ["codeql"],
    "Snyk (extra)": ["snyk"],
    "tfsec (extra)": ["tfsec"],
}


def records(path):
    """Yield one run at a time without loading the whole file into memory."""
    decoder = json.JSONDecoder()
    with open(path, "rb") as raw:
        packed = raw.read(2) == b"\x1f\x8b"  # works with the .gz file or an unpacked copy
    opener = gzip.open if packed else open
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
                    break  # record not complete yet, read more
                buf = buf[end:]
                if isinstance(obj, list):
                    yield from obj
                else:
                    yield obj
            if not chunk:
                return


def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python count_tools.py runs.json.gz")
    runs = Counter()
    repos = {name: set() for name in TOOLS}
    examples = {}
    samples = {}  # one full run per tool, saved so we can see where the tool name appears
    total = 0
    for rec in records(sys.argv[1]):
        total += 1
        if total == 1:
            keys = list(rec.keys()) if isinstance(rec, dict) else type(rec).__name__
            print("Fields in one run:", keys)
        text = json.dumps(rec).lower()
        for name, words in TOOLS.items():
            if any(w in text for w in words):
                runs[name] += 1
                if isinstance(rec, dict):
                    repo = rec.get("repository") or rec.get("repo") or rec.get("repo_name") or rec.get("full_name")
                    if isinstance(repo, dict):
                        repo = repo.get("full_name") or repo.get("name")
                    if repo:
                        repos[name].add(str(repo))
                    if repo is None:
                        repo = next((v for k, v in rec.items() if "repo" in k.lower() and isinstance(v, (str, int))), None)
                        if repo is not None:
                            repos[name].add(str(repo))
                    if name not in examples:
                        examples[name] = rec.get("id") or rec.get("run_id") or rec.get("_id")
                        samples[name] = rec
        if total % 50000 == 0:
            print(f"...{total} runs read", file=sys.stderr)

    lines = [f"Total runs: {total}", "", f"{'Tool':28}{'Runs':>8}{'Projects':>10}  Example run id"]
    for name in TOOLS:
        lines.append(f"{name:28}{runs[name]:>8}{len(repos[name]):>10}  {examples.get(name, '-')}")
    out = "\n".join(lines)
    print(out)
    with open("tool_counts.txt", "w") as f:
        f.write(out + "\n")
    with open("examples.json", "w") as f:
        json.dump(samples, f, indent=2, default=str)
    print("\nSaved to tool_counts.txt and examples.json. Send examples.json back in the chat.")


if __name__ == "__main__":
    main()
