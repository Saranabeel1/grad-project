#!/usr/bin/env python3
"""List projects that ran more than one of our scanners (the best demo for a *unified* portal).

Usage:  python find_overlap.py scan_runs.csv
Reads scan_runs.csv (from find_scan_runs.py), prints the projects that used 2+ tools,
and writes overlap_runs.csv with only those projects' runs (same columns, ready for fetch_logs.py).
"""
import csv
import sys
from collections import defaultdict

if len(sys.argv) != 2:
    sys.exit("Usage: python find_overlap.py scan_runs.csv")
with open(sys.argv[1], newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

tools = defaultdict(set)
for r in rows:
    if r["logs_in_dataset"] == "yes":
        tools[r["repo"].lower()].add(r["tool"])
multi = {repo: t for repo, t in tools.items() if len(t) > 1}

print(f"Projects with 2 or more scanners: {len(multi)}\n")
for repo, t in sorted(multi.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:40]:
    print(f"  {len(t)} tools  {repo:50} {', '.join(sorted(t))}")

keep = [r for r in rows if r["repo"].lower() in multi]
with open("overlap_runs.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(keep)
print(f"\nSaved {len(keep)} runs to overlap_runs.csv.")
print("Next: python fetch_logs.py overlap_runs.csv --per-tool 100 --out fetched_overlap.csv")
