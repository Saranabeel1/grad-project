"""Security Gate: the checkpoint after the scanners, as on the Pipeline Status page.

  Critical / High  -> the run fails (in a real pipeline the code would not be deployed)
  Medium / Low     -> a warning only, the run continues

Usage (in daily-scan.yml):  python portal/scripts/security_gate.py reports
Reads the same reports as push_reports.py, so the gate and the portal always agree.
"""
import argparse
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from push_reports import read_folder  # noqa: E402

BLOCKING = ("critical", "high")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="folder with target.json and the scanners' reports")
    args = ap.parse_args()

    target, found = read_folder(Path(args.folder))
    counts = Counter(f["severity"] for items in found.values() for f in items)
    blocking = sum(counts[s] for s in BLOCKING)
    line = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low"))
    verdict = "FAILED: Critical/High findings, the pipeline stops" if blocking else \
        "PASSED: no Critical/High findings" + (" (Medium/Low are warnings only)" if counts["medium"] + counts["low"] else "")

    print(f"{target['alias']}: {line}")
    print(f"Security Gate {verdict}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:  # shown on the run's page on GitHub
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"### Security Gate: {target['alias']}\n\n{line}\n\n**{verdict}**\n")
    sys.exit(1 if blocking else 0)


if __name__ == "__main__":
    main()
