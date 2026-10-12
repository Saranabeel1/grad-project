"""Automatic import of the daily scans while the backend is running.

When AUTO_FETCH_REPO (your GitHub repo that runs daily-scan.yml, like name/repo) and GITHUB_TOKEN
are set, the backend runs scripts/fetch_daily.py once a minute after it starts, then every
AUTO_FETCH_HOURS hours (default 6). fetch_daily.py only brings in runs it has not seen yet,
so starting the backend after a few days away catches up on everything that was missed.
"""
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path

log = logging.getLogger("uvicorn.error")
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "fetch_daily.py"


def settings() -> dict | None:
    repo = os.getenv("AUTO_FETCH_REPO")
    if not repo or not os.getenv("GITHUB_TOKEN") or not os.getenv("PORTAL_API_KEY"):
        return None
    return {
        "repo": repo,
        "hours": float(os.getenv("AUTO_FETCH_HOURS", "6")),
        # the backend itself; hosting services such as Render choose the port in $PORT
        "url": os.getenv("AUTO_FETCH_PORTAL_URL", f"http://127.0.0.1:{os.getenv('PORT', '8000')}"),
        "key": os.getenv("PORTAL_API_KEY"),
    }


def command(cfg: dict) -> list[str]:
    return [sys.executable, str(SCRIPT), "--repo", cfg["repo"], "--send", cfg["url"], cfg["key"]]


def fetch_once(cfg: dict) -> None:
    log.info("Auto-fetch: checking %s for new daily scans", cfg["repo"])
    try:
        done = subprocess.run(
            command(cfg), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        lines = [line for line in (done.stdout + done.stderr).splitlines() if line.strip()]
        for line in lines[-8:]:  # the per-project counts and the total
            log.info("Auto-fetch: %s", line)
    except Exception as e:  # never let a failed fetch stop the backend
        log.warning("Auto-fetch failed: %s", e)


def start() -> threading.Event | None:
    """Starts the background loop. Returns an event that stops it, or None when not configured."""
    cfg = settings()
    if cfg is None:
        if os.getenv("AUTO_FETCH_REPO"):
            log.warning("Auto-fetch is off: GITHUB_TOKEN is not set")
        return None
    stop = threading.Event()

    def loop():
        if stop.wait(60):  # give the server a moment to start
            return
        while True:
            fetch_once(cfg)
            if stop.wait(cfg["hours"] * 3600):
                return

    threading.Thread(target=loop, name="auto-fetch", daemon=True).start()
    log.info("Auto-fetch is on: %s, every %s hours", cfg["repo"], cfg["hours"])
    return stop
