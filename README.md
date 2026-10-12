# Unified DevSecOps Telemetry Portal: starter (P030)

A thin end-to-end slice: **GitHub Actions pipeline → scanners → FastAPI → database → React dashboard**.

```
.github/workflows/security-scan.yml   pipeline: runs Semgrep, sends results to the portal
scripts/send_results.py               converts Semgrep JSON → portal format and POSTs it (stdlib only)
sample-target/app.py                  deliberately insecure code for the scanner to find
backend/                              FastAPI + SQLAlchemy API, tests, Dockerfile
frontend/                             React + TypeScript + Recharts dashboard (see frontend/README.md)
docker-compose.yml                    PostgreSQL + backend
```

## 1. Run the backend (no Docker, SQLite)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest                                     # 15 tests
PORTAL_API_KEY=dev-key uvicorn app.main:app --reload
```
Open http://localhost:8000/docs for the interactive API page.

## 1b. Run the dashboard

With the backend running, open a second terminal:
```bash
cd frontend
npm install      # first time only (needs Node.js 20+)
npm run dev      # then open http://localhost:5173
```
Step-by-step Windows instructions and what each number means: `frontend/README.md`.

## 2. Run with PostgreSQL (Docker)

```bash
cp .env.example .env      # edit the two secrets
docker compose up --build
```

## 3. Send a test finding

```bash
curl -X POST http://localhost:8000/api/ingest/scan \
  -H "Content-Type: application/json" -H "X-API-Key: dev-key" \
  -d '{"repo":"team/demo","branch":"main","commit_sha":"abc1234","run_id":"1",
       "tool":"semgrep","tool_type":"SAST",
       "findings":[{"rule_id":"demo.eval","title":"eval","severity":"high",
                    "cwe":"CWE-95","file":"app.py","line":7}]}'
curl localhost:8000/api/summary
```
Sending the same finding again updates it instead of duplicating (fingerprint = repo + tool + rule + file + line).

## 4. Connect the GitHub pipeline

1. Push this folder to a GitHub repo.
2. Settings → Secrets and variables → Actions → add `PORTAL_URL` and `PORTAL_API_KEY`.
3. Actions tab → *security-scan* → Run workflow.

**Important:** GitHub-hosted runners cannot reach `localhost`. `PORTAL_URL` must be a public address
(deployed backend, or a tunnel such as ngrok / Cloudflare Tunnel during development), or use a self-hosted runner.
Without the secrets the workflow still scans and uploads `semgrep.json` as an artifact; it just doesn't send.

## What was tested

- Backend: 9 automated tests pass; live server smoke test with the real script: ingest, re-ingest without duplicates, run status, summary, wrong key → 401.
- `send_results.py` run on real Semgrep 1.180 output (using a local rule file).
- Workflow and compose files parse as valid YAML.

## What was NOT tested

- The workflow on real GitHub (needs your repo). The `p/default` ruleset needs internet access to semgrep.dev, which works on GitHub runners.
- `docker compose` / PostgreSQL (no Docker where this was built). SQLAlchemy code is database-neutral, but run it once and tell me if anything breaks.

## Before this is more than a demo

- Replace the dev defaults (`dev-change-me`, `portal_dev_password`) with real secrets.
- Add migrations (Alembic) and pagination in the UI.
- Next milestones: login + roles → finding detail page → mark findings Fixed when a scan no longer reports them → AI remediation with human approval.

## Daily scans of public projects (our own live data)

`.github/workflows/daily-scan.yml` runs Semgrep, Trivy, Checkov, ZAP and SonarQube on three public projects each time one of them gets a new commit
(a quick check every 15 minutes compares each project's latest commit with the last one scanned; unchanged projects are skipped)
(Juice Shop, WebGoat, Online Boutique; shown as Project G, H, I). ZAP scans a running copy of the website,
started inside the job. Each project's reports are saved as an artifact named `daily-<alias>`.
A **Security Gate** step (`scripts/security_gate.py`) then fails the run when there is any Critical or High finding;
Medium/Low are warnings only. Results are still sent and saved, and the portal shows the run as failed.

1. Put `daily-scan.yml` in `.github/workflows/` of your GitHub repository (only this file is needed there).
2. Actions tab → *daily-scan* → Run workflow (this always scans all three), or wait: new commits are picked up within about 15 minutes.
3. On your computer, with the portal running:
   `python scripts/fetch_daily.py --repo YOUR_NAME/YOUR_REPO --send http://localhost:8000 dev-key`
   It uses the same GitHub token as `fetch_live.py` and only brings in runs it has not seen yet.

Tested: the reader and portal sending on real Checkov and Semgrep output from Online Boutique (425 findings,
no duplicates on a second run). Not tested here: the workflow on GitHub itself. GitHub pauses scheduled
workflows after 60 days with no activity in the repository.

## 6. SonarQube (fifth scanner, SAST)

`daily-scan.yml` also runs SonarQube on each project. SonarQube keeps results on a server, so each run starts a
fresh SonarQube Community Build in Docker, scans the code, and `scripts/export_sonarqube.py` saves the security
issues and hotspots to `reports/sonarqube.json` (code smells are left out). The server is then thrown away.
Nothing to set up: no account, no secrets. `fetch_daily.py` reads `sonarqube.json` like the other reports and sends
it to the portal as `tool: sonarqube`, `tool_type: SAST`.

To try it on your PC (needs Docker):
```bash
docker run -d --name sonarqube -p 9000:9000 sonarqube:community   # open http://localhost:9000, log in admin/admin
# My Account > Security > generate a *user* token, then scan a folder:
docker run --rm --network host -v "$PWD/sample-target:/usr/src" -e SONAR_HOST_URL=http://localhost:9000 \
  -e SONAR_TOKEN=YOUR_TOKEN sonarsource/sonar-scanner-cli -Dsonar.projectKey=demo
SONAR_HOST_URL=http://localhost:9000 SONAR_TOKEN=YOUR_TOKEN python scripts/export_sonarqube.py --project demo
```
Tested here with SonarQube 26.9: Juice Shop 85 security findings, microservices-demo 54, WebGoat 61.
Java projects are scanned without building them first, so Java results are a little less precise.

## 7. Automatic updates (no manual fetching)

The backend can bring in new daily scans by itself. While it is running, it runs `scripts/fetch_daily.py`
one minute after starting and then every `AUTO_FETCH_HOURS` hours (1 in `start-portal.cmd`), and the dashboard reloads its data every 5 minutes.
Only runs it has not seen yet are imported, so after a few days with the PC off, the next start catches up.

One-time setup on Windows:
1. Save your GitHub token for your Windows user (it is not stored in any project file). In a terminal:
   `setx GITHUB_TOKEN "paste-your-token-here"`
   then close and reopen VS Code / the terminal.
2. Open `start-portal.cmd` and check `AUTO_FETCH_REPO` is your repository and `DATABASE_URL` is the database you want.

Every time: double-click `start-portal.cmd`. It opens the backend and the dashboard in two windows and then the browser.
The backend window shows lines starting with `Auto-fetch:` when it checks GitHub.

Settings (environment variables): `AUTO_FETCH_REPO` (turns it on), `GITHUB_TOKEN`, `AUTO_FETCH_HOURS` (default 6),
`AUTO_FETCH_PORTAL_URL` (default `http://127.0.0.1:8000`). Without `AUTO_FETCH_REPO` or `GITHUB_TOKEN` nothing runs.
Updates only happen while the backend is running on your PC; a server that is always on would be needed for 24/7 updates.

## 8. Real-time push (GitHub sends results to the portal as soon as a scan finishes)

At the end of each project's scan, `daily-scan.yml` runs `scripts/push_reports.py`, which sends the results straight
to the portal (`/api/ingest/run` and `/api/ingest/scan`). GitHub's machines cannot reach `localhost`, so the portal needs
a public address. A free ngrok account gives your PC one fixed address while the tunnel runs.

One-time setup:
1. Make a long random key and save it for your Windows user (PowerShell):
   `$k = -join ((48..57)+(97..122) | Get-Random -Count 32 | % {[char]$_}); setx PORTAL_API_KEY $k; $k`
   Copy the key it prints; you need it in step 5.
2. Sign up at ngrok.com (free), then install ngrok: `winget install ngrok.ngrok` (or download it from ngrok.com).
   Check `ngrok version` shows 3.20 or newer (free accounts need it); if not, run `ngrok update`.
3. Connect it to your account: `ngrok config add-authtoken YOUR_NGROK_TOKEN` (the token is on the ngrok dashboard).
4. On the ngrok dashboard, open **Domains** and copy your free domain (like `something.ngrok-free.app`), then:
   `setx PORTAL_PUBLIC_DOMAIN "something.ngrok-free.app"`
5. On GitHub: your repo → Settings → Secrets and variables → Actions → New repository secret, twice:
   `PORTAL_URL` = `https://something.ngrok-free.app` and `PORTAL_API_KEY` = the key from step 1.
6. Close and reopen VS Code / File Explorer so the new values are picked up.
7. The repo needs `scripts/push_reports.py`, `scripts/report_readers.py` and `scripts/security_gate.py` (the workflow runs them).
   Never upload `scripts/fetch_live.py`: it holds the real names of Projects A-F (it is in `.gitignore`).

Every time: double-click `start-portal.cmd`. A third window ("SecFlow tunnel") opens ngrok. When a scan finishes, the
GitHub log shows "Send results to the portal" with the counts, and the dashboard shows them within 5 minutes
(or press F5). If the PC is off, the push fails without breaking the scan, and auto-fetch brings the results in later.
Anyone who knows the address can read the dashboard data (the scanned projects are public and shown as aliases);
only the key can add or change data.

## 9. Share the dashboard with your team

`start-portal.cmd` builds the dashboard, and the backend serves that build at its own address. So while the three
windows are open, the dashboard works at **http://localhost:8000** and, through the ngrok tunnel, at your
**https://...ngrok-free.dev** link. Send that link to your team: it opens the full dashboard in any browser, phone included.
The first time, ngrok shows a "You are about to visit" page; click **Visit Site**.

- It only works while your PC is on and `start-portal.cmd` is running.
- Anyone with the link can read the dashboard (only aliases and public projects are in `daily.db`). Sending results
  still needs `PORTAL_API_KEY`, so nobody can change the data.
- The build is refreshed each time you start `start-portal.cmd`; after a code change, restart it.

## 10. Put the portal online (works when your PC is off)

The `Dockerfile` in the top folder packs the dashboard and the backend into one app that a hosting service runs.
Free setup: **Neon** keeps the data (PostgreSQL), **Render** runs the app. Neither needs a credit card.

1. The repo must contain `backend/`, `frontend/`, `scripts/` and `Dockerfile`
   (never `scripts/fetch_live.py`, `live-data/` or any `.db` file; `.gitignore` keeps them out).
2. **Neon** (neon.tech): sign up with GitHub → create a project → copy the *connection string*
   (starts with `postgresql://`).
3. **Render** (render.com): sign up with GitHub → **New → Web Service** → pick your repo → Language **Docker**,
   Instance type **Free**. Under *Environment Variables* add:
   - `DATABASE_URL` = the Neon connection string
   - `PORTAL_API_KEY` = your key (the same as the GitHub secret)
   - `SESSION_SECRET` = any long random text (keeps people signed in when the app restarts)
   - `AUTO_FETCH_REPO` = `YOUR_NAME/YOUR_REPO`, `GITHUB_TOKEN` = your token, `AUTO_FETCH_HOURS` = `1`
   Then **Deploy**. Render gives the app an address like `https://secflow-xxxx.onrender.com`.
4. On GitHub, change the `PORTAL_URL` secret to that address, so scans are sent to the online portal.
5. Make the accounts from your PC, pointed at Neon (Render's free plan has no Shell). In PowerShell:
   ```
   cd backend
   $env:DATABASE_URL="the Neon connection string"
   .venv\Scripts\python.exe -m app.users add
   ```
   Accounts on your PC (`daily.db`) are separate, so add yourself again here.
6. Send the address to your team.

Notes: the free app sleeps after 15 minutes without visitors; the next visit wakes it in about a minute.
Every push to the repo redeploys it. The secrets live only in Render's settings, never in the repo.

## 11. Accounts and sign in

Everyone now signs in. Managers see every project. Developers see only the projects you give them.
They can assign findings, mark them fixed, and see their team.

Make accounts on the PC that runs the portal (Windows, in VS Code's terminal):

```
cd backend
set DATABASE_URL=sqlite:///./daily.db
.venv\Scripts\python.exe -m app.users add
```

It asks for the email, name, role (manager or developer), the projects (for a developer), and a password (at least 8 characters).

Other commands:

```
.venv\Scripts\python.exe -m app.users list
.venv\Scripts\python.exe -m app.users password name@cyberani.sa
.venv\Scripts\python.exe -m app.users projects name@cyberani.sa "Project G,Project H"
.venv\Scripts\python.exe -m app.users remove name@cyberani.sa
```

In PowerShell use `$env:DATABASE_URL="sqlite:///./daily.db"` instead of the `set` line.
Online: run the same commands with `DATABASE_URL` set to the Neon connection string (section 10, step 5).
GitHub Actions still sends results with the X-API-Key header, so nothing changes there.
Set a SESSION_SECRET environment variable when hosting so sign-ins survive restarts.
