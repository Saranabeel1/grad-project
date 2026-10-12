# SecFlow dashboard (React + TypeScript + Recharts)

Screens follow the team's Figma design (manager view):

- **Dashboard (Overview)**: cards for open findings, pipeline success rate, mean time to fix and risk warnings;
  open findings by severity, findings over time, findings by tool type, projects compared, and the top risk warnings.
- **Projects**: every project with its scanners, open findings by severity, pass rate and last run.
- **Project page** (click a project): read-only view with "Switch project", severity bars, trend, findings and recent runs.
- **Findings**: searchable table with filters for project, tool, category, severity and status. Click a row for details.
- **Pipeline Status**: all runs with the Security Gate rule on top and a link to each run on GitHub.
- **Risk Insights**: rule-based warnings (no AI) and the most repeated vulnerability types.

Not built yet (they need login, team assignment and the AI fix feature): sign-in, the developer view,
finding detail with the suggested fix, and the team page.

The address bar keeps the page and filters, so you can bookmark a view or use the browser Back button.

## Run it (Windows, VS Code)

You need **Node.js 20 or newer** (https://nodejs.org, the LTS installer). Check in a terminal: `node -v`.

1. Start the backend first (terminal 1), with the database you want to show:
   ```powershell
   cd portal-starter\backend
   $env:DATABASE_URL="sqlite:///./daily.db"
   $env:PORTAL_API_KEY="dev-key"
   .venv\Scripts\python.exe -m uvicorn app.main:app --reload
   ```
2. Open a second terminal in VS Code (the **+** button in the terminal panel) and start the dashboard:
   ```powershell
   cd portal-starter\frontend
   npm.cmd install    # only the first time
   npm.cmd run dev
   ```
3. Open http://localhost:5173 in your browser.

`npm.cmd` instead of `npm` avoids the PowerShell "running scripts is disabled" error.

If the page says "Could not reach the backend", check that terminal 1 is still running and that
http://localhost:8000/docs opens.

## Notes on the numbers

- **Open findings** counts findings with status `open`. "Still in the latest scan" is how many of them the most
  recent scan by the same tool on the same project still reports.
- **Mean time to fix** is an estimate: for findings that the latest scan no longer reports, the days between
  first seen and last seen. The backend does not yet mark findings as Fixed by itself.
- **Pipeline pass rate** uses the runs sent to `/api/ingest/run` (passed / passed + failed).
- **Findings over time** counts a finding on each day between its first and last scan (up to the last 180 days),
  one point per week when there are more than two weeks of data. "Improving" means the last point is lower than the first.
- **Risk warnings** come from `backend/app/insights.py`: the same vulnerability type (CWE, or the scanner rule) open in
  2+ projects or 3+ times in one project, a project whose last 3 runs failed, and projects with fewer findings than a week ago.

## Files

```
src/api.ts                  calls to the backend + data types
src/nav.ts                  page and filter state in the address bar
src/pages/                  one file per screen (Dashboard, Projects, Project, Findings, Runs, Insights)
src/components/             cards, badges, charts, insight cards
src/assets/logo.png         SecFlow logo from the Figma file
src/index.css               styles (colours, spacing and font from the Figma design)
```

To use a different backend address, copy `.env.example` to `.env` and change `VITE_API_URL`.
