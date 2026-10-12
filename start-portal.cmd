@echo off
rem Starts the SecFlow portal: backend + dashboard (+ the public tunnel), each in its own window, then opens the browser.
rem Double-click this file in File Explorer, or run .\start-portal.cmd from a terminal in this folder.
rem Secrets are NOT written here (this file is in a public repo). Save them once for your Windows user with setx:
rem   setx GITHUB_TOKEN "..."           lets the backend fetch new scans by itself (README section 7)
rem   setx PORTAL_API_KEY "..."         the key GitHub uses to send results (README section 8)
rem   setx PORTAL_PUBLIC_DOMAIN "..."   your free ngrok address, for real-time push (README section 8)

rem ---- settings you can change ----
set DATABASE_URL=sqlite:///./daily.db
set AUTO_FETCH_REPO=saranabeel1/grad-project
set AUTO_FETCH_HOURS=1
rem ---------------------------------

cd /d "%~dp0"
if "%PORTAL_API_KEY%"=="" set PORTAL_API_KEY=dev-key
if "%GITHUB_TOKEN%"=="" echo GITHUB_TOKEN is not set, so new scans will not be fetched automatically. See README section 7.

rem Build the dashboard first, so the backend can also serve it on port 8000 (the link you share with your team).
echo Building the dashboard...
pushd frontend
call npm.cmd run build >nul 2>&1 || echo The dashboard build failed: the shared link will not show it, localhost:5173 still works.
popd

start "SecFlow backend" cmd /k "cd backend && .venv\Scripts\python.exe -m uvicorn app.main:app"
start "SecFlow dashboard" cmd /k "cd frontend && npm.cmd run dev"

if "%PORTAL_PUBLIC_DOMAIN%"=="" (
  echo PORTAL_PUBLIC_DOMAIN is not set, so GitHub cannot send results in real time. See README section 8.
  set TUNNEL_PROBLEM=1
) else (
  if "%PORTAL_API_KEY%"=="dev-key" (
    echo Not opening the tunnel: set your own PORTAL_API_KEY first, dev-key is not safe on the internet. See README section 8.
    set TUNNEL_PROBLEM=1
  ) else (
    start "SecFlow tunnel" cmd /k "ngrok http --domain=%PORTAL_PUBLIC_DOMAIN% 8000"
  )
)

timeout /t 6 /nobreak >nul
start "" http://localhost:5173
if defined TUNNEL_PROBLEM pause
