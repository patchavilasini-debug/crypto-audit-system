@echo off
REM Starts the site for this machine only.

if not exist venv\Scripts\python.exe (
  echo Setup has not been run yet. Double click setup.bat first.
  pause
  exit /b 1
)

echo Starting. Leave this window open. Close it or press Ctrl+C to stop.
echo.
venv\Scripts\python.exe app.py
pause
