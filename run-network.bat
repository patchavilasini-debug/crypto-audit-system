@echo off
REM Starts the site so other machines on the same network can reach it.
REM The window will print the address they should use.

if not exist venv\Scripts\python.exe (
  echo Setup has not been run yet. Double click setup.bat first.
  pause
  exit /b 1
)

echo Starting on the network. Leave this window open.
echo.
venv\Scripts\python.exe app.py --network
pause
