@echo off
REM Copies the database to the backups folder.
REM Point Windows Task Scheduler at this to run it daily.
cd /d "%~dp0"
if exist venv\Scripts\python.exe (
  venv\Scripts\python.exe backup.py
) else (
  python backup.py
)
