@echo off
REM Starts the production server.
REM Edit the secret key below before first use. Generate one with:
REM    python -c "import secrets; print(secrets.token_urlsafe(32))"

set CRYPTO_AUDIT_ENV=production
set CRYPTO_AUDIT_SECRET=CHANGE-THIS-TO-A-LONG-RANDOM-STRING
set CRYPTO_AUDIT_PORT=8000
REM set CRYPTO_AUDIT_HTTPS=1     (uncomment when HTTPS is in front)

if "%CRYPTO_AUDIT_SECRET%"=="CHANGE-THIS-TO-A-LONG-RANDOM-STRING" (
  echo.
  echo  Edit run-production.bat and set a real secret key first.
  echo  Generate one with:
  echo     python -c "import secrets; print(secrets.token_urlsafe(32))"
  echo.
  pause
  exit /b 1
)

if exist venv\Scripts\python.exe (
  venv\Scripts\python.exe serve.py
) else (
  python serve.py
)
pause
