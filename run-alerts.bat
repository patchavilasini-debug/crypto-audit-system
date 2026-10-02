@echo off
REM Checks every expiry subscription once and emails anyone who is due.
REM Point Windows Task Scheduler at this file to run it every day.
REM
REM For real email rather than the outbox, uncomment and fill in:
REM set CRYPTO_AUDIT_SMTP_HOST=smtp.gmail.com
REM set CRYPTO_AUDIT_SMTP_PORT=587
REM set CRYPTO_AUDIT_SMTP_USER=youraddress@gmail.com
REM set CRYPTO_AUDIT_SMTP_PASS=your-app-password

cd /d "%~dp0"

if exist venv\Scripts\python.exe (
  venv\Scripts\python.exe notifier.py
) else (
  python notifier.py
)
