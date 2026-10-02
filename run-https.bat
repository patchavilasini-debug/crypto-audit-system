@echo off
REM Starts the site over HTTPS, making a certificate first if needed.

if not exist venv\Scripts\python.exe (
  echo Setup has not been run yet. Double click setup.bat first.
  pause
  exit /b 1
)

if not exist certs\site.crt (
  echo No certificate yet. Making one...
  venv\Scripts\python.exe make_cert.py
  echo.
)

echo Starting over HTTPS on the network. Leave this window open.
echo Your browser will warn about the certificate. That is expected.
echo.
venv\Scripts\python.exe app.py --network --https
pause
