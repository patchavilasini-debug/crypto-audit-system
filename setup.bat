@echo off
REM One time setup. Double click this, or run:  setup.bat
REM Creates a private Python environment and installs what the site needs.

echo ============================================================
echo  CRYPTO AUDIT SYSTEM - SETUP
echo ============================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
  echo Python is not installed, or not on the PATH.
  echo.
  echo Download it from https://python.org/downloads
  echo On the first screen of the installer, TICK
  echo    "Add python.exe to PATH"
  echo.
  pause
  exit /b 1
)

echo Python found:
python --version
echo.

if not exist venv (
  echo Creating a private environment in the venv folder...
  python -m venv venv
) else (
  echo Environment already exists, reusing it.
)

echo.
echo Installing Flask, cryptography and waitress...
call venv\Scripts\python.exe -m pip install --upgrade pip --quiet
call venv\Scripts\python.exe -m pip install -r requirements.txt

echo.
echo ============================================================
echo  DONE
echo ============================================================
echo.
echo  Start the site by double clicking:  run.bat
echo  Or for other machines to reach it:  run-network.bat
echo.
pause
