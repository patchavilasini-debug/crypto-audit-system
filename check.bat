@echo off
REM Runs each engine on its own, to prove the backend works
REM before you worry about the web pages.

if not exist venv\Scripts\python.exe (
  echo Setup has not been run yet. Double click setup.bat first.
  pause
  exit /b 1
)

echo ============================================================
echo  1. THE KNOWLEDGE BASE
echo ============================================================
venv\Scripts\python.exe crypto_rules.py

echo.
echo ============================================================
echo  2. THE SCORING FORMULA
echo ============================================================
venv\Scripts\python.exe risk_engine.py

echo.
echo ============================================================
echo  3. RANKING AND RECOMMENDATIONS
echo ============================================================
venv\Scripts\python.exe recommendation_engine.py

echo.
echo ============================================================
echo  4. THE DATABASE
echo ============================================================
venv\Scripts\python.exe database.py

echo.
echo ============================================================
echo  5. A REAL SCAN
echo ============================================================
venv\Scripts\python.exe scanner.py github.com

echo.
echo ============================================================
echo  6. CRYPTO-AGILITY
echo ============================================================
venv\Scripts\python.exe crypto_service.py

echo.
echo ============================================================
echo  If all six printed results, the backend is working.
echo ============================================================
pause
