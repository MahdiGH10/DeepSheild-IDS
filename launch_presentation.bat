@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [DeepShield] Missing .venv. Create/install first:
  echo   python -m venv .venv
  echo   .venv\Scripts\python.exe -m pip install -r deepshield_backend\requirements.txt
  pause
  exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
  echo [DeepShield] npm is not available in PATH. Install Node.js LTS and retry.
  pause
  exit /b 1
)

if exist "scripts\reset_demo_state.py" (
  echo [DeepShield] Resetting demo state for a clean benign startup...
  .venv\Scripts\python.exe scripts\reset_demo_state.py
)

start "DeepShield Backend" cmd /k "cd /d "%~dp0deepshield_backend" && ..\.venv\Scripts\python.exe run.py"

echo [DeepShield] Waiting 3 seconds for backend warm-up...
timeout /t 3 /nobreak >nul

start "DeepShield Frontend" cmd /k "cd /d "%~dp0uii-main" && set VITE_API_BASE=http://127.0.0.1:5000 && npm run dev"

echo [DeepShield] Waiting 5 seconds for frontend startup...
timeout /t 5 /nobreak >nul

start "DeepShield Simulator" cmd /k "cd /d "%~dp0deepshield_backend" && ..\.venv\Scripts\python.exe simulate_live_traffic.py --mode benign --interval 1.3 --burst-size 6"

start "" "http://localhost:3000"

echo.
echo [DeepShield] Presentation mode is live (benign-only):
echo   Backend:   http://127.0.0.1:5000
echo   Frontend:  http://localhost:3000
echo   Simulator: benign baseline running in separate terminal
echo.
echo [DeepShield] To inject attack types and trigger email automation, open: launch_attack_control.bat
endlocal
