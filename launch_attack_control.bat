@echo off
setlocal
cd /d "%~dp0"

color 0C
title DeepShield Red-Team Console

if not exist ".venv\Scripts\python.exe" (
  echo [DeepShield] .venv not found. Create it first.
  pause
  exit /b 1
)

cls
echo ================================================================
echo   DEEPSHIELD RED-TEAM CONSOLE
echo ================================================================
echo   Controlled adversary simulation interface
echo   Unknown attack option arms a critical zero-day scenario
echo ================================================================
echo.

start "DeepShield Red-Team Console" cmd /k ""%~dp0launch_simulator_menu.bat""

echo [DeepShield] Red-team console opened in a new terminal.
echo [DeepShield] Use option 15 for the unknown critical attack demo.
pause
endlocal
