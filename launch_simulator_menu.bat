@echo off
setlocal
cd /d "%~dp0\deepshield_backend"

if not exist "..\.venv\Scripts\python.exe" (
  echo [DeepShield] .venv not found. Create it first.
  pause
  exit /b 1
)

set BASE_URL=http://127.0.0.1:5000
rem One burst = one incident signature (stable source/target in simulator) -> one auto-email.
set BURST_SIZE=8
set CYCLES=1
set INTERVAL=1.0

:MAIN_MENU
cls
color 0C
title DeepShield Red-Team Console
echo ======================================================================
echo   DEEPSHIELD RED-TEAM CONSOLE  ::  CONTROLLED PRESENTATION MODE
echo ======================================================================
echo   operator : analyst-demo
echo   target   : %BASE_URL%
echo   payloads : known taxonomy + unknown zero-day emergency
echo ----------------------------------------------------------------------
echo   Burst size   : %BURST_SIZE%
echo   Cycles       : %CYCLES%
echo   Interval (s) : %INTERVAL%
echo ======================================================================
echo.
"..\.venv\Scripts\python.exe" simulate_live_traffic.py --print-attack-menu
echo.
set ATTACK_CHOICE=
set /p ATTACK_CHOICE=Select option [1-15, S, Q] ^(default 1^): 

if /I "%ATTACK_CHOICE%"=="Q" goto END
if /I "%ATTACK_CHOICE%"=="S" goto SETTINGS

set ATTACK_TYPE=DoS Hulk
if "%ATTACK_CHOICE%"=="2" set ATTACK_TYPE=DDoS
if "%ATTACK_CHOICE%"=="3" set ATTACK_TYPE=PortScan
if "%ATTACK_CHOICE%"=="4" set ATTACK_TYPE=FTP-Patator
if "%ATTACK_CHOICE%"=="5" set ATTACK_TYPE=SSH-Patator
if "%ATTACK_CHOICE%"=="6" set ATTACK_TYPE=Infiltration
if "%ATTACK_CHOICE%"=="7" set ATTACK_TYPE=Heartbleed
if "%ATTACK_CHOICE%"=="8" set ATTACK_TYPE=DoS GoldenEye
if "%ATTACK_CHOICE%"=="9" set ATTACK_TYPE=DoS Slowhttptest
if "%ATTACK_CHOICE%"=="10" set ATTACK_TYPE=DoS slowloris
if "%ATTACK_CHOICE%"=="11" set ATTACK_TYPE=Bot
if "%ATTACK_CHOICE%"=="12" set ATTACK_TYPE=Web Attack - Brute Force
if "%ATTACK_CHOICE%"=="13" set ATTACK_TYPE=Web Attack - Sql Injection
if "%ATTACK_CHOICE%"=="14" set ATTACK_TYPE=Web Attack - XSS
if "%ATTACK_CHOICE%"=="15" set ATTACK_TYPE=Unknown Zero-Day Exploit Chain

echo.
cls
echo ======================================================================
echo   PAYLOAD ARMING SEQUENCE
echo ======================================================================
echo [operator@red-team] arming payload profile...
echo [payload] signature  : %ATTACK_TYPE%
echo [target]  backend    : %BASE_URL%
echo [burst]   packets    : %BURST_SIZE% x %CYCLES%
echo [timing]  interval   : %INTERVAL%s
if /I "%ATTACK_TYPE%"=="Unknown Zero-Day Exploit Chain" (
  echo [warning] UNKNOWN SIGNATURE MODE - DeepShield should declare CRITICAL emergency
  echo [warning] SOC action expected: isolate target, preserve logs, dispatch emergency PDF
)
echo [console] executing controlled attack simulation for presentation
echo ======================================================================
echo.

"..\.venv\Scripts\python.exe" simulate_live_traffic.py --mode attack --attack-type "%ATTACK_TYPE%" --base-url "%BASE_URL%" --interval %INTERVAL% --burst-size %BURST_SIZE% --cycles %CYCLES%

echo.
echo [DeepShield] Injection finished. Press any key to return to menu...
pause >nul
goto MAIN_MENU

:SETTINGS
cls
echo ================================================================
echo   DeepShield Attack Controller - Settings
echo ================================================================
echo Current values:
echo   Base URL  : %BASE_URL%
echo   BurstSize : %BURST_SIZE%
echo   Cycles    : %CYCLES%
echo   Interval  : %INTERVAL%
echo.
echo Presets:
echo   1^) Light demo    ^(burst=6,  cycles=3, interval=1.0^)
echo   2^) Balanced demo ^(burst=10, cycles=6, interval=0.8^)
echo   3^) Intense demo  ^(burst=14, cycles=9, interval=0.6^)
echo   4^) Custom values
echo   5^) Change backend URL only
echo   B^) Back to attack menu
echo.
set SETTINGS_CHOICE=
set /p SETTINGS_CHOICE=Select settings option [1-5, B]: 

if /I "%SETTINGS_CHOICE%"=="B" goto MAIN_MENU
if "%SETTINGS_CHOICE%"=="1" (
  set BURST_SIZE=6
  set CYCLES=3
  set INTERVAL=1.0
  goto SETTINGS_SAVED
)
if "%SETTINGS_CHOICE%"=="2" (
  set BURST_SIZE=10
  set CYCLES=6
  set INTERVAL=0.8
  goto SETTINGS_SAVED
)
if "%SETTINGS_CHOICE%"=="3" (
  set BURST_SIZE=14
  set CYCLES=9
  set INTERVAL=0.6
  goto SETTINGS_SAVED
)
if "%SETTINGS_CHOICE%"=="4" goto CUSTOM_VALUES
if "%SETTINGS_CHOICE%"=="5" goto CHANGE_URL

echo.
echo [DeepShield] Invalid selection.
pause
goto SETTINGS

:CHANGE_URL
echo.
set NEW_BASE_URL=
set /p NEW_BASE_URL=Enter backend URL ^(example http://127.0.0.1:5000^): 
if not "%NEW_BASE_URL%"=="" set BASE_URL=%NEW_BASE_URL%
goto SETTINGS_SAVED

:CUSTOM_VALUES
echo.
set NEW_BURST=
set NEW_CYCLES=
set NEW_INTERVAL=
set /p NEW_BURST=Enter burst size ^(current %BURST_SIZE%^): 
set /p NEW_CYCLES=Enter cycles ^(current %CYCLES%^): 
set /p NEW_INTERVAL=Enter interval seconds ^(current %INTERVAL%^): 

if not "%NEW_BURST%"=="" set BURST_SIZE=%NEW_BURST%
if not "%NEW_CYCLES%"=="" set CYCLES=%NEW_CYCLES%
if not "%NEW_INTERVAL%"=="" set INTERVAL=%NEW_INTERVAL%
goto SETTINGS_SAVED

:SETTINGS_SAVED
echo.
echo [DeepShield] Settings updated.
echo   Base URL  : %BASE_URL%
echo   BurstSize : %BURST_SIZE%
echo   Cycles    : %CYCLES%
echo   Interval  : %INTERVAL%
pause
goto MAIN_MENU

:END
echo.
echo [DeepShield] Controller closed.
endlocal
