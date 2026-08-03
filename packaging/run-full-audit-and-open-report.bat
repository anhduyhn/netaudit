@echo off
REM One-click, non-interactive audit: audit -> drift analysis -> open the
REM HTML report. Use this when you just want the report.
REM
REM (Double-clicking netauditor.exe itself opens the interactive dashboard
REM instead - same tool, different entry point.)
REM
REM Put this file, netauditor.exe and your filled-in inventory.yml in the
REM same folder, then double-click it. Results are saved to the "out" folder.
cd /d "%~dp0"

if not exist netauditor.exe (
    echo netauditor.exe was not found next to this script.
    pause
    exit /b 1
)
if not exist inventory.yml (
    echo No inventory.yml found next to this script.
    echo Copy the inventory template here, rename it inventory.yml and fill in
    echo your switch IPs and credentials, then run this again.
    pause
    exit /b 1
)

netauditor.exe audit -i inventory.yml -o out
if errorlevel 2 (
    echo.
    echo Audit could not run - see the message above.
    pause
    exit /b 2
)

netauditor.exe analyze out -o out --tests all

start "" "out\audit.html"
echo.
echo Reports are in the "out" folder - audit.html just opened in your browser.
pause
