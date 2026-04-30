@echo off
title BMC 2600 IP Finder

echo.
echo  ==========================================
echo       BMC 2600 IP Finder
echo  ==========================================
echo.

cd /d "%~dp0"

python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found.
    echo  Please install Python 3.10+: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo  Starting server...
echo  Browser will open http://localhost:5000 in 2 seconds.
echo  Press Ctrl+C to stop the server.
echo  ------------------------------------------
echo.

start "" cmd /c "timeout /t 2 >nul && start http://localhost:5000"

python app.py

echo.
echo  Server stopped.
pause
