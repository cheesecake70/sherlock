@echo off
rem Sherlock - Windows launcher. Installs requirements, starts the server, opens the dashboard.
cd /d "%~dp0"

echo Installing requirements...
py -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo Install failed. Check that Python 3.10+ is installed and the "py" launcher works.
    pause
    exit /b 1
)

echo Starting Sherlock at http://127.0.0.1:8000 (Ctrl+C to stop)
start "" cmd /c "timeout /t 3 /nobreak >nul & start http://127.0.0.1:8000"
py -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
pause
