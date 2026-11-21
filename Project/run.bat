@echo off
title AES-Based Secure Backup and Recovery System
echo ============================================================
echo   AES-Based Secure Backup and Recovery System
echo   AES-256-GCM + scrypt KDF + SQLite + Flask Web Dashboard
echo ============================================================
echo.

set PYTHON_CMD=python
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    if exist "%LOCALAPPDATA%\Python\bin\python.exe" (
        set "PYTHON_CMD=%LOCALAPPDATA%\Python\bin\python.exe"
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
        set "PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
        set "PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    )
)

echo Starting Flask server with: %PYTHON_CMD%
echo Open your browser at: http://127.0.0.1:5000
echo.
"%PYTHON_CMD%" app.py
pause
