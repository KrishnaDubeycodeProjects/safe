@echo off
setlocal enabledelayedexpansion

echo ================================================
echo   SAFE AI Backend - Digital Arrest Detector
echo   Auto Install + Run  (port 8001)
echo ================================================
echo.

REM ── Step 1: Fix PowerShell execution policy (optional, won't block if fails) ─
powershell -NonInteractive -Command "try { Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force } catch {}" >nul 2>&1

REM ── Step 2: Find Python ───────────────────────────────────────────────────────
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in PATH.
    echo         Make sure Python 3.9+ is installed and added to PATH.
    pause
    exit /b 1
)

for /f "delims=" %%i in ('where python') do set PYTHON_EXE=%%i
echo [INFO] Using Python: %PYTHON_EXE%
echo.

REM ── Step 3: Create venv if missing ───────────────────────────────────────────
if not exist "venv\Scripts\python.exe" (
    echo [1/3] Creating virtual environment...
    "%PYTHON_EXE%" -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create venv. Try: python -m pip install virtualenv
        pause
        exit /b 1
    )
    echo       Done.
) else (
    echo [1/3] Virtual environment already exists.
)
echo.

REM ── Step 4: Upgrade pip ───────────────────────────────────────────────────────
echo [2/3] Upgrading pip...
venv\Scripts\python.exe -m pip install --upgrade pip --quiet
echo       Done.
echo.

REM ── Step 5: Install packages ──────────────────────────────────────────────────
echo [3/3] Installing packages from requirements.txt...
venv\Scripts\python.exe -m pip install -r requirements.txt --quiet
echo       Done.
echo.

REM ── Step 6: Start server ──────────────────────────────────────────────────────
echo ================================================
echo   Starting API server on http://127.0.0.1:8001
echo   Docs:   http://127.0.0.1:8001/docs
echo   Health: http://127.0.0.1:8001/health
echo ================================================
echo.
echo   Press Ctrl+C to stop the server.
echo.
venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8001 --reload

pause
