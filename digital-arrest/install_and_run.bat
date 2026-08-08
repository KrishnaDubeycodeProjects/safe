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
    echo [1/5] Creating virtual environment...
    "%PYTHON_EXE%" -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create venv. Try: python -m pip install virtualenv
        pause
        exit /b 1
    )
    echo       Done.
) else (
    echo [1/5] Virtual environment already exists.
)
echo.

REM ── Step 4: Upgrade pip ───────────────────────────────────────────────────────
echo [2/5] Upgrading pip...
venv\Scripts\python.exe -m pip install --upgrade pip --quiet
echo       Done.
echo.

REM ── Step 5: Install core packages ─────────────────────────────────────────────
echo [3/5] Installing core packages (fastapi, uvicorn, nltk, requests, slowapi)...
venv\Scripts\python.exe -m pip install ^
    fastapi ^
    "uvicorn[standard]" ^
    python-multipart ^
    pydantic ^
    "pydantic-settings>=2.0.0" ^
    "slowapi>=0.1.9" ^
    requests ^
    nltk ^
    --quiet
echo       Done.
echo.

echo [4/5] Installing ML and vision packages (numpy, opencv, scikit-learn, joblib)...
venv\Scripts\python.exe -m pip install ^
    numpy ^
    opencv-python-headless ^
    scikit-learn ^
    joblib ^
    --quiet
if %errorlevel% neq 0 (
    echo [WARN] Some ML packages failed. Core API will still work via heuristics.
) else (
    echo       Done.
)
echo.

echo       Installing optional audio package (soundfile)...
venv\Scripts\python.exe -m pip install soundfile --quiet >nul 2>&1
echo       Installing optional speech model (vosk - may take time)...
venv\Scripts\python.exe -m pip install vosk --quiet >nul 2>&1
echo       Optional packages installed (or skipped if unavailable).
echo.

REM ── Step 6: Download NLTK data ────────────────────────────────────────────────
echo [5/5] Downloading NLTK vader lexicon...
venv\Scripts\python.exe -c "import nltk; nltk.download('vader_lexicon', quiet=True)"
echo       Done.
echo.

REM ── Step 7: Start server ──────────────────────────────────────────────────────
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
