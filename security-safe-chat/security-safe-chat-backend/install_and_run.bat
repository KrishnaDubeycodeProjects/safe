@echo off
echo ================================================
echo  SAFE AI - Main Backend (Port 8000)
echo ================================================
echo.

if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

echo Installing packages...
venv\Scripts\python.exe -m pip install --upgrade pip --quiet
venv\Scripts\python.exe -m pip install -r requirements.txt --quiet

echo.
echo Starting Main Backend on port 8000...
echo  API Docs: http://127.0.0.1:8000/docs
echo  Health:   http://127.0.0.1:8000/health
echo.
venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
pause
