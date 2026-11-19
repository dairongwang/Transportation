@echo off
REM Admin dashboard launcher (Windows cmd.exe). Independent of the ServiceUber app's launcher.
REM   run.bat          -> http://127.0.0.1:5001
REM   run.bat --test   -> run the dashboard's tests
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\activate.bat (
  echo ^>^> creating virtual environment
  if exist .venv rmdir /s /q .venv
  py -3 -m venv .venv 2>nul || python -m venv .venv
  if errorlevel 1 ( echo Python 3.10+ not found. & exit /b 1 )
)
call .venv\Scripts\activate.bat
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
if errorlevel 1 ( echo pip install failed & exit /b 1 )
if not exist .env ( copy .env.example .env >nul & echo ^>^> created .env from .env.example ^(DUMMY secrets - dev/test only^) )
if "%~1"=="--test" ( python -m pytest & exit /b %errorlevel% )
echo ^>^> admin dashboard on http://127.0.0.1:5001 ^(Ctrl+C to stop^)
python app.py
endlocal
