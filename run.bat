@echo off
REM Windows (cmd.exe) launcher: creates a venv, installs deps, prepares .env, starts the app.
REM   run.bat            -> http://127.0.0.1:5000
REM   run.bat --lan      -> also reachable from phones/tablets on the same Wi-Fi
REM   run.bat --check    -> only run the environment doctor
REM   run.bat --test     -> only run the test suite
setlocal
cd /d "%~dp0"

if not exist .venv (
  echo ^>^> creating virtual environment
  py -3 -m venv .venv 2>nul || python -m venv .venv
  if errorlevel 1 ( echo Python 3.10+ not found. Install from https://www.python.org/downloads/windows/ & exit /b 1 )
)
call .venv\Scripts\activate.bat
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
if errorlevel 1 ( echo pip install failed & exit /b 1 )
if not exist .env ( copy .env.example .env >nul & echo ^>^> created .env from .env.example ^(DUMMY secrets - dev/test only^) )

if "%~1"=="--check" ( python scripts\check_env.py & exit /b %errorlevel% )
if "%~1"=="--test"  ( python -m pytest & exit /b %errorlevel% )
if "%~1"=="--lan"   ( set HOST=0.0.0.0 )

python scripts\check_env.py
if errorlevel 1 ( echo Environment check failed & exit /b 1 )
echo ^>^> starting app ^(Ctrl+C to stop^)
python app.py
endlocal
