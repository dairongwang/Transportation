# Windows (PowerShell) launcher: creates a venv, installs deps, prepares .env, starts the app.
#   .\run.ps1            -> http://127.0.0.1:5000
#   .\run.ps1 -Lan       -> also reachable from phones/tablets on the same Wi-Fi
#   .\run.ps1 -Check     -> only run the environment doctor
#   .\run.ps1 -Test      -> only run the test suite
# If scripts are blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
param([switch]$Lan, [switch]$Check, [switch]$Test)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .venv)) {
    Write-Host ">> creating virtual environment"
    try { py -3 -m venv .venv } catch { python -m venv .venv }
}
& .\.venv\Scripts\Activate.ps1
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
if (-not (Test-Path .env)) { Copy-Item .env.example .env; Write-Host ">> created .env from .env.example (DUMMY secrets - dev/test only)" }

if ($Check) { python scripts\check_env.py; exit $LASTEXITCODE }
if ($Test)  { python -m pytest; exit $LASTEXITCODE }
if ($Lan)   { $env:HOST = "0.0.0.0" }

python scripts\check_env.py
if ($LASTEXITCODE -ne 0) { throw "Environment check failed" }
Write-Host ">> starting app (Ctrl+C to stop)"
python app.py
