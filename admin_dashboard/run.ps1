# Admin dashboard launcher (PowerShell). Independent of the ServiceUber app's launcher.
#   .\run.ps1         -> http://127.0.0.1:5001
#   .\run.ps1 -Test   -> run the dashboard's tests
param([switch]$Test)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path .venv\Scripts\Activate.ps1)) {
    Write-Host ">> creating virtual environment"
    if (Test-Path .venv) { Remove-Item -Recurse -Force .venv }
    try { py -3 -m venv .venv } catch { python -m venv .venv }
}
& .\.venv\Scripts\Activate.ps1
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
if (-not (Test-Path .env)) { Copy-Item .env.example .env; Write-Host ">> created .env from .env.example (DUMMY secrets - dev/test only)" }
if ($Test) { python -m pytest; exit $LASTEXITCODE }
Write-Host ">> admin dashboard on http://127.0.0.1:5001 (Ctrl+C to stop)"
python app.py
