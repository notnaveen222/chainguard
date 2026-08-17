<#
.SYNOPSIS
    Start ChainGuard: the API server and the dashboard.

.DESCRIPTION
    Opens each service in its own window so the logs stay visible and either can
    be stopped independently — which matters during a live demo, where a silent
    background failure is far worse than a visible one.

    Run from the repository root:  .\scripts\start.ps1
#>

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'

if (-not (Test-Path $python)) {
    Write-Host "No virtual environment found at $python" -ForegroundColor Red
    Write-Host "Create it first:" -ForegroundColor Yellow
    Write-Host "  python -m venv .venv"
    Write-Host "  .venv\Scripts\activate"
    Write-Host "  pip install -r requirements.txt"
    exit 1
}

if (-not (Test-Path (Join-Path $root 'frontend\node_modules'))) {
    Write-Host "Frontend dependencies are not installed." -ForegroundColor Yellow
    Write-Host "  cd frontend && npm install"
    exit 1
}

Write-Host ''
Write-Host '  ChainGuard' -ForegroundColor Cyan
Write-Host '  Malicious package detection and vulnerability reachability analysis'
Write-Host ''

# --- API ------------------------------------------------------------------- #
Write-Host '  Starting the API on http://127.0.0.1:8000 ...' -ForegroundColor Gray
Start-Process -FilePath 'powershell' -ArgumentList @(
    '-NoExit', '-Command',
    "`$env:PYTHONPATH='$root\backend'; Set-Location '$root'; " +
    "& '$python' -m uvicorn chainguard.api.app:app --port 8000 --host 127.0.0.1"
) -WorkingDirectory $root

# Give uvicorn a moment before the dashboard starts polling /api/health, so the
# first thing on screen is not a "backend unreachable" badge.
Start-Sleep -Seconds 4

# --- Dashboard -------------------------------------------------------------- #
Write-Host '  Starting the dashboard on http://localhost:5173 ...' -ForegroundColor Gray
Start-Process -FilePath 'powershell' -ArgumentList @(
    '-NoExit', '-Command',
    "Set-Location '$root\frontend'; node node_modules\vite\bin\vite.js"
) -WorkingDirectory (Join-Path $root 'frontend')

Start-Sleep -Seconds 6

Write-Host ''
Write-Host '  Dashboard : http://localhost:5173' -ForegroundColor Green
Write-Host '  API docs  : http://127.0.0.1:8000/docs' -ForegroundColor Green
Write-Host ''
Write-Host '  Demo project to scan:' -ForegroundColor Gray
Write-Host "    $root\demo\vulnerable-app"
Write-Host ''
Write-Host '  Close the two PowerShell windows to stop the services.' -ForegroundColor Gray
Write-Host ''

Start-Process 'http://localhost:5173'
