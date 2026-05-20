# pii-service local dev launcher
#
# Usage:
#   .\start-local.ps1              Normal start
#   .\start-local.ps1 -Pull        Git pull before starting
#   .\start-local.ps1 -ForceDeps  Reinstall all requirements before starting
#   .\start-local.ps1 -Pull -ForceDeps  Pull + reinstall + start

param([switch]$ForceDeps, [switch]$Pull)

$ErrorActionPreference = 'Stop'
$Root   = $PSScriptRoot
$Log    = "$Root\.hub-logs\pii-service.log"
$LogErr = "$Root\.hub-logs\pii-service.err"

# Kill any stale instance - hub kills the shell but not Python child processes,
# leaving the log files locked on the next launch.
try {
    $stale = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*app.py*" -and $_.CommandLine -like "*$Root*" }
    if ($stale) {
        $stale | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
    }
} catch {}

# Create log dir, wipe old logs
New-Item -ItemType Directory -Path "$Root\.hub-logs" -Force | Out-Null
if (Test-Path $Log)    { Remove-Item $Log }
if (Test-Path $LogErr) { Remove-Item $LogErr }

# Pull latest code if requested
if ($Pull) {
    Write-Host "Pulling latest code..." -ForegroundColor Cyan
    git -C $Root pull
    if ($LASTEXITCODE -ne 0) {
        Write-Host "WARNING: git pull failed - continuing with current code" -ForegroundColor Yellow
    }
}

# Activate venv - error if missing (VS manages it for this project)
$Venv = "$Root\.venv\Scripts\Activate.ps1"
if (-not (Test-Path $Venv)) {
    Write-Host "ERROR: venv not found at $Venv" -ForegroundColor Red
    Write-Host "Create it in Visual Studio: Add Environment -> Existing environment"
    exit 1
}
. $Venv

# Install deps if requested or flask is missing
if ($ForceDeps -or (-not (Test-Path "$Root\.venv\Lib\site-packages\flask"))) {
    Write-Host "Installing dependencies..." -ForegroundColor Cyan
    pip install -r "$Root\requirements.txt" --quiet
}

# Copy .env.example if no .env present
if (-not (Test-Path "$Root\.env")) {
    Write-Host "WARNING: .env not found - copying from .env.example" -ForegroundColor Yellow
    Copy-Item "$Root\.env.example" "$Root\.env"
}

# Load .env into process environment so it takes precedence over hub-injected vars
Get-Content "$Root\.env" | ForEach-Object {
    if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
        $key = $matches[1]
        $val = $matches[2].Trim().Trim('"').Trim("'")
        [System.Environment]::SetEnvironmentVariable($key, $val, 'Process')
    }
}

$env:FLASK_DEBUG = if ($env:FLASK_ENV -eq 'production') { '0' } else { '1' }

# Get LAN IP (skip link-local, vEthernet, WSL, loopback)
$IP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '169.254.*' -and
                   $_.InterfaceAlias -notlike '*vEthernet*' -and
                   $_.InterfaceAlias -notlike '*WSL*' -and
                   $_.IPAddress -ne '127.0.0.1' } |
    Select-Object -First 1).IPAddress

# Resolve current git branch and commit for the banner
$Branch = (git -C $Root rev-parse --abbrev-ref HEAD 2>$null)
$Commit = (git -C $Root rev-parse --short HEAD 2>$null)
$GitInfo = if ($Branch -and $Commit) { "$Branch @ $Commit" } else { 'unknown' }

$Port = if ($env:PORT) { $env:PORT } else { '5006' }
Write-Host "---"
Write-Host "pii-service v1.0.0"
Write-Host "  Port:    $Port"
Write-Host "  Branch:  $GitInfo"
Write-Host "  Local:   http://localhost:${Port}/health"
if ($IP) { Write-Host "  Network: http://${IP}:${Port}/health" }
Write-Host "  Docs:    https://github.com/tfinnerdu/pii-service"
Write-Host "---"
Write-Host "Endpoints:"
Write-Host "  POST /api/v1/scan              - Detect PII"
Write-Host "  POST /api/v1/sanitize          - Detect and sanitize"
Write-Host "  POST /api/v1/sanitize/batch    - Batch sanitize"
Write-Host "  POST /api/v1/preflight         - AI safety check"
Write-Host "  POST /api/v1/policy/apply      - Named policy (ai_prompt, embedding, ferpa_strict...)"
Write-Host "  POST /api/v1/file              - Upload CSV/JSON for sanitization"
Write-Host "  GET  /api/v1/policies          - List named policies"
Write-Host "  GET  /api/v1/recognizers       - Recognizer pattern specs"
Write-Host "  GET  /api/v1/stats             - Service telemetry"
Write-Host "---"

# Continue so Python's stderr logging doesn't trip PowerShell's error handler
$ErrorActionPreference = 'Continue'
python -u "$Root\app.py" >> $Log 2>> $LogErr
