# pii-service start-local.ps1
# Starts the PII Service locally for development.
# Pure ASCII only - no Unicode characters.
#
# Usage:
#   .\start-local.ps1              Normal start
#   .\start-local.ps1 -ForceDeps  Reinstall all requirements before starting

# Accept -ForceDeps (manual) or hub launcher's two-token form: '-' 'ForceDeps'
$ForceDeps = $false
foreach ($a in $args) {
    if ($a -match '^-?ForceDeps$') { $ForceDeps = $true }
}

$ErrorActionPreference = "Stop"

$PORT   = if ($env:PORT) { $env:PORT } else { "5900" }
$VENV   = ".venv\Scripts\python.exe"
$PIP    = ".venv\Scripts\pip.exe"
$LOG    = ".hub-logs\pii-service.log"
$LOGERR = ".hub-logs\pii-service.err"

# Wipe hub-logs so stale output doesn't confuse the launcher
if (Test-Path ".hub-logs") {
    if (Test-Path $LOG)    { Clear-Content $LOG    -ErrorAction SilentlyContinue }
    if (Test-Path $LOGERR) { Clear-Content $LOGERR -ErrorAction SilentlyContinue }
} else {
    New-Item -ItemType Directory -Path ".hub-logs" | Out-Null
}

if (-not (Test-Path $VENV)) {
    Write-Host "ERROR: venv not found at $VENV"
    Write-Host "Create it in Visual Studio: Add Environment -> Existing environment"
    Write-Host "Then: $PIP install -r requirements.txt"
    exit 1
}

if ($ForceDeps) {
    Write-Host "ForceDeps: reinstalling requirements..."
    & $PIP install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: pip install failed"
        exit 1
    }
}

if (-not (Test-Path ".env")) {
    Write-Host "WARNING: .env not found - copying from .env.example"
    Copy-Item ".env.example" ".env"
}

$FLASK_DEBUG = if ($env:FLASK_ENV -eq "production") { "0" } else { "1" }

# Filter out WSL, vEthernet, and link-local adapters for LAN IP display
$IP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object {
        $_.InterfaceAlias -notmatch "Loopback|vEthernet|WSL" -and
        -not ($_.IPAddress -like "169.254.*")
    } |
    Select-Object -First 1).IPAddress

Write-Host "---"
Write-Host "pii-service v1.0.0"
Write-Host "  Port:    $PORT"
Write-Host "  Local:   http://localhost:$PORT/health"
if ($IP) { Write-Host "  Network: http://${IP}:$PORT/health" }
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
Write-Host "  GET  /api/v1/stats             - Service telemetry"
Write-Host "---"

$env:FLASK_APP   = "app.py"
$env:FLASK_ENV   = if ($env:FLASK_ENV) { $env:FLASK_ENV } else { "development" }
$env:FLASK_DEBUG = $FLASK_DEBUG
$env:PORT        = $PORT

# Use python app.py (not flask run) for use_reloader=False compatibility with hub launcher
& $VENV -u app.py
