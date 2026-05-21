# CLAUDE.md — pii-service

Project notes for AI-assisted development sessions.

---

## start-local.ps1 — Startup Script Notes

### Background
`start-local.ps1` is the Windows launcher used by the hub and for local dev in Visual
Studio. It activates the venv, optionally pulls latest code and reinstalls deps, loads
`.env`, prints the startup banner, and runs `python -u app.py` with log redirection.

### Changes made and why

**Default port corrected to 5006**
Both `start-local.ps1` and `app.py` previously fell back to port 5900 when `PORT` was
not set in the environment. The `.env` and `.env.example` both specify `PORT=5006`.
`python-dotenv`'s `load_dotenv()` does not override env vars that are already set in
the process, so if the hub launched the script without injecting `PORT`, Flask would
bind to 5900. The hardcoded defaults in both files were changed to 5006 to match.

**ASCII-only — no em dashes or other non-ASCII characters**
Windows PowerShell 5.x reads `.ps1` files using the system ANSI code page rather than
UTF-8. Em dashes and other non-ASCII characters in string literals or comments cause
the parser to misread the file and produce spurious "Missing closing }" errors that
abort the script before it starts. All comments and strings must use plain ASCII
hyphens (`-`) in place of em dashes (`-`).

**Stale process kill on startup**
When the hub terminates the PowerShell launcher process, Windows does not automatically
kill the Python child process. The orphaned Python process holds the log files
(`.hub-logs/pii-service.log` and `.hub-logs/pii-service.err`) open for writing. On the
next launch, `Remove-Item` and the `>> $Log` redirect both fail with an access-denied
IOException, halting the script. The fix is a `Get-CimInstance` lookup at the top of
the script that finds any `python.exe` running our `app.py` from this directory and
stops it before touching the log files:

```powershell
$stale = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*app.py*" -and $_.CommandLine -like "*$Root*" }
if ($stale) {
    $stale | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
}
```

**-Pull switch**
Added a `-Pull` switch parameter. When passed (`.\start-local.ps1 -Pull`), the script
runs `git pull` before activating the venv. A failed pull prints a warning and
continues rather than aborting, so a network hiccup does not prevent the service from
starting on the current code. The hub launcher does not pass `-Pull` by default.

**Branch/commit in startup banner**
The banner now resolves the current git branch and short commit hash at launch time and
prints them as `Branch: <branch> @ <commit>`. This makes it immediately visible in hub
logs which version of the code is running without having to SSH in or check git.
