# PowerShell 5+ start helper; .env is read as configuration (do not run downloaded scripts).
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
if (Test-Path '.env') {
    Get-Content '.env' | ForEach-Object {
        $line = $_.Trim()
        if ($line -and !$line.StartsWith('#') -and $line.Contains('=')) {
            $parts = $line.Split('=', 2)
            [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(' ', '"', "'"), 'Process')
        }
    }
}
python -m uvicorn app.web:app --host 127.0.0.1 --port 8000
