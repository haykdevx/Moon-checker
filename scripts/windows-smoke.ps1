# Moon Checker — Windows validation smoke test.
#
# Run this on a real Windows gaming PC (ideally one with Steam + CS2 installed)
# to verify the Windows-only code paths actually work before trusting the tool
# on players. Run from an elevated PowerShell:
#
#   powershell -ExecutionPolicy Bypass -File scripts\windows-smoke.ps1
#
# It checks that each module completes, then creates a few synthetic artefacts
# (an alternate data stream, a PE renamed to .png) and confirms the scanner
# reports them.
param(
    [string]$Jar = "target\moon-checker.jar"
)
$ErrorActionPreference = "Stop"

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

$admin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Warning "NOT elevated — MFT, USN, AmCache and kernel checks will be limited." }

Section "1. Module selftest"
java -jar $Jar --selftest
if ($LASTEXITCODE -ne 0) { Write-Error "selftest failed (no module completed)"; exit 1 }

Section "2. Synthetic artefacts"
$lab = Join-Path $env:TEMP "moon-smoke"
New-Item -ItemType Directory -Force -Path $lab | Out-Null

# (a) a PE disguised as an image — should be flagged "disguised by extension"
Copy-Item "$env:WINDIR\System32\notepad.exe" (Join-Path $lab "screenshot.png") -Force

# (b) a hidden alternate data stream — should be flagged as ADS
"moon-smoke-payload" | Out-File -FilePath (Join-Path $lab "notes.txt")
Set-Content -Path (Join-Path $lab "notes.txt") -Stream "hidden" -Value "payload"

# (c) a file whose NAME matches a cheat signature
Copy-Item "$env:WINDIR\System32\notepad.exe" (Join-Path $lab "nixware_loader.exe") -Force
Write-Host "created: $lab"

Section "3. Headless inspection"
java -jar $Jar --cli --out (Join-Path $lab "reports")

Section "4. Verify the synthetic artefacts were detected"
$json = Get-ChildItem (Join-Path $lab "reports") -Filter *.json | Select-Object -First 1
if (-not $json) { Write-Error "no evidence bundle produced"; exit 1 }
$text = Get-Content $json.FullName -Raw
$checks = @{
    "disguised PE (screenshot.png)" = "screenshot.png"
    "alternate data stream"         = "hidden"
    "cheat-name match"              = "nixware_loader"
}
$failed = 0
foreach ($k in $checks.Keys) {
    if ($text -match [regex]::Escape($checks[$k])) {
        Write-Host ("  PASS  " + $k) -ForegroundColor Green
    } else {
        Write-Host ("  MISS  " + $k) -ForegroundColor Yellow
        $failed++
    }
}

Section "Result"
Write-Host "evidence: $($json.FullName)"
Remove-Item -Recurse -Force $lab -ErrorAction SilentlyContinue
if ($failed -gt 0) { Write-Warning "$failed synthetic artefact(s) not detected — investigate"; exit 2 }
Write-Host "All synthetic artefacts detected." -ForegroundColor Green
