# Moon Checker — Windows smoke test (checker 1.3.0).
# Saved as UTF-8 WITH a BOM: Windows PowerShell 5.1 reads a script without one in the ANSI code page,
# and the Cyrillic test names and dashes below would break the parser.
#
# Run on a real Windows PC (ideally one with Steam + CS2) before trusting a build on
# players. From an elevated PowerShell in the unpacked MoonCheck folder (or the repo):
#
#   powershell -ExecutionPolicy Bypass -File windows-smoke.ps1
#
# It creates harmless synthetic artefacts — some the checker MUST report, some it must
# NOT (things every ordinary PC has) — runs a headless scan, and prints a PASS/FAIL table.
param(
    [string]$Checker = "",
    [string]$Java = ""
)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [Text.Encoding]::UTF8

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Checker) {
    foreach ($c in @((Join-Path $here "MoonCheck.exe"), (Join-Path $here "..\MoonCheck.exe"),
                     (Join-Path $here "..\target\moon-checker.jar"))) {
        if (Test-Path $c) { $Checker = (Resolve-Path $c).Path; break }
    }
}
if (-not $Java) {
    $bundled = Join-Path (Split-Path -Parent $Checker) "runtime\bin\java.exe"
    $Java = if (Test-Path $bundled) { $bundled } else { "java" }
}
Write-Host "checker: $Checker"
Write-Host "java:    $Java"

$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Warning "NOT elevated: the scan will be INCOMPLETE by design (MFT, USN, AmCache, kernel)." }

Section "1. Self-test"
& $Java -jar $Checker --selftest
if ($LASTEXITCODE -ne 0) { Write-Error "self-test failed (no collector completed)"; exit 1 }

Section "2. Synthetic artefacts"
$lab = Join-Path $env:TEMP "moon-smoke"
Remove-Item -Recurse -Force $lab -ErrorAction SilentlyContinue
$cyr = Join-Path $lab "Проверка Игрока"
New-Item -ItemType Directory -Force -Path $cyr | Out-Null
$notepad = "$env:WINDIR\System32\notepad.exe"

# MUST be reported
Copy-Item $notepad (Join-Path $cyr "скриншот.png") -Force                     # program disguised as an image, Cyrillic path
Set-Content -Path (Join-Path $lab "notes.txt") -Value "moon smoke"
Set-Content -Path (Join-Path $lab "notes.txt") -Stream "payload" -Encoding Byte `
    -Value ([IO.File]::ReadAllBytes($notepad))                                 # a program hidden in a stream (>32 KiB)
Copy-Item $notepad (Join-Path $lab "nixware_loader.exe") -Force                # name matches a cheat rule

# must NOT be reported (every ordinary PC has these)
Set-Content -Path (Join-Path $lab "download.zip") -Value "zip"
Set-Content -Path (Join-Path $lab "download.zip") -Stream "Zone.Identifier" -Value "[ZoneTransfer]`r`nZoneId=3"
Set-Content -Path (Join-Path $lab "setup.exe.txt") -Value "x"
Set-Content -Path (Join-Path $lab "setup.exe.txt") -Stream "SmartScreen" -Value "Anaheim"
Write-Host "created: $lab"

Section "3. Headless scan"
$out = Join-Path $lab "reports"
& $Java '-Dstdout.encoding=UTF-8' -jar $Checker --cli --out $out
$json = Get-ChildItem $out -Filter *.json -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $json) { Write-Error "no evidence bundle produced"; exit 1 }
$report = Get-Content $json.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
$evidence = @($report.evidence)
# @(...) around every use: Windows PowerShell 5.1 gives a single object from ConvertFrom-Json no .Count
function Found($needle) { @($evidence | Where-Object { "$($_.evidence) $($_.detail)" -like "*$needle*" }) }

Section "4. Results"
$rows = @()
function Row($what, $ok, $note) { $script:rows += [pscustomobject]@{ Check = $what; Result = $(if ($ok) { "PASS" } else { "FAIL" }); Note = $note } }
Row "disguised program in a Cyrillic folder is reported" (@(Found "скриншот.png").Count -gt 0) "path must be readable, not ????"
Row "program hidden in a stream is reported HIGH" (@(Found "payload" | Where-Object { $_.severity -in "HIGH","CRITICAL" }).Count -gt 0) ""
Row "cheat-name match is reported" (@(Found "nixware_loader").Count -gt 0) ""
Row "Zone.Identifier stream is NOT reported" (@(Found "Zone.Identifier").Count -eq 0) "every download has one"
Row "SmartScreen stream is NOT reported" (@(Found "SmartScreen").Count -eq 0) "Edge writes one"
Row "platform security line present" (@($evidence | Where-Object rule -eq "kernel:platform-posture").Count -eq 1) ""
Row "no test-signing finding on a normal PC" (@($evidence | Where-Object { $_.rule -in "kernel:dse-off","kernel:boot-integrity-weakened" }).Count -eq 0) "unless you enabled it"
$cov = $report.coverage
Row "all required parts completed" ([bool]$cov.complete) ("missing: " + (@($cov.missing) -join ", "))
$rows | Format-Table -AutoSize

Write-Host "outcome:  $($report.verdict.outcome)"
Write-Host "coverage: $(@($cov.required).Count - @($cov.missing).Count) of $(@($cov.required).Count) required parts"
foreach ($p in $cov.errors.PSObject.Properties) { Write-Host "  $($p.Name): $($p.Value)" -ForegroundColor Yellow }
Write-Host "report:   $($json.FullName)"
Write-Host "log:      $env:LOCALAPPDATA\MoonCheck\logs"

$failed = @($rows | Where-Object Result -eq "FAIL").Count
if ($failed -gt 0) { Write-Warning "$failed check(s) failed — send the report and the log to the developer"; exit 2 }
Write-Host "All checks passed." -ForegroundColor Green
