# Windows readiness — checker 1.2.0

Most MOON players run Russian-language Windows 10/11 with a Cyrillic user name,
OneDrive-redirected folders, several drives, Defender or a third-party antivirus, and
everyday gaming software (MSI Afterburner, RGB and fan tools, other games' anti-cheats).
This document records what was checked against that picture, what was changed, how each
change is tested, and what still needs a real Windows PC.

## What was changed (and the test that pins it)

| Area | Problem on a real PC | Fix | Test |
|---|---|---|---|
| Vulnerable-driver rules | MSI Afterburner (RTCore64), WinRing0/ENE/Gigabyte/ASUS utilities and another game's anti-cheat driver matched CRITICAL/HIGH rules just by being installed → "needs a look" for clean players | Location decides: Windows or program folder = context (`kernel:vulnerable-driver-installed`), unusual folder = MEDIUM, user-writable folder (Temp, AppData, Downloads, Desktop — where BYOVD loaders drop drivers) = the rule's severity (`kernel:vulnerable-driver`); manual mappers stay critical anywhere | `FalsePositivePolicyTest` |
| Defender history | "HackTool" and "keygen" counted as cheating; Windows/Office activators (AutoKMS, KMSpico) are detected as HackTool and are common | Game hacks, cheat engines, trainers and HackTool DLL injectors count (`defender:game-hack-detected`); other HackTools are context (`defender:other-hacktool`); generic "Injector" malware is ignored | `FalsePositivePolicyTest` |
| Defender real-time protection | Off = MEDIUM indicator → review | A setting: lowers assurance only (`defender:realtime-off`) | catalogue |
| Test signing | `bcdedit` output was checked for "Yes" **anywhere** — `recoveryenabled Yes` is on most PCs; values are translated ("Да") and printed in CP866 | The registry's `SystemStartOptions` (current boot, language-independent) is the source; `bcdedit` is a fallback read on the `testsigning` line with translated yes-words; the setting is reported once instead of three times; `NODEBUG` no longer reads as a kernel debugger | `WindowsParsingTest`, `PostureTest` |
| Fresh install | A Windows feature update rewrites `InstallDate` → looked like a reinstall before the check | `Setup\Source OS (Updated on …)` keys identify an in-place upgrade → context (`antiforensic:feature-update`) | `FalsePositivePolicyTest` |
| Cleaners | CCleaner merely installed → MEDIUM | Installed or run long ago = LOW; run in the last 24 h (prefetch file date) = review; running now = HIGH; secure-wipe tools keep more weight | `FalsePositivePolicyTest` |
| Alternate data streams | Any unknown stream = HIGH; Edge's `SmartScreen`, Kaspersky's `KAVICHS`, Dropbox and Mac metadata streams are on ordinary files | Small streams with those names are skipped; unknown small streams are LOW; 32 KiB+ (big enough for a program) is HIGH; cheat-named streams CRITICAL | `WindowsParsingTest` |
| AmCache | Windows keeps `Amcache.hve` locked; `reg load` failed and the collector reported **OK with nothing read** | Copy through a shadow copy (`esentutl /y … /vss`, built into Windows) and read the copy; if that fails, a collection error → incomplete scan, never "nothing found" | logic reviewed; **needs Windows** |
| Commands | `readAllBytes()` before `waitFor` made timeouts useless; output decoded as UTF-8 while Windows writes CP866 | `WinCommand`: real timeouts (process tree killed), PowerShell told to write UTF-8, native tools decoded from the OEM code page | `WindowsParsingTest` |
| Platform security | Not reported | One context line: Secure Boot, memory integrity, VBS, vulnerable-driver blocklist, TPM (Linux: Secure Boot, lockdown, module signing, ptrace scope); a deliberately disabled blocklist lowers assurance (`kernel:driver-blocklist-off`) | `PostureTest` |
| Network | Antivirus HTTPS scanning (on by default in Kaspersky/ESET) re-signs TLS with a root Java does not trust → "no connection"; proxies ignored; every failure said "check your internet" | Windows root store trusted besides Java's; system proxy used; DNS / timeout / certificate / proxy / captive portal / refused told apart with Russian advice; certificate errors not retried blindly | `NetworkErrorsTest`, `MessagesTest` |
| Window | 1180×800 did not fit 1366×768 or 1920×1080 at 150 %: buttons under the taskbar | Fits the usable screen, opens maximized when needed | `WindowFitTest` |
| Start-up | An exception while opening the window left an invisible process | A Russian error message with the log file path | review |
| Messages | `MessageFormat` swallowed text after an apostrophe | Apostrophes escaped; ru/en keys checked equal | `MessagesTest` |

## Still needs a real Windows PC

The test VM (Windows 11 25H2 Enterprise evaluation, ru-RU locale, Cyrillic user, Secure
Boot on, no TPM) covers what a VM can; results are added below when the run finishes.
A VM cannot tell us about: real gaming hardware and drivers, a PC with Steam and CS2
installed and played, OneDrive-redirected folders, third-party antivirus, and HiDPI laptops.

## First test on a real PC — step by step

Run everything from the unpacked `MoonCheck-1.2.0-win64` folder. For each case, expected
result in the panel:

1. **Clean gaming PC, as administrator** (right-click → Run as administrator; the exe asks
   for rights itself): *Nothing found* or *Needs a look* only for something you recognise;
   "Checked 9 of 9 required parts"; platform security line present; MSI Afterburner (if
   installed) appears only under "The rest".
2. **Same PC, without administrator rights** (decline the UAC prompt, run
   `MoonCheck.exe --cli` from a normal console): *Check incomplete*, reason "no
   administrator rights"; no crash.
3. **Russian Windows with a Cyrillic user name**: file paths in findings readable (no
   `????`); the report uploads.
4. **Steam and CS2 on drive D:**: the CS2 part completes; Steam accounts are listed.
5. **Synthetic artefacts** — `powershell -ExecutionPolicy Bypass -File scripts\windows-smoke.ps1`:
   a program renamed to `.png` is reported; a downloaded file's `Zone.Identifier` stream is
   not.
6. **Antivirus with HTTPS scanning on** (Kaspersky/ESET): the code is accepted (the
   Windows certificate store is trusted).
7. **Laptop at 150 % scaling, 1366×768**: the window fits, buttons visible.

Send the admin the log (`%LOCALAPPDATA%\MoonCheck\logs`) and the JSON report for any case
that does not match.
