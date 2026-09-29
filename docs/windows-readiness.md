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
| File collector time | The whole-drive content pass had 4 minutes **per drive** inside a 5-minute limit per collector: a PC with two big drives timed out → incomplete scan | One shared budget: names on every drive (MFT), user folders, drive roots, then the content pass with the time left; drive indexes are not kept together in memory | `FalsePositivePolicyTest` (budget below the engine's limit) |
| Relocated folders | Desktop/Downloads/Documents moved to OneDrive or `D:\` were only reached by the capped whole-drive pass | Real locations read from *User Shell Folders* and scanned like the profile folders | `FalsePositivePolicyTest` |
| CS2 launch options | `-tools` (map makers), `-insecure` (practice), `-allow_third_party_software` were HIGH cheating indicators | Settings: lower assurance only (`cs2:unsafe-launch-option`), matched as whole options | `FalsePositivePolicyTest` |
| CS2 folder | Any library without a certificate was MEDIUM; CS2 ships third-party libraries | LOW context until measured on real installs (`cs2:unsigned-binary`); config scripts LOW | catalogue |
| Running game (new) | Nothing looked at what is loaded into or drawn over `cs2.exe` | `cs2live`: DLLs from user folders in the game (HIGH), unusual folders (MEDIUM), cheat-named (CRITICAL); transparent always-on-top windows over the game from unknown programs (MEDIUM/HIGH); known overlays (Steam, Discord, NVIDIA, AMD, RivaTuner, OBS, Overwolf, Medal) as context; "CS2 not running" as context | `LiveGamePolicyTest` |
| Start-up | An exception while opening the window left an invisible process | A Russian error message with the log file path | review |
| Messages | `MessageFormat` swallowed text after an apostrophe | Apostrophes escaped; ru/en keys checked equal | `MessagesTest` |

## Results on a Windows 11 test machine (2026-09-29)

A local virtual machine: Windows 11 25H2 Enterprise evaluation, Russian system locale (console
code page 866), Secure Boot on, no TPM, 4 cores, 8 GB, one 64 GB drive. Two accounts: `igrok`
(the desktop) and `Игорь` (Cyrillic, administrator). Every problem below was found there
and fixed in the build that then passed.

| Test | Result | What it found and what was fixed |
|---|---|---|
| Self-test (`--selftest`) | pass | — |
| Full scan as administrator, nothing planted | 9 of 9 required parts, about 20 s | First runs: `files` and `amcache` **timed out** (incomplete scan). Causes: every collector's clock started when the scan was queued, not when it ran; the file walk looped through `C:\ProgramData\Application Data` (a junction back to itself); a PowerShell signature check per program file; hashing without hash rules. Fixed: clocks start per collector, junctions and OneDrive online-only files are not followed or read, signatures checked only for files that already look suspicious. 208 s → 20 s. |
| Clean-PC findings | only two, both correct | "Recent Windows reinstall" (true for a new VM) and "virtual machine" (lowers assurance, does not ask for review). No false driver, Defender, test-signing or stream findings. |
| `scripts/windows-smoke.ps1` | 8 of 8 pass | Program disguised as `скриншот.png` in `Проверка Игрока\` reported with a readable path; a program hidden in a stream reported HIGH; a cheat-named file reported; `Zone.Identifier` and `SmartScreen` streams not reported; platform security line present; no test-signing finding. (The script needed a UTF-8 BOM for Windows PowerShell 5.1.) |
| Running game (`cs2live`) | pass | A stand-in `cs2.exe` loaded a library from `C:\Users\Public\Downloads` → HIGH "DLL from a user folder loaded into CS2"; a transparent always-on-top window over it → MEDIUM overlay finding. |
| Code → checker → panel | pass | Code entered in the window, the panel showed the admin and player, the scan uploaded; the panel page shows the Cyrillic paths, verdict and parts. |
| Window at 100 % (1280×800) | pass after fixes | Start-screen text was cut off on the right (Swing counts a CSS pixel as 1.3 screen pixels); the report signature was painted over by the buttons; ✓ showed as an empty box (Segoe UI has no such glyph); grey context notes were counted as red "улик" with a wrong plural; verdict reasons were English. All fixed. |
| Window at 150 % (1920×1080, a gaming laptop) | pass after a fix | Opens maximized and sharp; the results screen showed only two findings under a fixed-height explanation — now a divider the admin can drag, with more rows by default. |
| Same file found twice | fixed | The user-folder walk and the whole-drive pass both read `Downloads`; each file is now inspected and reported once. |

## Still needs a real Windows PC

A VM cannot tell us about: real gaming hardware and drivers, a PC with Steam and CS2
installed and played (the CS2 and Steam parts only saw "not installed" here), OneDrive-
redirected folders, third-party antivirus with HTTPS scanning, several physical drives, and a
1366×768 laptop screen.

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
