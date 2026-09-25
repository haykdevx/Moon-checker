# Windows validation

Moon Checker's Windows code paths (JNA registry, NTFS MFT/USN via
`DeviceIoControl`, AmCache, alternate data streams, the `MoonMon` driver) cannot be
exercised by unit tests on Linux. Every module is also deliberately best-effort: a
broken API produces *no findings*, which looks exactly like a clean PC. This
document is how a build is proven to work on real Windows.

## 1. Test matrix

| Where | OS | Locale | Runs | Notes |
|---|---|---|---|---|
| GitHub Actions `java-windows` | Windows Server 2022 | en-US | every push | elevated; `--diagnose` + headless scan |
| GitHub Actions `java-windows` | Windows Server 2025 | en-US | every push | elevated; `--diagnose` + headless scan |
| GitHub Actions `driver-windows` | Windows Server 2025 + VS 2026 | en-US | every push | builds and test-signs `MoonMon.sys` (NuGet WDK) |
| Lab VM (manual, before each release) | **Windows 11 Pro 25H2**, build 26200 | **ru-RU**, OEM cp866 | release | players' real environment; driver load test |
| Lab PC (manual, optional) | Windows 10 22H2 | ru-RU | release | older AmCache/Prefetch layouts |

Server editions in CI ship with Prefetch disabled, so the `prefetch` probe reports
INFO there; the client VM covers it. The lab VM used for the results below was a
clean install (`dockurr/windows`, `VERSION=11`, `LANGUAGE=Russian`) on KVM, with a
second, never-logged-on local account named `Игрок` to exercise offline hives and a
Cyrillic profile path.

## 2. The checklist is executable

```
java -jar moon-checker.jar --diagnose --out <dir>                     # elevated prompt
(Start-Process .\MoonCheck.exe -ArgumentList '--diagnose','--out','C:\moon-diag' -Wait -PassThru).ExitCode
```

`MoonCheck.exe` is a GUI-subsystem launcher, so run it through `Start-Process -Wait`
(or `start /wait` in cmd) to get its exit code; its launch4j wrapper propagates
the JVM's code (verified: `--bogus` → 2, `--diagnose` → 0).

Each probe drives the same code a module uses against an artefact it creates
itself, so PASS means "the module would have seen it". Exit code 0 = no FAIL,
4 = at least one FAIL; `moon-diagnostics.json` holds the details.

| Probe | What it proves |
|---|---|
| `elevation` | running as administrator (most probes need it) |
| `powershell.utf8` | PowerShell output survives a Russian OEM console (UTF-8 forced) |
| `reg.exe.decode` | `reg.exe` messages decode with the OEM code page (cp866) |
| `registry.read` / `registry.oddTypes` | JNA registry works; a key with a `REG_RESOURCE_LIST` value still yields its other values |
| `mft.enumerate` | `FSCTL_ENUM_USN_DATA` enumerates the MFT and path resolution rebuilds the path of a marker file it created |
| `usn.journal` | `FSCTL_READ_USN_JOURNAL` returns the delete record of a file the probe just deleted |
| `ads.detect` | `echo payload > file.txt:hidden` (empty host file) is listed **and** reported by `FileInspection`; `Zone.Identifier` is ignored |
| `amcache.mount` | Amcache.hve mounts (live or via VSS snapshot), has inventory keys, a stale mount from a crashed run is recovered, and the key is gone afterwards |
| `userhives` | two parallel scopes see the same users (incl. offline profiles) and no `HKU\MoonChk_*` key is left mounted |
| `processes` | ToolHelp enumeration + image paths (finds its own `java.exe`) |
| `prefetch`, `bam` | artefact sources are readable |
| `signing.state` | kernel code-integrity flags readable (test-signing / nointegritychecks / debug) |
| `vm.detect`, `windows.titles`, `defender.query` | informational |
| `kernel.bridge` | `\\.\MoonMon` answers `IOCTL_MOON_GET_REPORT` (SKIP when the driver is not loaded) |

## 3. Results — Windows 11 Pro 25H2 (ru-RU), 2026-09-14

All 17 applicable probes PASS (3 INFO, `kernel.bridge` SKIP without the driver, PASS
with it). Headless scan: 12/12 modules OK in 20 s. The shipped `MoonCheck.exe`
(launch4j + bundled JRE from `scripts/build-exe.sh`) gives the same probe results.

| Probe | Result | Detail |
|---|---|---|
| `powershell.utf8` | PASS | `Проверка` round-trips |
| `reg.exe.decode` | PASS | `Ошибка: Не удается найти указанный раздел или параметр в реестре.` |
| `registry.oddTypes` | PASS | `[plain, resourceList]` |
| `mft.enumerate` | PASS | 154 016 records in 514 ms; marker path resolved exactly |
| `usn.journal` | PASS | 36 480 delete/rename records; own deleted file found |
| `ads.detect` | PASS | host size 0, stream `hidden` listed and reported |
| `amcache.mount` | PASS | via VSS snapshot; 257 InventoryApplicationFile, 401 InventoryDriverBinary; stale mount recovered; unmounted |
| `userhives` | PASS | `[Docker, Игрок]` — the offline Cyrillic profile was mounted and released |
| `prefetch` / `bam` | PASS | 156 `.pf` files / 26 BAM entries |
| `signing.state` | PASS | `CodeIntegrityOptions=0x5` (`0x280207` with test-signing on) |
| `kernel.bridge` | PASS | 169 report lines from `MoonMon.sys` (test-signed, loaded with `sc start`) |

### Bugs the Windows run surfaced (all fixed, with regression tests where the logic is portable)

| # | Bug | Effect before the fix | Fix / test |
|---|---|---|---|
| 1 | `reg load` of the live `Amcache.hve` fails with a sharing violation on Windows 10/11 | **AmCache module silently returned nothing on every modern PC** | `HiveMount.snapshot` copies hive + `.LOG1/.LOG2` with `esentutl /y /vss` and mounts the copy; probe `amcache.mount` |
| 2 | ADS check ran after the "size > 0" gate | `file.txt:hidden` on an empty `file.txt` (the classic trick) never reported | check moved before the gate; `FileInspectionTest` |
| 3 | Parallel modules each `reg load`ed the same `NTUSER.DAT` | the module that lost the race skipped every logged-off user | reference-counted shared mount; `UserHivesTest` |
| 4 | External tools read with `readAllBytes()` before `waitFor(timeout)` | a hung `powershell`/`reg` blocked forever (timeout never fired) | `core/Exec` drains on a thread, kills on deadline; `ExecTest` |
| 5 | PowerShell/`reg.exe` output decoded with the JVM charset | Cyrillic paths in Defender detections garbled on Russian Windows | UTF-8 forced for PowerShell, OEM code page for console tools; `ExecTest`, `WinConsoleTest` |
| 6 | Test-signing detected by `bcdedit` text containing "yes" anywhere | wrong on localized Windows; any other "Yes" line matched | kernel `SystemCodeIntegrityInformation` + `SystemStartOptions`; `WinInfoTest` |
| 7 | Test-signing reported by two modules | one setting added 60/100 to the score | single finding in `KernelCheck` |
| 8 | VM detection used `vmicheartbeat`/`vmci` services | present on physical Windows 10/11 → "running in a VM" on real gaming PCs; Hyper-V guests missed | SMBIOS fields combined + guest-only services; `WinInfoTest` |
| 9 | JNA bulk registry read throws on unmapped value types | one odd value hid every value in the key | per-value fallback enumeration; probe `registry.oddTypes` |
| 10 | SQLite JDBC URL built from a raw path | a `#`, `?` or `%` in a profile path read nothing | percent-encoded `file:` URI; `BrowserHistoryTest` |
| 11 | Firefox history copied without its `-wal` | visits from the last minutes before the check invisible | WAL-aware snapshot; `BrowserHistoryTest` |
| 12 | A browser database that cannot be copied was read silently | admin not told coverage was partial | INFO finding "Browser history locked". Observed: current Edge does **not** lock `History` — a visit made while Edge was open was detected, so this is only a fallback |
| 13 | Benign `StreamedFileState` / `SmartScreen` streams | 22 HIGH findings on a clean Windows 11 | size-bounded benign stream list (from an ADS inventory of the VM); `AlternateStreamsTest` |
| 14 | `kernel/linux/Makefile` used `M=$(PWD)` | `make -C kernel/linux` from the repo root failed | `M=$(CURDIR)`; CI `kernel-linux` job |
| 15 | launch4j `stayAlive=false` | `MoonCheck.exe` always exited 0, so scripted runs could not detect failure | `stayAlive=true` in `build-exe.sh` |
| 16 | `build-exe.sh` zipped whatever `MoonCheck.exe` existed | launch4j exits 0 on a config error → a stale exe could ship | old exe deleted first, presence checked after |

Findings on the clean VM that are **false positives caused by substring signature
matching** (`gdrv.sys` inside `EhStorTcgDrv.sys`, `xone` inside `XboxOne.svg`,
Defender's own `.vdm` files) are tracked separately under false-positive reduction.

## 4. Manual steps for a maintainer without Windows

CI covers build, unit tests and the elevated self-test on Windows Server. Before a
release, someone with a Windows 11 machine or VM (Secure Boot may stay on for
steps 1–3) runs:

1. Download the `windows-results-*` artifacts of the release commit and check both
   `moon-diagnostics.json` files have no `FAIL`.
2. On the Windows 11 test machine (ru-RU recommended), in an **elevated** PowerShell
   in the unpacked release folder:
   `(Start-Process .\MoonCheck.exe -ArgumentList '--diagnose','--out','C:\moon-diag' -Wait -PassThru).ExitCode`
   must print `0`, and `C:\moon-diag\moon-diagnostics.json` must contain no `FAIL`.
3. Launch `MoonCheck.exe` normally, run a check, and confirm every module shows
   "done" and the verification code on screen matches the saved JSON report.
4. Optional, driver release only (needs Secure Boot **off**): follow the
   "TEST-SIGN AND LOAD" block at the top of `kernel/windows/MoonMon.c` using the
   `moonmon-driver-test-signed` CI artifact or an EWDK build, and confirm
   `kernel.bridge` PASS. Then `bcdedit /set testsigning off` and reboot.
5. Record the OS build, locale and probe summary in the release notes.

A reproducible lab VM on a Linux host with KVM:

```
docker run -d --name moon-win11 -e VERSION=11 -e LANGUAGE=Russian -e RAM_SIZE=8G -e CPU_CORES=4 \
  -p 127.0.0.1:8006:8006 --device=/dev/kvm --device=/dev/net/tun --cap-add NET_ADMIN \
  -v "$PWD/winvm/storage:/storage" -v "$PWD/winvm/shared:/shared" --stop-timeout 120 dockurr/windows
```

The `shared` folder appears in the guest as `\\host.lan\Data`; the web console is
on http://127.0.0.1:8006. To build the driver there, attach the EWDK ISO as a
second DVD drive (`-e ARGUMENTS="-drive id=ewdk,if=none,media=cdrom,readonly=on,file=/storage/ewdk.iso -device ide-cd,drive=ewdk,bus=ide.2"`),
because the EWDK cannot run from a network share.
