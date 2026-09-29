# Kernel components — threats, states, validation and release blockers

The two kernel components (`kernel/windows/MoonMon.c`, `kernel/linux/moonmon.c`) are
**optional snapshot helpers**. They are not continuous protection, they do not prevent anything,
and an empty comparison is not evidence of a clean kernel. They ship in no player package today.

## What each capability is for

| Capability | Named threat | Measurable benefit | What it cannot see |
|---|---|---|---|
| Windows: kernel module table read from a driver (`IOCTL_MOON_GET_REPORT`, `SystemModuleInformation`) | A user-mode hook in the checker process (or a patched `ntdll`) hiding a loaded cheat/vulnerable driver from the checker's own user-mode enumeration | A driver present in the kernel's table cannot be filtered by user-mode code in the checker; names are matched against vulnerable-driver and cheat rules with location-aware severity | Manually mapped drivers (never in the table), a kernel rootkit that unlinks itself, hypervisors, firmware, DMA. A user-mode vs kernel list *diff* is **not implemented** on Windows (only the kernel list is consumed) |
| Linux: task list from the scheduler (`/proc/moonmon`, `for_each_process`) | An `LD_PRELOAD` / `/etc/ld.so.preload` rootkit filtering `readdir` on `/proc`, which also fools the JVM | A process the kernel runs and that answers at `/proc/<pid>`, but is missing from two listings, is reported as hidden (`kernel:hidden-process`) | Kernel-mode rootkits (hide from both), processes in other PID namespaces (treated as races, not reported) |

User-mode fallbacks run whether or not a component is present (Windows services registry,
test-signing, Secure Boot / HVCI / blocklist posture; Linux `/proc/modules` vs `/sys/module`,
taint, `ld.so.preload`).

## States the checker distinguishes (`KernelBridge.State`, `KernelReport`)

| State | Meaning | Effect on the report |
|---|---|---|
| `ABSENT` | not installed (no device / no `/proc` entry) | INFO note; user-mode checks only; coverage unaffected (optional component) |
| `INACCESSIBLE` | installed, cannot be opened (not elevated) | context note `kernel:component-inaccessible` |
| `FAILED` | opened but the request/read failed | collector `PARTIAL` with the reason → coverage incomplete |
| incompatible | another protocol version (`KernelReport` problem) | collector `PARTIAL` |
| partial | truncated / miscounted / stray lines (`KernelReport` problem) | collector `PARTIAL` |
| `COLLECTED` (complete) | framing valid | records consumed; context line `kernel:cross-view` states how many records were compared and that an empty diff is not proof |

## Interface validation (reviewed 2026-09-29)

Windows driver: device secured by `IoCreateDeviceSecure` with `SDDL_DEVOBJ_SYS_ALL_ADM_ALL`
and `FILE_DEVICE_SECURE_OPEN`; one IOCTL (`METHOD_BUFFERED`, `FILE_READ_ACCESS`), any other
code → `STATUS_INVALID_DEVICE_REQUEST`; no input buffer is read; output bounded by
`OutputBufferLength` (< 64 bytes refused), `Information` never exceeds it; each line bounded
(`RtlStringCbPrintfA` into 300 bytes, path copied from the fixed 256-byte field and sanitised to
printable ASCII so no module name can forge a line); `END` written only when every record fit;
module table re-queried with slack when it grows between size query and read (4 attempts);
per-call `NonPagedPoolNx` allocation, freed on every path; no shared state between calls
(concurrent IOCTLs are independent); no pended IRPs, so unload is safe. No arbitrary memory
access, no disabled protections.

Linux module: `/proc/moonmon` mode `0440` (root); `seq_file` + `single_open`, so large task
lists are retried with a larger buffer instead of truncated; walk under `rcu_read_lock`
without sleeping; `comm` sanitised to printable ASCII; `END n` for truncation detection.

User-mode side: the report is untrusted text. `KernelReport.parse` accepts only protocol 2 with
consistent header count, records and `END`; anything else is a named problem. The Linux
comparison rules out three races before reporting — process exited between reads (`/proc/<pid>`
gone), process started between reads (present in a second listing), PID reused (name differs
from the kernel's, compared with the same sanitising).

## Validation actually run

| Check | Result |
|---|---|
| Linux module compiled against Linux 7.0.0-34 headers, `make W=1` | clean (only toolchain-version notes) |
| Same with GCC `-fanalyzer` | no diagnostics in `moonmon.c` |
| `KernelComponentTest` — 20 000 seeded random mutations of reports | parser never threw; every report it called complete was internally consistent |
| `KernelComponentTest` — race cases (exited, started, reused PID) and the real hiding case | exited/started/reused not reported; a live PID missing from two listings reported |
| Module loaded on a machine | **not done** — per project rule, experimental kernel code is not loaded on the development host; an isolated VM run is pending |
| Windows driver built / Code Analysis / Static Driver Verifier / Driver Verifier | **not done here** — needs the EWDK on Windows; last recorded build and load: 2026-09-14 (protocol 1, see the header comment of `MoonMon.c`) |

## Release blockers (explicit)

1. **Windows production signing.** Microsoft's current documentation (Driver Signing Options,
   2026-03-23; Attestation sign Windows drivers, 2025-07-15, page updated 2026-04-14) says
   attestation signing is "for testing purposes only", requires an **EV code-signing
   certificate** and a Partner Center (Hardware Dev Center) submission, and yields a driver
   that is not Windows Certified; distribution to retail audiences through Windows Update
   requires the Windows Hardware Compatibility Program (HLK-tested dashboard signing), which
   Microsoft recommends. The project has neither an EV certificate nor a Partner Center
   account. Test-signed builds require Secure Boot off and must never reach players.
2. **Windows validation:** build with EWDK at `/W4 /WX`, Code Analysis, Static Driver
   Verifier, `infverif`, a Driver Verifier run with standard flags under load (repeated
   IOCTLs from several threads, unload during use), HVCI-enabled load test.
3. **Linux validation in an isolated VM:** load/unload loops, reading `/proc/moonmon` from
   several processes concurrently, 10 000+ tasks, kernels of each supported distribution;
   module signing: on Secure Boot systems with `lockdown` / `module.sig_enforce` an unsigned
   module is refused — distributions need either a signed build (distribution or MOK key the
   player enrols) or the component stays unavailable there.
4. **Windows cross-view diff** (kernel list vs `EnumDeviceDrivers`) is not implemented.

## Continuous protection

Not provided and not claimed. A continuous game-session capability (a service that stays
resident during the match, with a defined start/stop lifecycle, measured overhead, crash
recovery and enforcement tests) would be a separate product capability; nothing in these
components is a step toward it without that design.
