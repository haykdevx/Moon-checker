# Linux collection — support matrix and kernel-side options

## Supported configurations

| Dimension | Supported | Verified how |
|---|---|---|
| Architecture | x86-64 only (CS2 ships no other Linux build) | `Platform.support()` refuses anything else as `UNSUPPORTED_CONFIGURATION` |
| Distribution | Any distribution with a readable `/proc` and a Java 21 runtime | Unit tests + CLI runs on Ubuntu 26.04 (kernel 7.0) in development; GitHub runners (Ubuntu 24.04) once Actions works again. **No other distribution has been tested.** |
| Privileges | root for full coverage; without it the scan is `INCOMPLETE_SCAN` | `VerdictEngineTest`, `ScanEngineTest` |
| Kernel component | Optional `moonmon.ko` (lab prototype) | Compiles warning-free at `-Werror` against 7.0.0-34-generic headers; load test runs in the `kernel-linux` CI job |
| Secure Boot / lockdown | User-mode collectors work in every mode; the out-of-tree module does not load when lockdown refuses unsigned modules | Documented behaviour of kernel lockdown; not tested on a lockdown machine |

## What user mode already sees

`/proc` (processes, command lines, memory maps and environment of the CS2 process),
`/proc/modules`, kernel taint, `/etc/ld.so.preload`, home-directory files and history,
autostart locations. An LD_PRELOAD rootkit that filters `readdir` on `/proc` also fools
the JVM, which is why a second, kernel-side process list is useful.

## Option A — signed out-of-tree module (`kernel/linux/moonmon.ko`)

* **Gives:** the scheduler's task list (`for_each_process`) for a diff against `/proc`.
* **Costs:** must be built per kernel (DKMS), signed with a key the player enrols in
  MOK for Secure Boot systems, taints the kernel (`O`, and `E` if unsigned), and a bug
  runs with kernel privileges. Asking players to install a kernel module for a one-time
  check is a large trust request.
* **Status:** lab prototype. Output framing (protocol 2) and name escaping are done;
  signing and packaging are not.

## Option B — eBPF (recommended direction, not implemented)

* **Gives:** the same task list through a BPF task iterator, and — unlike the module —
  *live* observation during a monitoring window through tracepoints: process exec, module
  loads, `ptrace` attach, `process_vm_readv`/`pidfd_getfd` calls and opens of
  `/proc/<cs2>/mem` targeting the game. That is the Linux building block for continuous
  match protection.
* **Costs:** needs root (`CAP_BPF` + `CAP_PERFMON`), BTF-enabled kernels for CO-RE
  portability, and lockdown in *confidentiality* mode restricts kernel-memory reads.
* **Safety:** programs are checked by the kernel verifier and cannot crash the kernel the
  way a module can; nothing out-of-tree needs signing.

| | Module | eBPF |
|---|---|---|
| Point-in-time task list | yes | yes (task iterator) |
| Live syscall/exec/module-load observation | no (would need hooks) | yes (tracepoints) |
| Works under Secure Boot without MOK enrolment | no | yes (root required) |
| Crash risk | kernel bug = panic | verifier-bounded |
| Per-kernel build | yes | no (CO-RE, BTF) |

Neither option can see a kernel-mode rootkit that hides from both views, a hypervisor,
firmware or DMA reads. An empty diff is never reported as proof of absence.
