# Release evidence — checker 1.4.0 / panel (2026-10-01)

Thresholds were fixed before the runs below; a row passes only on its evidence. Two separate
assessments: the quality of a **bounded inspection product** (what this project is), and
**progress toward competitive anti-cheat protection** (what it is not). Details of every
finding: `docs/hardening-record.md`.

## Thresholds and results

| Area | Release threshold | Evidence (what ran) | Result |
|---|---|---|---|
| Implementation quality | All suites green on the supported toolchains; no known-vulnerable runtime dependency; reproducible build | Java 248 tests (1 skipped: platform-specific), JDK 21 in `maven:3.9-eclipse-temurin-21`; panel 141 tests on SQLite and 141 on PostgreSQL 17; OSV / pip-audit clean; two builds give identical jar/exe/zip hashes | **Met** |
| Report assurance | A fabricated report cannot earn a "verified" label; replay, cross-session reuse, duplicates, stale/expired uploads and inconsistent metadata refused; the outcome is recomputed server-side; honest zero-finding scans accepted | `test_api.py` attack cases, rendered-page tests EN/RU, 6-thread upload race on PostgreSQL; real checker → panel runs on Linux and on Windows 11 (bound, value consumed, codes equal) | **Met**. Execution integrity is **not** verifiable without platform attestation (`docs/report-assurance.md`) |
| Application security | Permission-bounded role grants in every backend path; atomic MFA consumption (exactly one winner under concurrency); object-level access enforced on every endpoint; player data removed from the audit trail on deletion; bounded parsing | `PermissionBoundaryTests`, `MfaAtomicityTests`, `ConcurrencyTests` (PostgreSQL; fail on the previous code), `test_object_access.py`, ingest fuzz (300 cases) | **Met** for the tested surface; no external penetration test |
| Detection validation | False-positive rate of outcome-moving findings on legitimate system files: 95 % upper bound below 0.1 % per corpus of ≥ 5 000 files; every rule with class, status and provenance; no unsourced hashes; concealment and exact matches never silenced by location or signature | Benign corpus 61 423 files (Linux `/usr`; Windows System32, SysWOW64, Program Files, Defender): 0 outcome-moving, upper bound 0.0063 % overall; fixture suites; Windows smoke 8/8 | **Met for false positives on these corpora.** **Real-cheat detection rate: unmeasured** (no labelled samples) — not a pass |
| Platform reliability | Windows 11 (ru-RU, Cyrillic user): 9/9 required parts, smoke 8/8, GUI at 100 % and 150 %; Linux: honest `PARTIAL` instead of silent truncation; kernel parser fuzzed | VM runs 2026-09-29/30 (`docs/windows-readiness.md`); Ubuntu 26.04 run; 20 000-case kernel-report fuzz; `moonmon.c` clean under `W=1` and `-fanalyzer` | **Met on the tested platforms only** (one Windows build, one Linux distribution; no gaming PC, no third-party antivirus) |
| Usability | Russian by default, complete translations (enforced by test); desktop and 390-px mobile pages without horizontal overflow or console errors; claims never shown in green | `moon_i18n --check` 608/608; headless Chromium over 8 pages × 2 widths; decision bar fits at 360 px | **Met** for the rendered pages |

## Open release blockers (external prerequisites)

1. **Code signing:** `MoonCheck.exe` is unsigned (needs a code-signing certificate, EV preferred).
2. **Kernel components:** Windows production signing (Microsoft, 2026-03-23: attestation signing
   is for testing only; EV certificate + Partner Center; retail via WHCP/HLK), an EWDK build with
   SDV and Driver Verifier, and isolated load/stress runs on Windows and Linux — none done; the
   components ship in no player package.
3. **Detection measurement:** labelled real samples through an authorised, isolated process with
   a held-out split (`docs/rules-pipeline.md`); until then accuracy is unknown.
4. **Platform coverage:** a real gaming PC (Steam + CS2, overlays, third-party antivirus, HiDPI
   laptop), other Linux distributions, a root Linux run, SELinux/AppArmor enforcing.
5. **Attestation:** stronger report assurance needs TPM attestation (design and gaps in
   `docs/report-assurance.md`).
6. **CI:** GitHub Actions is unavailable on the account; all runs above were local.

## Assessment

**Bounded inspection product:** ready for use as what it claims to be. It is a supervised,
one-time PC inspection that reports evidence with its limits: coverage and "not independently
verified" are stated on every report, and false positives on system files were measured as rare.
It is not ready to be described as detecting cheats at a known rate.

**Competitive anti-cheat protection:** not provided. There is no continuous in-game protection,
no signed kernel component, no attestation, and no measured detection of real cheats. Any claim
of FACEIT-like protection would be false.
