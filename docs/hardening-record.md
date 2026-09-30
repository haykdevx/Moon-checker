# Hardening record — Protocol Moon (from 2026-09-29)

A working record for the external review of checker 1.2.0 / panel. The plan comes first, then
every finding with its fix and the test that pins it, then what was actually run. Nothing is
marked closed without a regression test or a recorded platform run.

## Baseline (verified 2026-09-29, before this work)

- Java: 203 tests pass, 1 skipped (`mvn test` in `maven:3.9-eclipse-temurin-21`).
- Django: 97 tests OK (`manage.py test`, SQLite).
- Windows 11 VM runs: see `docs/windows-readiness.md` (full scan 9/9, smoke 8/8, live-game, GUI 100 %/150 %).
- The bundled known-cheat hash list is empty (`signatures.json` `hashes: []`).

## Plan (highest impact first)

1. **Report trust** (panel): stop calling self-reported values "verified"; separate session
   authentication, report consistency, claimed artifact identity, collector integrity and
   device facts; bind uploads to the session with a server-issued single-use value, a
   protocol version and a deadline; reject replay, cross-session reuse, duplicates and
   inconsistent metadata; recompute the outcome on the server.
2. **Account policy and MFA**: grant only permissions the actor holds; atomic TOTP step and
   recovery-code consumption bound to the current enrolment; last-owner protection.
3. **Path and identity trust** (checker): boundary-aware normalized locations; no suppression
   by location alone; signer identity by exact name with a pinned-root chain; overlay trust
   needs identity, not a file name.
4. **Linux content inspection and coverage**: executables recognised by content (ELF/PE),
   explicit limits, inaccessible/over-budget targets reported, support matrix.
5. **Rule pipeline**: provenance, classification, review status, withdrawal; signed-update
   tests (tamper, rollback, incompatible, interrupted); evaluation harness with a benign
   corpus, per-class FP/FN and confidence intervals; no invented hashes.
6. **Kernel components**: threat mapping, interface validation review, state model
   (absent/inaccessible/incompatible/failed/partial/collected), parser fuzzing; release blockers.
7. **Web hardening review**: object-level access, CSRF/session, abuse limits, decompression,
   injection, secrets, retention, supply chain.
8. **UI**: findings / coverage / assurance / decision kept apart; mobile navigation, focus,
   reduced motion, states; rendered desktop and mobile workflow run.
9. **Release evidence matrix** with thresholds agreed before evaluation.

## Findings

| ID | Area | Problem | Status | Fix | Regression evidence |
|---|---|---|---|---|---|
| R1 | Report trust | A hand-written report over a valid session, naming a registered hash, was labelled "Official checker build" and overall trust "ok" | Closed | Five separate questions; claims worded as claims; "checker execution: not independently verified" on every report; old stored signals re-worded on display; "no evidence" neutral | `test_a_fabricated_report_claiming_an_official_hash_gets_no_verified_label`, `ReportPageTests` (EN/RU, legacy signals) |
| R2 | Report trust | Reports not bound to a session: a report from another check could be delivered, duplicate completion guarded only by status, no deadline | Closed | Protocol 3: single-use upload value + session id + protocol inside the report, deadline, atomic conditional-UPDATE consumption; replayed ids, cross-session, stale value, wrong protocol, late upload refused | `test_a_report_made_for_another_check_is_refused`, `test_unbound_and_wrong_protocol_reports_are_refused`, `test_a_late_upload_is_refused`, `test_a_report_id_seen_in_another_check_is_refused`, `test_a_stale_view_of_the_session_cannot_complete_it_twice`, `ConcurrencyTests.test_simultaneous_report_uploads_complete_the_check_once` (PostgreSQL, 6 threads) |
| R3 | Report trust | Inconsistent metadata (other PC/user/OS/version/program file at upload than at connect) only flagged | Closed | Refused with 422 `inconsistent_report` | `test_connect_and_upload_must_describe_the_same_pc`, `test_a_report_from_a_different_program_file_is_refused`, fuzz contract (5 cases moved to reject) |
| R4 | Report trust | Outcome stored as the client stated it; required list taken from the client | Closed | Outcome recomputed with the server's required set; client statement kept separately | `test_an_edited_outcome_is_replaced_by_the_servers`, `test_shrunk_required_list_is_flagged`, `test_an_honest_zero_finding_scan_is_accepted` |
| A1 | Accounts | Role assignment checked rank only: a lower custom role with permissions the admin lacks could be assigned (invite, promotion) | Closed | Grant = rank below actor AND role permissions ⊆ actor's; enforced in `assignable_roles` (forms), again under lock on save, and at invite acceptance | `PermissionBoundaryTests` (policy + direct HTTP) |
| A2 | Accounts | Found while fixing A1: a member of such a role could be managed (password-reset link → sign in with their permissions) | Closed | `can_manage_member` and `can_edit_role` require the same permission boundary | `test_members_holding_more_permissions_cannot_be_taken_over`, `test_a_role_editor_cannot_edit_a_role_with_permissions_they_lack` |
| A3 | MFA | Two stale user copies both accepted one TOTP step | Closed | Step consumed by conditional UPDATE on the stored row, bound to the same secret and 2FA still on | `MfaAtomicityTests`, `ConcurrencyTests.test_simultaneous_totp_logins_with_one_code` (PostgreSQL, 8 threads); fails on the old code |
| A4 | MFA | Recovery code: read-then-save, not atomic | Closed | Conditional UPDATE on the code row; refused when stored 2FA is off | `test_a_recovery_code_works_once_even_from_stale_copies`, `ConcurrencyTests.test_simultaneous_recovery_code_uses`; fails on the old code |
| A5 | Accounts | Two owners demoting each other at once could leave no owner | Closed | Owner rows and the member locked in a fixed order (PostgreSQL); SQLite transactions `IMMEDIATE` | `ConcurrencyTests.test_two_owners_demoting_each_other_leave_one_owner`; fails without the lock |
| C1 | Checker: locations | Allowlisted paths matched as substrings: a harmless fixture stopped producing its heuristic finding under a nested `…/opt/vendor/` (or `…\steam\steamapps\common\`) folder | Closed | `checks/Locations.java`: normalised paths, whole-component roots from the machine, most specific root wins, real path (links/junctions) classified too and the less trusted answer used, unresolvable/network never trusted, Linux needs root-owned and closed files; the path allowlist is gone | `ContentAndLocationTest` (nested fragments, prefix collisions, D:-installed Windows, symlink into a user folder, UNC), `ValidationCorpusTest.disguisedExecutableHeuristic` now asserts 0/20 suppressed (was 20/20) |
| C2 | Checker: suppression | Location alone suppressed every heuristic (streams, disguise, offsets, imports, entropy) | Closed | Identity gate: verified publisher or approved hash → not reported; unverified in a system/program folder → LOW context (visible, does not move the outcome); signature broken → at least MEDIUM; elsewhere → as observed. Exact name/hash matches unchanged | `ContentAndLocationTest.theIdentityGateNeverDropsAFindingForItsLocationAlone` |
| C3 | Checker: signer identity | Signer allowlist matched substrings of the subject ("Not Microsoft Corporation Ltd" passed) and did not look at the chain | Closed | Exact CN/O match after normalisation; valid status; chain root pinned by SHA-1 (21 roots, each with the store it was read from: Windows 11 root store, Mozilla bundle, OpenJDK cacerts); batch verification | `AllowlistTest` (exact names, substring attempts, unpinned root, invalid status, quoted DN) |
| C4 | Checker: overlays | Overlay DLL names and window-owner names got trusted treatment without file identity (a `GameOverlayRenderer64.dll` in Downloads, an ESP named `discord.exe`); game folder matched by string prefix (`cs2-cheat` inside `cs2`) | Closed | Overlay/program treatment only with a verified publisher; boundary-aware game root; new `cs2:module-proxy-dll` for Windows library names loaded from the game folder | `LiveGamePolicyTest` (overlay names in writable folders, unverified owners, prefix collision, proxy DLLs) |
| L1 | Linux content | Inspection gate knew extensions and `MZ` only: identical ELF fixtures produced a finding as `.so` and none without an extension | Closed | Executables recognised by content (valid PE: `MZ` + `PE\0\0` at e_lfanew; ELF: magic, class, data, version), any name; malformed headers get string/entropy checks only; `process_vm_readv/writev` indicator | `ContentAndLocationTest.theSameProgramGetsTheSameFindingsWhateverItIsCalled` (`tool`, `libtool.so`, `libtool.so.1`, `.elf`, `.bin` → identical findings), `executablesAreRecognisedByContent` (truncated, bad class, e_lfanew past end) |
| L2 | Coverage | Walks stopped at 8,000 files, skipped unreadable folders and had no time budget — silently; the collector reported OK | Closed | `FileInspection.scan` reports root missing/unreadable, file limit, time limit, cancellation, unreadable subfolders, links not followed; collectors call `ctx.partial(...)` → new status `PARTIAL` → coverage incomplete → `INCOMPLETE_SCAN`; panel accepts `PARTIAL` | `ScanEngineTest.aCollectorThatCouldNotCoverEverythingIsPartialNotOk`, `ContentAndLocationTest.aWalkSaysWhyItDidNotFinish`, `anUnreadableSubfolderMakesTheWalkIncomplete` |
| L3 | Coverage | Scan limits invisible to the reviewer (files too large, cloud-only, candidates skipped, drives without an NTFS table) | Closed | Per-file outcomes (`INSPECTED`, `NOT_EXECUTABLE`, `TOO_LARGE`, `MALFORMED`, `UNREADABLE`, `CLOUD_ONLY`, `EMPTY`); `files:scan-scope` / `linuxfiles:scan-scope` context line; non-NTFS drives noted, an unreadable NTFS table is a shortfall; whole-drive pass ordered user-writable → other → program folders | `ContentAndLocationTest.limitsAndUnreadableFilesAreOutcomesNotSilence` |
| L4 | Linux scope | Steam libraries and Flatpak stores made "complete" coverage impossible to state honestly | Closed | Declared exclusions from the required part (`steamapps`, `flatpak`), walked afterwards with the time left and reported in the scope line | `ContentAndLocationTest.linksAreNotFollowedAndDeclaredExclusionsAreSkipped` |
| W1 | Checker: Windows | Found on the Windows VM while verifying C3: PowerShell scripts went out as `-Command` text and Java does not escape `"` inside a Windows argument, so the batch signature lookup returned nothing and every Microsoft file read "publisher not verified" (116 s scan, ~40 needless context lines) | Closed | All scripts are sent as `-EncodedCommand` (Base64 UTF-16LE); signature lookups batched 40 per PowerShell start per collector | `WindowsParsingTest.powershellScriptsTravelEncodedSoQuotesSurvive`; VM: Microsoft files verified, 51 s scan |
| C5 | Checker: suppression | Found on the VM: the identity gate silenced a Microsoft-signed program renamed to `.png` (smoke test row failed) | Closed | Concealment (disguised extension, program-sized hidden stream) is reported as observed whoever signed the bytes; only code heuristics are answered by a verified publisher | `ContentAndLocationTest.aVerifiedPublisherAnswersWhatItsCodeDoesButNotWhyItIsHidden`; VM smoke 8/8 |
| D1 | Rules | Found on a real Linux run: name rules that are ordinary words or legitimate products (`midnight`, `primordial`, `predator`, `gamesense`…) reported documents (`midnight-jazz.md`, `primordials.js`) as CRITICAL cheat files | Closed | 19 rules marked `ambiguous`: program/archive names only, capped at MEDIUM; dual-use tools INFO context | `WordBoundaryTest.anAmbiguousNameMatchesProgramsOnlyAndAsksForALookNotAVerdict`, `dualUseToolsAreContextAndEveryRuleSaysWhereItComesFrom` |
| D2 | Rules | No provenance, classification, review status or withdrawal for rules | Closed | Format 2: `class`, `status` (all current rules honestly `provisional`), `source`, `since`; withdrawn rules kept but never loaded; `docs/rules-pipeline.md` | `WordBoundaryTest.dualUseTools…` (every rule has class/source/status), `SignatureLoaderTest.withdrawnRulesStayInTheFileButAreNotUsed` |
| D3 | Rule updates | Signed updates not tested for incompatible format, empty rule sets, interrupted downloads, recovery | Closed | Newer format and empty sets refused; cut-off and new-file/old-signature refused; next complete pair used; key-compromise procedure documented | `SignatureLoaderTest` (4 new tests) |
| D4 | Rules | Known-hash list empty | Kept empty, by design | No hash without a classified sample through the isolated process (`docs/rules-pipeline.md`); stated in the rule file and tested | `WordBoundaryTest` asserts `hashes` empty |
| M1 | Measurement | No false-positive measurement on real files | Done (benign only) | `--evaluate-benign`: 61,423 legitimate files (Linux `/usr`, Windows System32/SysWOW64/Program Files/Defender), 0 outcome-moving, 95 % upper bound 0.0063 %; raw JSON in `docs/evidence/benign/` | `BenignCorpusTest` (Wilson interval, attribution), `docs/validation.md` §8b |
| K1 | Kernel (Linux) | Hidden-process re-check inverted: skipped PIDs that answer at `/proc/<pid>` (exactly what a readdir-filter rootkit hides) and reported processes that exited between reads | Closed | `HiddenObjects.confirmedHidden`: alive + missing from two listings + same name; exited / started / reused PIDs are races | `KernelComponentTest` (race cases + real hiding case) |
| K2 | Kernel | Component states conflated ("absent" for access denied, I/O errors, exceptions); incomplete report threw a generic error | Closed | `ABSENT`, `INACCESSIBLE`, `FAILED`, incompatible, partial, `COLLECTED`; failures → `PARTIAL`; every collected comparison states that an empty diff is not proof | `KernelComponentTest.otherProtocolsAndTruncationAreNamed`, catalogue `kernel:cross-view`, `kernel:component-inaccessible` |
| K3 | Kernel | Parser not fuzzed; module not statically checked | Done | 20,000-case seeded fuzz of `KernelReport.parse`; `make W=1` and GCC `-fanalyzer` on `moonmon.c` clean (compile only, never loaded) | `KernelComponentTest.theParserSurvives…`; `docs/kernel.md` |
| K4 | Kernel | Production signing and runtime validation not established | Open — release blockers | Microsoft docs (2026-03-23): attestation signing is for testing only, needs EV cert + Partner Center; retail → WHCP/HLK. No isolated load/stress run yet; no Windows build/SDV/Driver Verifier here; Windows cross-view diff not implemented | `docs/kernel.md` "Release blockers" |
| H1 | Panel: object access | Swept every session-scoped endpoint over direct HTTP; found one gap: a deletion request whose check was already gone could be handled by any member with delete rights | Closed | Orphan requests need `checks.view_all`; all other endpoints already 404 for invisible checks | `tests/test_object_access.py` (9 endpoints GET/POST, lists/search/stats/player history, audit/settings, player tokens) |
| H2 | Panel: retention | The audit log kept player names, PC names, codes and the player's IP / browser string forever — after a deletion request and after retention purges | Closed | `scrub_player_data` on player deletion and retention purge (actions, times and admin identities stay); audit events expire after `MOON_AUDIT_RETENTION_DAYS` (730) | `PlayerDataRetentionTests` |
| H3 | Panel: abuse | Progress endpoint had no per-check write limit | Closed | 120 updates per minute per check (heartbeat is one per 5 s), then 429 | `test_a_flood_of_progress_updates_is_limited` |
| S1 | Supply chain (panel) | Dependencies as version ranges; base image by tag | Closed | `requirements.lock` with SHA-256 hashes (`pip install --require-hashes`), base image pinned by digest; image build verified; `pip-audit`: no known vulnerabilities (2026-09-29) | docker build + import smoke; pip-audit output |
| S2 | Supply chain (checker) | `jackson-databind` 2.17.2 had 9 OSV advisories (GHSA-3pjw…, -5jmj…, -gx83…, -hgj6…, -j3rv…, -q4xh…, -rmj7…, -vvgp…, -wjgm…) | Closed | 2.18.10 (fixes all nine); OSV query over every runtime dependency: none known | 244 Java tests; OSV batch query |
| S3 | Supply chain (build) | Bundled JRE downloaded as "latest" and launch4j downloaded without any checksum | Closed | JRE pinned to Temurin 21.0.12.1+1 with Adoptium's published SHA-256; launch4j pinned to the hash of the copy used since 2026-09-14 (trust on first use, stated); mismatches stop the build | `scripts/build-exe.sh` |
| S4 | Reproducibility | Jar, exe and zip differed between builds of the same source | Closed | Fixed `outputTimestamp`, clean builds, PE TimeDateStamp + checksum normalised (`scripts/pe-normalize.py`, checksum verified against Windows' own notepad.exe and kernel32.dll), deterministic zip | Two consecutive builds: identical jar, exe and zip SHA-256; normalised exe runs on Windows (exit 0) |
| S5 | Delivery | `MoonCheck.exe` is not Authenticode-signed | Open — blocker | Needs a code-signing certificate (EV recommended); until then Windows shows an unknown-publisher warning and the claimed-build check stays a claim | `Get-AuthenticodeSignature` = NotSigned |
| P1 | Privacy | Checker logs accumulated forever; the download page said nothing stays on the PC | Closed | Logs pruned after 14 days; `--forget` removes them; download page explains removal in RU/EN | `LogRetentionTest` |
| U1 | UI | "Checker build" and "About the PC" rows were green when they had no warnings — green read as verified | Closed | Claim rows neutral; only the panel's own checks can be green | headless Chromium check of row classes |
| U2 | UI (mobile) | "Перепроверить" overflowed its button in the mobile decision bar | Closed | Buttons wrap and fit at 360 px | headless Chromium at 360 px |

## Verification log

| When | What ran | Result |
|---|---|---|
| 2026-09-29 | Java suite (baseline) | 203 pass, 1 skipped |
| 2026-09-29 | Django suite (baseline) | 97 OK |
| 2026-09-29 | Real checker (jar, Linux) → local panel, protocol 3 | bound, value consumed, verification codes equal |
| 2026-09-29 | Django suite, SQLite | 133 OK, 4 skipped (thread races need PostgreSQL) |
| 2026-09-29 | Django suite, PostgreSQL 17 (docker, throwaway) | 133 OK |
| 2026-09-29 | Mutation check: old `totp.py` + no owner lock, PostgreSQL | 6 of the new tests fail, as they should |
| 2026-09-29 | Java suite | 205 pass, 1 skipped |
| 2026-09-29 | Java suite after C1–C4, L1–L4 | 227 pass, 1 skipped |
| 2026-09-29 | Windows 11 VM, smoke (`windows-smoke.ps1`) after C1–C4 | 8/8 PASS but 116 s and ~40 Microsoft files "publisher not verified" → W1 |
| 2026-09-29 | Windows 11 VM, smoke after W1 | 7/8: disguised signed program silenced → C5 |
| 2026-09-29 | Windows 11 VM, smoke after C5 | 8/8 PASS, 51 s, 9/9 required parts, no unverified Microsoft files, only planted artefacts + correct context |
| 2026-09-29 | Java suite after W1, C5 | 229 pass, 1 skipped |
| 2026-09-29 | Linux host full scan (non-root) | `linuxfiles` PARTIAL (Documents over the 100,000-file limit; root-only /tmp folders), reviewer's leftover fixtures `native_payload` / `.so` / nested `usr/sample.bin` reported identically; two dictionary-word FPs → D1 |
| 2026-09-29 | Benign corpus, Linux host + Windows VM | 61,423 files, 0 outcome-moving (Wilson 95 % upper 0.0063 %) |
| 2026-09-29 | `moonmon.c` `make W=1`, `-fanalyzer` (Linux 7.0 headers) | clean; not loaded |
| 2026-09-29 | Java suite after D1–D3, K1–K3 | 244 pass, 1 skipped |
| 2026-09-29 | Panel suite after H1–H3 | SQLite 141 OK (4 PostgreSQL-only skipped); PostgreSQL 17: 141 OK; no missing migrations |
| 2026-10-01 | Windows 11 VM, checker 1.3.0 full CLI scan → local panel | 9/9 required parts, bound upload, codes equal |
| 2026-10-01 | Headless Chromium, 8 panel pages × desktop 1366 / mobile 390 | no console errors, no horizontal overflow |
| 2026-10-01 | Java 245 / panel 141 (SQLite + PostgreSQL) | all pass |
| 2026-09-29 | Reproducible build, twice | jar `000de50e…`, exe `70a294e8…`, zip `19f78c26…` identical both times |

PostgreSQL run: `docker run -d --rm --name moon-test-pg -e POSTGRES_DB=moon -e POSTGRES_USER=moon
-e POSTGRES_PASSWORD=moontest -p 127.0.0.1:55432:5432 postgres:17-alpine`, then in `web/`:
`DJANGO_DEBUG=1 POSTGRES_DB=moon POSTGRES_USER=moon POSTGRES_PASSWORD=moontest POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=55432 python manage.py test`.
