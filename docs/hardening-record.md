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

PostgreSQL run: `docker run -d --rm --name moon-test-pg -e POSTGRES_DB=moon -e POSTGRES_USER=moon
-e POSTGRES_PASSWORD=moontest -p 127.0.0.1:55432:5432 postgres:17-alpine`, then in `web/`:
`DJANGO_DEBUG=1 POSTGRES_DB=moon POSTGRES_USER=moon POSTGRES_PASSWORD=moontest POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=55432 python manage.py test`.
