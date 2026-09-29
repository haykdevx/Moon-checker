# Report assurance — what the panel can and cannot say about a report

The checker runs on a PC the player controls, usually with administrator rights. Everything
the panel receives — findings, coverage, "ran as administrator", the checker's own file hash,
host name, timings — passes through that PC. A player who modifies the checker, or writes a
report by hand, can make every one of those values say anything. This page lists each
mechanism in the upload path and says exactly what it establishes, so no screen presents a
client claim as a verified fact.

## The five questions on the check page

The panel keeps them apart (`web/checks/trust.py`). An answer to one never stands in for another.

| Question | Who answers | What the panel shows |
|---|---|---|
| **Delivered for this check?** | the panel (session token + single-use upload value) | ✓ when bound; a warning for pre-1.3 checkers accepted during the transition |
| **Report consistency** | the panel (recomputed outcome, required parts, same PC as at connect, server clock, network path, rule origin, consent) | ✓ no contradictions / ! warnings / ✕ contradictions |
| **Checker build** | the player's PC (claimed SHA-256 of the checker file) | "The checker *says* it is build X" — never "official build verified" |
| **Did the official checker really run?** | nobody, today | always "Not independently verified" |
| **About the PC** | the player's PC (rights, OS, platform security, VM) | "The checker *reports* …" |

The session's stored `trust` value is the worst level among the panel's own checks. "ok"
means those checks found no contradiction; it is labelled that way, never "trusted".

## Mechanisms, one by one

| Mechanism | Establishes | Does not establish |
|---|---|---|
| **Check code** (8 characters, single-use, expires, one admin) | Who started the check; only one checker can claim it | Anything about the PC or the program that claimed it |
| **Session token** (random 256-bit, only SHA-256 stored) | Later progress and report requests come from whoever claimed the code | That this is the official checker |
| **Upload value** (protocol 3: random 256-bit, only SHA-256 stored, issued at claim, in the report next to the panel's session id, consumed by one conditional `UPDATE`) | The report was produced *or edited* for this check after the code was entered; an unmodified report from another check or an earlier upload cannot be delivered; exactly one report is accepted even when two race | That the report was produced by an unmodified checker — the value passes through the player's PC and a forger can copy it into any JSON |
| **Protocol version** (3) | Client and server agree on the upload rules; older clients are refused unless the owner's transition switch is on, and then the check is marked "not bound" | — |
| **Upload deadline** (claim + 3 h by default, `MOON_UPLOAD_WINDOW_MINUTES`) | A claimed session cannot be completed days later with a prepared report | — |
| **Same PC at connect and upload** (host name, user, OS, version, program-file hash prefix) | A report assembled from a different machine's run is refused unless it also copies those fields | Anything, against a careful forger |
| **Report id replay check** | The same report id cannot be delivered into two checks | — (ids are client-generated) |
| **Server-recomputed outcome** (`policy.expected_outcome` with the panel's own list of required parts) | The outcome shown follows the official rules from the evidence and coverage that were *submitted*; a report cannot drop a required part or state "no evidence" over its own detection | That the submitted evidence is complete or genuine |
| **Verification code** (HMAC-SHA-256 over the canonical report, key compiled into the checker) | The panel holds the same bytes as the checker window the admin sees over screen share; accidental corruption and casual edits show up | Origin: the key is public inside the checker, so anyone can compute a matching code for a forged report |
| **Upload checksum** (`X-Moon-Sha256`) | Transport integrity | Origin |
| **Build hash claim** (`selfHashFull` compared with registered builds) | Whether the checker *says* it is an official build — outdated copies and casual modifications that do not fake the hash are caught | Which program actually ran; a modified checker can send the official hash |
| **"Refuse unknown builds" setting** | Stops outdated and casually modified copies from connecting | Stops a determined forger |
| **Server clock timing, IP change, interruptions** | Sloppy forgeries, relaying, instant "scans" | Careful forgeries |
| **Authenticode signature of `MoonCheck.exe`** (when signed) | Windows can tell the player the file came from the publisher | Anything to the panel: the running process can be patched after start |
| **Obfuscation, embedded secrets** | Raise the effort of a forgery | Anything — they are not used as assurance |

A legitimate scan that finds nothing is accepted like any other: "no evidence" is a valid
outcome. It is shown in a neutral colour as "No evidence reported", with the note that the
report's content is not proof the PC was inspected.

## What stronger assurance would require (not implemented)

Proving that an unmodified checker ran on the PC needs a root of trust the player cannot
edit. The realistic option on Windows is **TPM-based attestation**:

- **Trust anchor:** the TPM's endorsement key, certified by the TPM manufacturer, and an
  attestation key bound to it (Windows: `Microsoft Platform Crypto Provider`; a verifier such
  as Azure Attestation or a self-run service that checks the EK certificate chain).
- **Measurements verified:** the boot log and PCRs (firmware, boot manager, Secure Boot
  policy, early-launch drivers, VBS/HVCI state), and — only with a signed kernel driver
  measured by Windows or a VBS enclave — the checker component itself.
- **Freshness:** the panel's single-use value as the quote's qualifying data.
- **Binding to the session and report:** the quote's qualifying data = SHA-256(upload value ‖
  SHA-256(canonical report)), so a quote cannot be moved to another report.
- **Deployment requirements:** TPM 2.0 (present on Windows 11 PCs), a code-signing and
  (for any kernel part) Microsoft attestation signing account, an attestation verifier, and a
  policy of acceptable measurements maintained per Windows build.
- **Remaining gaps:** a valid boot measurement shows how the machine *started*; it does not
  show what ran afterwards. User-mode code, including the checker, can be patched after boot
  by an administrator. Kernel drivers loaded later, DMA devices, a second PC reading memory,
  virtualisation that the boot log does not reveal, and hardware attacks on the TPM bus
  remain outside it. Even with attestation, "the official checker ran on a machine that
  booted a measured Windows" is the strongest statement available — not "the PC is clean".

Until such an anchor exists, every report is labelled "Not independently verified", and the
admin's own observation over screen share (the verification code, the checker window) remains
part of the process.

## Tests that pin this

`web/tests/test_api.py`: `test_a_fabricated_report_claiming_an_official_hash_gets_no_verified_label`,
`test_an_honest_zero_finding_scan_is_accepted`, `test_connect_and_upload_must_describe_the_same_pc`,
`test_a_report_from_a_different_program_file_is_refused`, `test_a_report_made_for_another_check_is_refused`,
`test_unbound_and_wrong_protocol_reports_are_refused`, `test_a_late_upload_is_refused`,
`test_a_report_id_seen_in_another_check_is_refused`, `test_an_edited_outcome_is_replaced_by_the_servers`,
`test_a_stale_view_of_the_session_cannot_complete_it_twice`, `test_legacy_checkers_only_when_the_owner_allows_it_and_marked`,
`ReportPageTests` (rendered page, English and Russian, including signals stored before 1.3);
`src/test/java/ru/moon/checker/report/EvidenceTest.java`: `aBoundReportCarriesItsCheckAndTheCodeCoversIt`.
