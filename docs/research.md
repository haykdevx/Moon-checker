# Protocol Moon — research notes (2026-09-28)

What was consulted, how, and what each source can and cannot support. Web pages
were read through a fetch tool or, where the site refused automated fetches,
through search-engine snippets of the page; that difference is recorded. No video
footage was watched (see §3), and no cheat software was downloaded or executed.

## 1. Sources

| Source | Kind | Access | Maintenance / licence | Used for |
|---|---|---|---|---|
| FACEIT support: “What is FACEIT Anti-cheat and how does it work?”, “Windows Security Requirements FAQ”, “Enabling IOMMU / DMA Protection”, “Enabling Memory Integrity (HVCI)”, “Enabling TPM 2.0”, “Human Input Detection FAQ” (support.faceit.com) | Vendor documentation | **Search snippets only** — direct fetches return HTTP 403 | Current (mentions dates up to Nov 2025) | Architecture reference; platform-security preconditions; continuous vs one-time inspection |
| Dorner & Klausner, *If It Looks Like a Rootkit and Deceives Like a Rootkit: A Critical Examination of Kernel-Level Anti-Cheat Systems*, arXiv:2408.00500 (Aug 2024) | Peer-review-style research | Abstract page | — | Privacy/integrity risks of kernel anti-cheat; design constraints for our kernel components |
| EasyCheatDetector (github.com/UnrealKaraulov/EasyCheatDetector) | Community checker | Repository page | **Binaries only, no licence file**; releases up to 3.32 | Scope comparison only. Its per-game detection rates (e.g. “CS2: 50%”) have no published method and are not used as evidence |
| SteeLChecker (github.com/ZerioCommand/SteeLChecker) | Community checker | Repository page | Binaries only (a LICENSE file but no source); C#/WPF | Scope comparison; it also ships a web “Live Panel” |
| CS2-Check-Cheats (github.com/ABKAM2023/CS2-Check-Cheats) | CounterStrikeSharp server plugin | Repository page | Source available, licence not shown, 14 commits | Workflow reference for MOON server integration (`!check`, countdown, contact, ban) |
| LOLDrivers (github.com/magicsword-io/LOLDrivers, loldrivers.io/api/drivers.json) | Curated vulnerable/malicious driver data | Repository page, API description | **Apache-2.0**, actively maintained (1,286 commits) | Candidate hash source for the vulnerable-driver indicator (not yet imported) |
| Microsoft Learn: *Microsoft recommended driver block rules* | Vendor documentation | Search snippets | Current | Blocklist is on by default since Windows 11 2022 and enforced with Memory Integrity |
| YouTube search “проверка пабликов с читами” and related queries | Videos | **Titles/URLs only** | — | See §3 |

The “YouTube example” named in the brief came without a link, so it could not be
identified; only the search above was reviewed.

## 2. Findings that shape the design

1. **Platform security is a precondition, not a detector.** FACEIT requires TPM 2.0
   (mandatory from 25 Nov 2025 per its FAQ), Secure Boot, Memory Integrity (HVCI) and
   IOMMU/DMA protection with VBS, to close off the cheap cheat paths it names:
   vulnerable drivers, EFI cheats and DMA devices. For Moon these become **assurance**
   facts reported with every scan, never cheating verdicts. Moon does not (and as a
   one-time checker cannot) enforce them.
2. **Attestation needs a trust anchor the player cannot forge.** FACEIT uses TPM measured
   boot and signed attestation. Moon's current report is produced by user-mode code on the
   player's PC and is trustworthy only as far as that code is; the design for a TPM-quote
   attestation path is in `docs/threat-model.md` §6 and is **not implemented**.
3. **Continuous match protection is a different product.** FACEIT's Human Input
   Detection scores in-match inputs with a learned model and weighs it with other
   signals. A one-time inspection cannot observe gameplay; Moon's verdicts never claim to.
4. **Kernel anti-cheat has real privacy and integrity cost** (Dorner & Klausner): Moon's
   kernel components are optional, on-demand, read-only, restricted to SYSTEM/Administrators,
   and never load at boot.
5. **Community checkers publish no validation.** The detection rates quoted by
   EasyCheatDetector are unverifiable. Moon reports measured results on stated sample
   sets only (`docs/validation.md`).
6. **Exact driver identity beats names.** LOLDrivers provides hashes. A hash match of a
   known vulnerable driver is still an *indicator*, because legitimate utilities load such
   drivers, but it removes name-collision false positives.

## 3. Video observations

No footage was watched. The claims below rest on **titles and URLs returned by search**
(2023–2025 uploads), not on what the videos show, and no timestamps can be given.
Titles in this genre are largely made by cheat sellers or promoters demonstrating
evasion of *manual* admin checks. Product names are deliberately not reproduced here.

| Observation (from titles only) | Defensive implication | Covered by |
|---|---|---|
| Admins “could not find” cheats during screen-share checks | Manual checks miss artefacts; automate collection, report coverage honestly | Whole design |
| A cheat “hidden in a picture” | Executable content disguised with a non-executable extension or inside another file | `files` collector: PE content with a non-executable extension, alternate data streams |
| Server-side cheat cvars enabled “on publics” | Server configuration problem, not a PC artefact | Out of scope for the checker; server integration |
| Admins checking via screen share for a fixed time | A live, verifiable session is needed; recordings can be replayed | Session codes, live clock, server-side timing, verification code |

## 4. Research matrix

Each row: technique class → the evidence it can leave → what collection requires →
legitimate lookalikes → limits → a reproducible, harmless test. “Test” rows marked
*fixture* run in the unit suite; *lab* needs a Windows machine.

| Technique class | Evidence | Collection requires | Legitimate lookalikes | Limits | Defensive test |
|---|---|---|---|---|---|
| Known cheat binary on disk | SHA-256 of a classified sample | Read access to the file (admin for all users) | None for the exact hash | Any rebuild changes the hash; possession ≠ use | *fixture*: harmless generated file whose hash is in a test signature pack → DETECTION (`FileInspectionTest`, synthetic corpus) |
| Loader/program executed then deleted | Prefetch, BAM, UserAssist, AmCache, USN delete records | Admin; artefacts within their retention | Uninstallers, updaters with similar names | Retention windows; wiped artefacts | *fixture*: parser fixtures (`PrefetchBodyTest`, `ParsersTest`, `AmCacheTest`) |
| Internal cheat (code injected into CS2) | Unexpected modules in the game process; Prefetch loaded-module lists | Game running; admin | Overlays (Steam, Discord, OBS, RTSS), GPU tools | Manually mapped code is absent from module lists | *lab*: benign DLL loaded into a test host, collector must list it |
| External reader | Process holding a read handle to CS2 (Windows); tracer on the game (Linux) | Live, during play | Recording/overlay tools, security software | Nothing persists after exit — continuous monitoring only | *lab*: benign harness opening a read handle to a dummy target |
| Kernel-assisted cheat | Vulnerable/unknown driver loaded or registered; test signing/DSE off | Admin; kernel component optional | Old vendor utilities, anti-cheats of other games | Manually mapped drivers are in no module list | *fixture*: `KernelReportTest`, driver-path classifier; *lab*: driver report on a test PC |
| DMA hardware | PCI device IDs; IOMMU/Kernel DMA protection state | Device enumeration | FPGA development boards | Firmware can spoof IDs; the OS cannot see DMA reads | *fixture*: PCI match unit test (to add) |
| Concealment | Event-log clears, SysMain/Prefetch disabled, USN reset, disguised PE, hidden processes | Admin | Privacy cleaners, fresh installs, container PID namespaces | Careful cleaning leaves nothing | *fixture*: disguised-PE fixture, `KernelReportTest` framing cases |
| Checker tampering / forged report | Unknown build hash, verdict inconsistent with evidence, shrunk required list, identity or timing mismatch, replayed report id | Server-side checks | — | A fully patched client can lie consistently; bounded by attestation (not implemented) | *fixture*: panel tests `EvidenceV2Tests`, `ApiFlowTests` (replay, identity, timing) |
| Replayed session / screen recording | Single-use code, token binding, server clock vs claimed duration, on-screen verification code and live clock | Panel | — | A live remote-controlled PC is still a live PC | *fixture*: panel tests |
| Input automation / “AI aim” with external capture and HID hardware | Capture software, extra HID devices (weak) | Live observation | Streaming setups, macro mice | Invisible to a one-time inspection; needs gameplay analysis | Out of scope — documented limitation |
| Firmware / bootkit / compromised kernel | Secure Boot state, measured boot (TPM) | Attestation | — | Local inspection cannot be trusted on a compromised kernel | Out of scope until attestation exists |
