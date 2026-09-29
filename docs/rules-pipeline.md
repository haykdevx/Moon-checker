# Detection rules: classes, provenance, updates and evaluation

This page defines what the checker's rules are allowed to claim, how a rule gets in and out,
how updates are trusted, and how detection is measured. It exists because the review of
2026-09-29 found an empty known-hash list, rules without provenance, and no measured
accuracy. None of the numbers here say how many real cheats the checker catches: that needs
labelled real samples, which the project does not have (see "Release blockers").

## Threat classes and what each can show

| Class | What the checker looks at | Evidence kind at best | Cannot see |
|---|---|---|---|
| **File-based cheat on disk** (loader, internal DLL, external program) | names (MFT/walk), exact hash, content heuristics (CS2 offset names, injection imports, entropy), disguise, hidden streams | `DETECTION` only for an exact hash of a classified sample; otherwise `INDICATOR` | a cheat that never touches disk, or is renamed and rebuilt (new hash, no telltale strings) |
| **Memory-resident / injected** | modules loaded into a running `cs2.exe`, windows drawn over it | `INDICATOR` | manually mapped code (not in the module list), anything when CS2 is not running during the check |
| **Kernel-assisted** | loaded drivers vs. vulnerable-driver names, test-signing, Secure Boot / HVCI state, the optional Moon kernel snapshot | `INDICATOR` / `CONFIGURATION` | a rootkit that hides from both views; see `docs/kernel.md` |
| **Historical traces** | Prefetch, AmCache, UserAssist, BAM, USN journal, recycle bin, browser history, Defender history, shell history (Linux) | `INDICATOR` (use on this PC), `CONCEALMENT` (cleaning) | traces wiped before the check beyond what the journal keeps; another PC |
| **External assistance** | DMA cards and macro devices by USB/PCI identifiers, macro software | `INDICATOR` / `CONTEXT` | a second PC, a capture-card setup, firmware that lies about its IDs |
| **Dual-use software** (debuggers, memory editors, process tools) | names | `CONTEXT` (INFO) — never outcome-moving | intent |
| **Vulnerable but legitimate drivers** (Afterburner, RGB tools) | driver name + location | `CONTEXT` when installed by software, full severity when dropped in a user folder | intent |

A report's outcome can move only on `DETECTION`, or `INDICATOR`/`CONCEALMENT` at MEDIUM or
above (`VerdictEngine`). Context and configuration never move it.

## What a rule carries (`signatures.json`, format 2)

`class`, `status` (`reviewed` | `provisional` | `withdrawn`), `source` (provenance, stated
plainly — "not verified against samples" where true), `since` (rules version), and
`ambiguous` for names that are also ordinary words or legitimate products (`predator`,
`gamesense`, `midnight`…): those match program or archive names only and never count above
MEDIUM. Withdrawn rules stay in the file for the record and are never loaded. Every rule in
the current set is `provisional`: they are publicly advertised product and tool names, and no
rule has been checked against a real sample.

**Known hashes: empty on purpose.** A hash is added only with a sample a maintainer
obtained through the isolated process below and classified, with the sample's provenance,
date and classification recorded next to the hash. Hashes from random internet lists or
guesses are not accepted: one wrong hash is a false `DETECTION`, the only kind that reads as
proof.

## Adding, reviewing and withdrawing a rule

1. Proposal with source and class. Names that are ordinary words or legitimate products are
   marked `ambiguous`.
2. `provisional` until checked: against the benign corpus (below) for false positives, and —
   for hash and content rules — against labelled samples in the isolated environment.
3. `reviewed` when both checks are recorded in `docs/validation.md` with their denominators.
4. A rule that produced a confirmed false positive on a player's PC is `withdrawn` in the next
   rules version (not deleted), with the reason.

## Signed updates

Bundled rules are the default. An override next to the checker is used only if
`signatures.json.sig` is a valid Ed25519 signature over its exact bytes by a key in
`rules-keys.txt` (shipped inside the build), its version is not older than the bundled one,
its format is one this checker understands, and it contains rules. Tested in
`SignatureLoaderTest`: signed newer accepted; unsigned, wrong key, tampered, older (rollback),
newer format (incompatible), empty, cut-off download and new-file-old-signature (interrupted)
refused with the bundled rules kept and the reason noted in the report; the next complete
pair is used (recovery); withdrawn rules are not loaded.

The panel refuses to treat a report as complete when its rules did not come from the build
or a signed update (`rules_ok`).

**If the signing key is compromised:** generate a new Ed25519 key offline; ship a checker
build whose `rules-keys.txt` lists only the new key; raise "Oldest allowed checker version"
in the panel to that build, so older checkers (which still trust the old key) cannot connect;
re-sign the current rules with the new key. The old key's signatures are then worthless to
every checker the panel accepts. The private key never enters the repository or a server.

## Evaluation

**Deterministic fixtures** (`ValidationCorpusTest`, `ContentAndLocationTest`): harmless byte
patterns with fixed seeds. They prove that each stage works (a disguised program is flagged,
identical content under different names gets identical findings, limits are reported). They
are not evidence that a real cheat would be detected.

**Benign corpus** (`--evaluate-benign <folder>`): runs the file inspection over real,
legitimate files and counts, per rule, how many files would be reported and how many would
move the outcome, with a Wilson 95 % interval for the per-file false-positive rate. Results
and the exact folders are in `docs/validation.md` ("Benign corpus"). Run on this project's
Linux host and on the Windows 11 test VM; neither is a gaming PC.

**Labelled real samples (not done — release blocker).** The procedure, when samples are
available through an authorised channel:
- a disposable, offline VM snapshot per run; samples never on a host or a player-facing machine;
- samples split before any tuning into a development set and a held-out set by *family and
  release date* (no variant of a held-out family in development), recorded with hashes;
- rules and thresholds frozen before the held-out set is scanned once;
- report per class: true/false positives and negatives with denominators and Wilson 95 %
  intervals; results published whether good or bad;
- the benign corpus scanned with the same frozen rules in the same run.

Until that exists, the product's detection accuracy on real cheats is **unknown** and is
described that way.
