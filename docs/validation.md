# Validation

Measured on 2026-09-28 with rules `2026.09.28-cs2`. Every number in sections 3 to 7 is
asserted by a test: `ValidationCorpusTest` (checker), `test_policy_golden.py` and
`test_fuzz_ingest.py` (panel). A change that moves one of them fails the build until this
document is updated. Section 8 is the exception. It describes the machine that ran it, so it
is reported as measured and is not pinned.

## 1. What is measured and what is not

**Measured.** These numbers cover:

- the matching logic of three file-content mechanisms: exact hash, executable disguised by
  extension, and CS2 offset names;
- the outcome policy, in both the checker's `VerdictEngine` and the panel's copy of it;
- how the panel's report ingestion handles malformed uploads;
- which rules match benign system files on one Linux machine.

**Not measured: real-world detection.** No cheat software was downloaded, executed or used.
The positives are harmless generated files: random bytes that start with `MZ`, described by a
test-only rule pack or by the bundled offset rules in the way a real rule describes a cheat.
So the numbers show whether the matching and the policy do what they claim. They do not show
how many real cheats the shipped rules catch, or how often a real player's PC trips a rule.

**Blocker.** Real-world numbers need a labelled corpus of real samples. That means cheat
builds with provenance, and benign lookalikes such as Source-engine demo and movie tools,
server plugins, overlays and macro software. Maintainers would handle the samples offline
under a written policy, and this project would never execute them. It also needs a consented
benign baseline from real Windows gaming PCs. Until then, precision and recall on real data
are unknown.

## 2. How to reproduce

```sh
mvn -q -B test                                   # sections 3-6 (host baseline skipped); compares with the golden file
mvn -q -B test -Dtest=ValidationCorpusTest -Dmoon.validation.host=true      # adds section 8 for this machine
mvn -q -B test -Dtest=ValidationCorpusTest -Dmoon.validation.writeGolden=true  # regenerate spec/policy-golden.json, deliberately
cd web && DJANGO_DEBUG=1 python manage.py test tests.test_policy_golden tests.test_fuzz_ingest
```

Results are written to `target/validation/results.json` before any assertion runs, so the
file exists even when a number has moved. The corpora are generated from seed `20260928`:
+0 for hashes, +1 for disguised extensions, +2 for offset names, +3 for policy scenarios. The
panel fuzz uses the same seed. All of it is deterministic except section 8.

Toolchain used: Temurin JDK 21.0.12.1, Maven 3.9.9, Python 3.14.4, Django 5.2.17, on Ubuntu
26.04 x86_64. The generated files live in JUnit's temporary directory (`/tmp/junit…`). Those
tests assume that path is not under an allowlisted location (`/usr/`, `/opt/`, `/lib/` …).

## 3. Exact-hash rules

**Corpus.** 100 random `MZ` files of 4–32 KiB. Their SHA-256s go into a test-only rule pack
as `CRITICAL` hash rules. Another 100 random files are unknown negatives. Each known file is
inspected three ways:

- as written (`sample-N.exe`);
- the same bytes renamed and moved (`moved/notes-N.png`);
- a copy with one byte flipped at a random offset after the `MZ` signature.

**Label.** Positive means "the same program as a classified sample". **Raised** means a
`DETECTION` finding.

| Corpus | TP | FP | FN | TN | Precision | Recall |
|---|---|---|---|---|---|---|
| Exact copies | 100 | 0 | 0 | 100 | 1.0 | 1.0 |
| Renamed and moved copies | 100 | 0 | 0 | 100 | 1.0 | 1.0 |
| One byte patched | 0 | 0 | 100 | 100 | — | 0.0 |

Exact identity survives renaming and moving, and it never fires on unknown content. It does
not survive any change to the file. A rebuild, a new version or one patched byte evades it by
design. That is why a hash match is the only `DETECTION` and everything else is an indicator.

## 4. Executable disguised by extension

Rule `files:executable-disguised-by-extension` fires on content that starts with `MZ` under a
document, media or archive extension, outside an allowlisted path.

**Corpus.**

- 60 positives: random `MZ` files named `file-N` with `.png .jpg .txt .mp4 .zip .cfg`, 10 each.
- 120 negatives:
  - 60 real-format files with those extensions (PNG, JPEG, MP4 and ZIP headers, or plain
    settings text);
  - 60 `MZ` files with legitimate PE extensions (`.dll .cpl .drv .ocx .sys .exe`).
- 20 disguised PEs inside an allowlisted directory (`…/opt/vendor/`), which must be suppressed.

| TP | FP | FN | TN | Precision | Recall | Suppressed in allowlisted path | `DETECTION`s from the heuristic |
|---|---|---|---|---|---|---|---|
| 60 | 0 | 0 | 120 | 1.0 | 1.0 | 20/20 | 0 |

The suppression is a deliberate blind spot. This heuristic does not report a disguised PE
anywhere under an allowlisted location. Exact name and hash matches there are still reported.

## 5. CS2 offset names in a binary: the decision

Rule `files:cs2-offset-strings-in-binary`. The 24 bundled `offsetStrings` rules fall into two
families:

- **10 offset-dump names** (`dwEntityList`, `dwViewMatrix`, …; rule severity HIGH). These
  come from cheat-community offset dumps.
- **14 game field names** (`m_iHealth`, `m_vecOrigin`, …; rule severity MEDIUM). These are
  the game's own fields. Legitimate Source-engine tools contain them too: demo and movie tools,
  server plugins and SDK code.

**Rules `2026.09.14-cs2`.** Every name was a substring match, so `m_iHealthMax` counted as
`m_iHealth`. One hit of any name gave a MEDIUM finding, and therefore `REVIEW_REQUIRED`.

**Rules `2026.09.28-cs2`.**

- The 14 `m_…` rules match whole identifiers only. A letter directly before or after the name
  breaks the match; digits, `_`, `:` and quotes do not.
- The `dw…` rules stay substring matches.
- `FileInspection` step 5 sets the severity like this:

| Distinct names found in one binary | Severity | Outcome effect |
|---|---|---|
| 3 or more | HIGH | `REVIEW_REQUIRED` |
| An offset-dump name, or exactly 2 names | MEDIUM | `REVIEW_REQUIRED` |
| Exactly 1 game field name and nothing else | LOW | Shown to the reviewer; does not ask for review |

**Corpus (200 samples).**

- 60 cheat-shaped (positive):
  - 30 with one dump name plus 0–2 distinct field names;
  - 30 with 2–4 distinct field names and no dump name.
- 40 negatives with a single field name: what a legitimate Source-engine tool can carry.
- 60 plain `MZ` negatives with none of the names.
- 40 near misses (negative): a field name inside a longer identifier (`…Max` suffix, `Old…` prefix).

**Label.** Positive means the sample should move the outcome, i.e. raise a finding at MEDIUM
or above.

| | Before (`2026.09.14-cs2`) | After (`2026.09.28-cs2`) |
|---|---|---|
| TP | 60 | 60 |
| FP | 80 | 0 |
| FN | 0 | 0 |
| TN | 60 | 140 |
| Precision | 0.4286 | 1.0 |
| Recall | 1.0 | 1.0 |
| Single field name reported | 40/40 (MEDIUM) | 40/40 (LOW) |
| Single field name moves the outcome | 40/40 | 0/40 |
| Near miss reported | 40/40 | 0/40 |

The "before" column was first measured on the unchanged matching code (commit `03bada8`).
The test still reproduces and pins it: it matches every offset name as a substring and counts
every reported offset finding as outcome-moving. That is exactly how `2026.09.14-cs2` behaved,
because every hit was MEDIUM or HIGH.

**How to read this.** The corpus encodes the policy, so FP = 0 shows the policy is
implemented. It is not a real-world false-positive rate. Two gaps remain:

- A legitimate tool that reads, say, health and position carries two field names and still
  reaches MEDIUM.
- A cheat that carries a single field name, or hides its strings, now yields only a LOW
  finding.

The real rate of either is unmeasured (section 9).

## 6. Outcome policy: one golden file for the checker and the panel

**Scenarios.** 1000 random scenarios, each with:

- **Evidence:** 0–3 items (none in 40% of scenarios). Kinds are drawn from DETECTION,
  INDICATOR ×3, CONCEALMENT, CONFIGURATION ×3 and CONTEXT ×3, and two thirds of the drawn
  DETECTIONs become CONTEXT. Severities are random.
- **Collectors:** 9 required Windows collectors, each OK in 94% of scenarios and
  ERROR/TIMEOUT/SKIPPED in 2% each.
- **Rights and platform:** elevated in 85%; platform supported in 92%.
- **Rules:** bundled in 80%, a signed override in 10%, none in 10%; the rule count is 0 for
  `none` and for 1 in 17 others.

**Golden file.** `VerdictEngine.assess` decides each outcome. The outcomes were written to
`spec/policy-golden.json` once, with `-Dmoon.validation.writeGolden=true`, one scenario per
line. Every normal run compares against that file. The panel replays it through
`checks.policy.expected_outcome`, deciding `rulesOk` server-side as ingestion does.

| Engine | Agrees with the golden file |
|---|---|
| Checker, `VerdictEngine` (`ValidationCorpusTest`) | 1000/1000 |
| Panel, `checks.policy` (`web/tests/test_policy_golden.py`) | 1000/1000 |

| Outcome | Scenarios |
|---|---|
| `INCOMPLETE_SCAN` | 430 |
| `NO_EVIDENCE` | 282 |
| `REVIEW_REQUIRED` | 205 |
| `UNSUPPORTED_CONFIGURATION` | 49 |
| `VALIDATED_DETECTION` | 34 |

The spec invariants are checked separately from the engine's code:

| Invariant | Scenarios it applies to | Violations |
|---|---|---|
| Any `DETECTION` ⇒ `VALIDATED_DETECTION` | 34 | 0 |
| Otherwise, INDICATOR/CONCEALMENT at MEDIUM+ ⇒ `REVIEW_REQUIRED` | 205 | 0 |
| Neither ⇒ never a cheating outcome (`VALIDATED_DETECTION`, `REVIEW_REQUIRED`) | 761 | 0 |
| CONFIGURATION-only evidence ⇒ never a cheating outcome | 71 (24 of them `NO_EVIDENCE`) | 0 |
| Incomplete coverage and no review evidence ⇒ never `NO_EVIDENCE` | 479 | 0 |

The golden file covers the outcome only. The assurance level and reason texts are covered
by `VerdictEngineTest`.

## 7. Report ingestion under malformed input (panel)

`web/tests/test_fuzz_ingest.py` starts from a valid `moon-evidence/2` report: three evidence
items, one verdict reason and one assurance note. It applies 300 mutations, taking 13 classes
in turn (24 of the first class, 23 of each other). Each mutation is uploaded to a freshly
claimed session. For the run, `MOON_MAX_UPLOAD_BYTES` is lowered to 256 KiB and
`MOON_MAX_REPORT_BYTES` to 768 KiB. The code paths are the same; over-limit bodies are just
cheaper to build.

The classes:

- **delete-key:** a key is deleted.
- **wrong-type:** a value becomes null, a number, a bool, a string, a list or an object.
- **huge-string:** a string grows to 5k–900k characters, some random, some non-ASCII.
- **bad-number:** negative, NaN, ±Infinity, 1e308 or 10³⁰.
- **evidence-ids:** the `E1…En` ids are broken (swapped, lower-case, integer, zero-based,
  duplicated, skipped, padded).
- **unknown-value:** an unknown kind, severity, level, outcome, checkId or collector state.
- **deep-nesting:** nesting 10 to 300,000 deep.
- **non-utf8:** invalid UTF-8 bytes inside the gzip.
- **lone-surrogate:** a `\ud800`-style escape.
- **gzip-damage:** truncated, bit-flipped, empty, header-only, or plain JSON labelled gzip.
- **size:** a gzip bomb, a report exactly at the limit and one byte over, too many bytes on
  the wire.
- **envelope:** unsupported `Content-Encoding`, correct and wrong `X-Moon-Sha256`, a
  non-object top level, v2 sections under the v1 schema name.
- **benign:** shuffled keys, unknown extra keys, non-ASCII text, 100–2500 evidence items,
  pretty-printed JSON, NUL characters.

Each mutation states what the report contract in `checks/ingest.py` requires:

- **reject:** a required key, a fixed type or an enumerated value is broken, or a size limit
  is exceeded;
- **accept:** only optional or free-text content changed, which the panel must clip or
  normalise;
- **either:** nesting deeper than the JSON parser's stack.

Every upload must end in exactly one of two states: accepted (200, report stored, session
`COMPLETED`), or rejected (4xx, nothing stored, session still `CONNECTED`).

Since upload protocol 3 (see `docs/report-assurance.md`) a report whose host name, user, OS,
version or program-file hash differs from what the checker sent when the code was entered is
refused, so the 5 mutations that change those fields moved from "accept" to "reject"
(previously 122/172). Each case now carries its own report id, because an id may be delivered
only once. The fuzz run delivers the prepared bytes as a pre-1.3 checker would (the owner's
transition switch on); binding itself is covered by `tests/test_api.py`.

| | Result |
|---|---|
| Mutations | 300 |
| Contract says accept → accepted and stored | 117/117 |
| Contract says reject → 4xx, nothing stored | 177/177 |
| Either | 6 (3 accepted, 3 rejected on Python 3.14.4; depends on the parser's stack, not pinned) |
| Server errors (5xx) | 0 |
| Invalid reports stored | 0 |
| Valid reports lost | 0 |

Measured status codes (Python 3.14.4, not pinned): 200 ×125, 400 ×63, 413 ×25, 415 ×5, 422 ×82.

**What the fuzz found.** Before this work (commit `0ab77f2`), the same 300 uploads produced
23 HTTP 500s:

- 9 unpaired surrogates reached the database driver. They came either as a `\ud800` escape,
  or as UTF-8-encoded surrogate bytes, which `json.loads(bytes)` accepts.
- 5 documents nested 300,000 deep raised `RecursionError` in the parser.
- 9 JSON lists or objects were tested for membership in a set: evidence severity, collector
  state, and a v1 `verdict`.

Commit `adcb8d0` fixed them:

- the body must be strict UTF-8, and a parser `RecursionError` is a 400;
- `clip()` replaces unpaired surrogates and returns an empty string for a list or object;
- enumerated values are checked in a way that cannot raise;
- `checkId` must fully match `MOON-<6 ASCII digits>-<4–8 A-Z0-9>`. The old pattern also
  accepted a trailing newline and non-ASCII digits.

The 23 is history, not a pinned number. Reproduce it by running the test file from `adcb8d0`
against `web/checks/ingest.py` from `0ab77f2`.

**Replay and token reuse.** `ReplayTests`, together with `tests/test_api.py`, checks the
following:

| Attempt | Result |
|---|---|
| The same report uploaded again to a completed session | 409, the client is told the existing verification code (`test_full_flow`) |
| A different report sent to a completed session | 409; first report, verdict and check id unchanged; no rows added |
| Progress sent with a completed session's token | 409; session stays `COMPLETED` |
| Session A's token used on session B's report or progress endpoint | 401; B still `CONNECTED`, nothing stored |
| The same report delivered in another check | Accepted but flagged `replay` (bad) (`test_replayed_report_is_flagged`) |
| A code claimed a second time, or after it expired | 409 `code_used`, 410 `code_expired` (`test_code_is_single_use_and_expires`) |
| Progress or a report on a session the admin cancelled | 410 (`test_cancelled_session_refuses_everything`) |

## 8. Benign baseline on one machine (measured, not pinned)

**Environment.** An Ubuntu 26.04 LTS x86_64 developer workstation:

- kernel 7.0.0-34-generic;
- 2126 dpkg packages and 32 snaps;
- Linux kernel headers, Node.js, GCC and KDE/GNOME runtime snaps installed;
- word list from `wamerican` 2020.12.07.

The walk covered `/usr /opt /snap /etc /var/lib`: 544,926 regular files (the cap of
2,000,000 was not reached). It is not a Windows gaming PC. These numbers describe this
machine only.

**File names against the name rules.** 62 files matched a rule, 0.011% of the files walked.
Rules are identified by list and index; their patterns are in `src/main/resources/signatures.json`.

| Rule | Files | What matched |
|---|---|---|
| `cheatNames#4` (substring rule) | 2 | A Linux kernel config entry named after a historical commercial Unix whose name contains the pattern; two installed header versions |
| `cheatNames#10` (substring rule; the pattern is an ordinary English word) | 1 | A Node.js contributor document named with the plural of that word |
| `cheatNames#48` (the generic word for an injection tool) | 2 | A Ruby Bundler source file and a Babel helper module whose file names contain that word, inside a KDE runtime snap |
| `cleaners#10` (an ordinary English word) | 19 | Icon files such as `draw-eraser.svg`, `tool_color_eraser.svg` and `cursor-eraser.png` in the Yaru, elementary, Breeze and Oxygen icon themes |
| `cleaners#3` | 1 | The software catalog's icon for the cleaner the rule describes. The catalog lists installable packages; the tool is not installed |
| `macroTools#1` (a two-character pattern) | 25 | X11 `5x7` bitmap fonts, Wacom `graphire2-5x7` tablet definitions, the kernel header `rohm-bd718x7.h`. Digits do not break a word-boundary match |
| `vulnerableDrivers#12` | 2 | Kernel header `arch/s390/include/asm/physmem_info.h` (two header versions) |
| `vulnerableDrivers#23` (the generic word "mapper") | 10 | `device-mapper.h`, `crush/mapper.h`, `g++-mapper-server` (GCC), and catalog icons of a map-drawing application |

What this means for the collectors:

- **Windows:** when the checker runs elevated, the files collector matches `cheatNames`
  against every file name in the master file table of every fixed drive. Those matches are
  indicators at the rule's severity, and the path allowlist does not suppress them. So a file like the `cheatNames#4`, `#10` or `#48`
  hits above would put a Windows player's check into `REVIEW_REQUIRED`: `#4` and `#10` are
  CRITICAL rules, `#48` is MEDIUM. The Windows equivalent of this baseline is unmeasured.
- **Linux:** the files collector walks only user-writable locations (`Downloads`, `Desktop`,
  `Documents`, `.local/share`, `.config` and `.steam` in each home folder, plus `/tmp`,
  `/var/tmp` and `/dev/shm`), so none of these system files would be reported.
- **Other lists:** `cleaners`, `macroTools` and `vulnerableDrivers` are matched against
  process names, drivers and execution traces, not against every file on disk. Their hits
  here show how generic some patterns are.

**Offset names in shared libraries.** 4000 shared libraries were scanned without the path
allowlist: the first 4000 in walk order, each under 48 MiB. None contained any of the 24
offset names. On this machine the heuristic had nothing to classify. That says nothing about
Windows PCs with Source-engine tools, which is the population where the section-5 trade-off
matters.

**Cheat-name rules that are dictionary words.** 13 of the 57 `cheatNames` rules are ordinary
English words (in `/usr/share/dict/words`): `#2 #7 #10 #13 #18 #19 #20 #23 #29 #30 #31 #48 #55`.
Three of them (`#7`, `#10`, `#23`) are substring rules, so they also match inside longer
words, as `#10` did above.

## 9. Known limitations and what is needed next

- **No real labelled data.** Real-world precision and recall per rule family need the corpus
  described in section 1. They should be reported with confidence intervals, and a consented
  baseline from Windows gaming PCs is needed alongside.
- **Synthetic positives encode the policy.** Sections 3 to 5 show that the implementation
  matches the stated policy. Their FP = 0 is not a false-positive rate in the field.
- **Name-rule precision.**
  - Section 8 shows substring name rules matching inside unrelated words (`cheatNames#4`,
    `#10`).
  - It also shows generic or very short patterns (`cheatNames#48`, `macroTools#1`,
    `cleaners#10`, `vulnerableDrivers#23`).
  - Candidate change: word-boundary matching for substring name rules that are dictionary
    words or occur inside common words. Measure against real Windows file-name lists before
    changing them.
- **Windows-only code is not exercised by this harness.** It runs on Linux, so the MFT, ADS,
  Authenticode and the registry are not covered. The parsers for Windows artefacts have their
  own unit tests in `src/test`:
  - `ParsersTest`: LNK, PE imports, Prefetch file names, Recycle Bin `$I`, ShellBags, USN
    journal records;
  - `PrefetchBodyTest` and `XpressTest`: compressed Prefetch bodies;
  - `AmCacheTest`, `UserAssistTest`, `ScheduledTaskTest`, `AlternateStreamsTest`;
  - `BrowserHistoryTest`: Chromium and Firefox history;
  - `VdfTest`: Steam login users;
  - `EntropyTest`.

  Kernel-component parsing is covered by `KernelReportTest` and `HiddenObjectsTest`. These
  tests check parsing against fixed inputs. They do not measure detection.
- **Ingestion fuzz scope.**
  - It covers the report endpoint. The claim and progress endpoints have unit tests only.
  - The tests run on SQLite. Postgres-specific rejections are not exercised; `clip()` removes
    the known cases (NUL, unpaired surrogates) before anything is stored.
- **Reproducibility.** Python's `random` guarantees the same `random()` sequence across
  versions, and `choice`/`shuffle`/`sample` have been stable in practice. A future
  interpreter could still change the fuzz corpus; the pinned class counts (117/177/6) would
  then fail and point at it.
