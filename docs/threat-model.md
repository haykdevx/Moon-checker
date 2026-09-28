# Protocol Moon — threat model

Scope: the Windows/Linux checker, its optional kernel components, the Moon panel
(API, database, admin dashboard), distribution/update, and the build pipeline.
Status labels: **done** (implemented and tested), **partial**, **planned**.

## 1. What Protocol Moon is — and is not

Moon is a **one-time inspection**: a player runs the checker when an admin asks,
it collects artefacts present on the PC *now*, and the admin gets evidence plus a
rule-based outcome. It is **not continuous match protection**.

| | One-time inspection (Moon) | Continuous match protection (e.g. FACEIT AC) |
|---|---|---|
| Sees | Files, execution traces, persistence, registry, loaded drivers, running processes, logs that survived until the scan | Everything during play: process handles, injected code, input streams, gameplay statistics |
| Cannot reconstruct afterwards | A cheat that ran only during a match and left no artefact; external readers that exited; input automation; memory-only payloads | — |
| Trust anchor | The checker binary on the player's PC (bounded, see §3) | Boot-time driver + TPM attestation |
| Privacy cost | Only during a consented check | Always on while the game runs |

Every report therefore distinguishes *no evidence found* from *clean*, and states
its coverage and assurance.

## 2. Assets

Player personal data in reports (PC name, Windows user, Steam IDs, file paths);
admin accounts and sessions; the integrity of verdicts and decisions; check codes
and session tokens; the checker build and its update channel; signing keys (none
exist yet); the VPS and its other tenants.

## 3. Adversaries and limits

* **Cheating player (primary).** Controls their PC fully: can patch the checker, run
  it in a VM, replay a recording over screen share, clean artefacts first, or run a
  kernel/firmware/DMA cheat. **Limit:** a local inspection on a machine whose kernel,
  hypervisor or firmware the player controls cannot be trusted to see everything. Moon
  reports what it saw and how much to trust it; it never claims absence of cheating.
* **Malicious or careless admin.** Could misuse reports or decide unfairly →
  least-privilege roles, audit log, appeals, retention limits.
* **External attacker** against the panel or VPS.
* **Supply-chain attacker** against the build or update path.

## 4. Component threats

### 4.1 Checker (client)

| Threat | Mitigation | Status |
|---|---|---|
| Patched checker sends a fabricated clean report | Server recomputes the outcome from evidence + coverage; flags shrunk required-collector lists; build hash vs trusted list; identity/timing/IP consistency; replayed report ids | done |
| A patched checker lies *consistently* | Only attestation (§6) or obfuscation raises the cost; residual risk accepted and stated | residual |
| Collector crashes/times out and the scan still reads "clean" | Required collectors per platform; any not OK ⇒ `INCOMPLETE_SCAN`; errors recorded per collector | done |
| Security settings misread as cheating | `CONFIGURATION` kind lowers assurance, never the outcome | done |
| Correlated traces inflate confidence | Findings grouped by subject; no summed weights | done |
| Hostile file names / paths / window titles | Treated as data: never executed, never rendered as HTML (Swing labels escaped; panel auto-escapes); parsers bound sizes | done (see §4.3) |
| Resource exhaustion from huge disks/files | Per-module and overall time budgets; hash size cap; bounded parsers | done |
| Checker run in a VM / on a different PC | VM detection (configuration), PC/user identity bound at connect, live clock + verification code on screen | partial |
| Screen-share replay | Server clock, single-use code, session token, on-screen verification code must match the panel | done |

### 4.2 Kernel components

| Threat | Mitigation | Status |
|---|---|---|
| Unprivileged user talks to the driver | `IoCreateDeviceSecure` with SYSTEM+Administrators SDDL (verified on hardware, protocol 1) | done |
| General-purpose kernel primitive (read/write memory) | Single read-only IOCTL returning the module list; no input buffer is parsed | done |
| Truncated/partial report read as complete | Protocol 2 framing (count header, END trailer); checker turns incomplete framing into a collection error | done (driver: CI-compiled only) |
| Crafted names forge report lines | Driver sanitises bytes outside 0x20–0x7e; Linux module escapes task names | done |
| Claiming more than the kernel view gives | Documentation states manual-mapped drivers, hypervisor, firmware and DMA are invisible | done |
| Unsigned/test-signed driver shipped to players | Only attestation-signed builds may ship; CI test-signs with a throw-away cert; production needs EV cert + Microsoft attestation signing | planned (no credentials) |
| Persistence / always-on driver | Loaded on demand for a check, unloaded after; never boot-start | design (install tooling planned) |

Linux: the module (`/proc/moonmon`, 0440 root) is a lab prototype. An eBPF
alternative (read-only task/module views, CO-RE, no out-of-tree module to sign) is
preferable for distribution on Secure Boot systems where unsigned modules are refused;
see `docs/linux-collection.md`.

### 4.3 API and ingestion

| Threat | Mitigation | Status |
|---|---|---|
| Code guessing | 8-symbol codes (~10¹²), single use, expiry, per-IP failure throttle | done |
| Token theft / reuse | Random per-session token, stored hashed, valid only for its session and state | done |
| Oversized/zip-bomb uploads | Size caps before and after gunzip, JSON shape validation, finding cap | done |
| Malformed v2 reports | Section and field validation; reasons may only cite evidence in the report | done |
| Cross-session report injection | Upload bound to the token's session; report id replay flagged | done |
| Stored XSS via evidence strings | Django auto-escaping everywhere; no `|safe` on report data; strict CSP without inline scripts | done |
| Rate abuse | App-level counters + nginx `limit_req` on `/api/` and `/login/` | done |

### 4.4 Database and data protection

| Threat | Mitigation | Status |
|---|---|---|
| Data kept forever | Retention job deletes completed checks after N days (default 180) | done |
| Player cannot see or remove their data | Export and deletion request workflow | planned (§7) |
| DB exposed | Postgres not published; only reachable on the compose network | done |
| Backups leak data | No automatic backup of the panel yet; recommend encrypted off-host backup | planned |

### 4.5 Admin dashboard

| Threat | Mitigation | Status |
|---|---|---|
| Account takeover | Argon2, mandatory TOTP 2FA + recovery codes, lockout, session binding (epoch) | done |
| Privilege escalation | Rank-based policy: manage only lower ranks, grant only held permissions, last owner protected | done |
| Cross-admin report access | Queryset scoping by `checks.view_all`; object-level 404 | done |
| Unaccountable decisions | Every decision, override, export, deletion and role change audited | done |
| Unfair decision with no recourse | Appeals workflow | planned (§7) |
| CSRF / clickjacking | Django CSRF, `X-Frame-Options: DENY`, `frame-ancestors 'none'` | done |

### 4.6 Update and distribution

| Threat | Mitigation | Status |
|---|---|---|
| Tampered download | HTTPS; build hash registered as trusted at deploy; unknown builds flagged or blocked | done |
| Tampered rule update / downgrade | Signed rule manifests (Ed25519, key off the server), monotonic version with a floor | planned |
| Old vulnerable checker keeps working | `min_checker_version` enforced at connect | done |

### 4.7 Build pipeline

| Threat | Mitigation | Status |
|---|---|---|
| Unreviewed changes shipped | CI builds and tests every PR (currently blocked: GitHub Actions does not start for this repository) | blocked |
| Secrets in the repo | Secret scans before every commit in this work; `.env` and keys never committed | done |
| Dependency vulnerabilities | Dependabot reports exist for the repository — review pending | planned |

## 5. What a verdict can and cannot mean

* `VALIDATED_DETECTION`: an exact hash of a classified sample was found. It shows
  possession, not use or intent. An admin decides.
* `REVIEW_REQUIRED`: indicators exist. Every indicator class has legitimate lookalikes
  (`coverage.json`).
* `NO_EVIDENCE`: all required collectors ran with admin rights and nothing needs review.
  It covers only what those collectors can see (see blind spots per collector).
* `INCOMPLETE_SCAN` / `UNSUPPORTED_CONFIGURATION`: nothing can be concluded.

## 6. Attestation (design — not implemented)

Goal: let the panel verify *measurements* of the machine that produced a report,
without mistaking them for proof that no cheat exists.

1. **Trust anchors:** TPM 2.0 endorsement key certificate chains of TPM vendors;
   an attestation key (AK) created for Moon and certified against the EK.
2. **Freshness:** the panel issues a nonce with the session; the checker returns a TPM
   quote over PCRs 0–7 (firmware, Secure Boot policy, boot manager) and PCR 11/12/13
   as applicable, signed by the AK, including the nonce.
3. **Approved measurements:** the panel replays the TCG event log against the quoted
   PCRs and checks Secure Boot enabled, expected boot components, HVCI/VBS state from
   the Windows boot log.
4. **Binding:** the report hash is included in the quoted data, tying the report to
   the attested machine and session.
5. **Failure handling:** no TPM, unverifiable EK chain, stale nonce or policy mismatch ⇒
   assurance `LOW` with a stated reason; never a cheating verdict by itself.
6. **What it does not prove:** a clean boot chain does not show that no cheat runs
   after boot, that no DMA device is attached, or that the player's inputs are human.

## 7. Privacy

* **Consent:** the start screen states what is sent and to whom; pressing Start records
  consent (notice version + time) in the report; the panel flags reports without it.
* **Minimisation:** browser and shell history are matched on the PC and only matches
  leave it; file contents are hashed, not uploaded. Two collectors are broader than
  necessary and are flagged for reduction: USB storage history (lists every device)
  and the Steam VAC lookup (a network request per SteamID during the scan).
* **Access:** only the issuing admin and roles with `checks.view_all`.
* **Retention:** configurable, default 180 days; audit log retained.
* **Export and deletion:** planned player-facing request flow; today an admin can delete.
* **AI assistance:** not used. If added, report data must be passed as quoted data,
  never as instructions, and every AI conclusion must cite evidence ids.
