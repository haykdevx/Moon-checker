# Moon Panel — results website for Moon Checker

The checker now reports to a web panel. Admins create a one-time **check code**
for a player. The player types it into the checker, and the verdict with all
evidence arrives live in that admin's panel.

Live instance: **https://moon.185.182.9.52.sslip.io** (VPS 185.182.9.52, `/opt/moon-panel`).

## How a check works

```
Admin (panel)                     Player PC (MoonCheck.exe)                 Panel server
─────────────                     ─────────────────────────                 ────────────
New check → code K7MQ-4X2P  ──►  sends code over Discord
                                  types code, presses Connect  ──────────►  POST /api/v1/claim
                                  sees "Admin: shadow • Player: Bob"  ◄───  session + secret token
                                  presses Start check
watches progress live      ◄────  heartbeat every 5 s  ──────────────────►  POST …/progress
                                  scan finishes, shows verdict + 🔒 code
verdict, evidence, trust   ◄────  gzip evidence JSON  ───────────────────►  POST …/report
signals, 🔒 code (must match)
records decision (Banned / Cleared / Review)
```

### Why a code, not just the admin's alias

The original idea was that the player types the admin's alias. That was replaced with a code because an alias alone:

* lets anyone who knows an alias flood that admin with fake "clean" reports;
* lets a player pick a friendlier admin by typing another alias;
* does not tie the upload to the player the admin is actually checking.

A code solves all three. It is random (32⁸ ≈ 10¹² combinations), single-use and
expires (30 min by default). Guessing is rate-limited per IP. The code belongs to
one admin and one named player. The checker still shows the admin's **alias**
after connecting, so the player knows who receives the results.

## Trust signals

The checker runs on the player's machine, so a report alone can never *prove* a
PC is clean. A modified checker could send a fake report. The server
cross-checks every report against things that are hard to fake all at once:

| Signal | Level |
|---|---|
| Checker file hash is in the trusted build list | ✓ / ✕ unknown build |
| Report came from the same binary / PC / Windows user that connected | ✕ if different |
| Ran as administrator | ✕ if not |
| All modules finished | ! if some errored / timed out |
| Scan duration measured by the **server** clock (too fast, or client claims longer than seen) | ! / ✕ |
| PC clock skew > 5 min | ! |
| Upload IP differs from connect IP | ! |
| Report id already submitted in another check (replay) | ✕ |
| Checker stopped heartbeating mid-scan | ! |
| Checker older than the minimum version | ! |

The **verification code** (🔒 `XXXX-XXXX-XX`) is computed by both sides from the
exact report bytes. If the code on the player's screen share differs from the
panel's, the report the admin is looking at is not the one on the screen.

## Roles

Accounts are invite-only. There is no public sign-up. Ranks decide who can manage whom:

* a member can only edit, disable or reset members ranked **below** them;
* a member can only assign roles below their own rank;
* a role editor can only grant permissions they hold themselves;
* the last active owner can never be demoted or disabled;
* changing a member's role or disabling them signs them out everywhere.

| Role (rank) | Can do |
|---|---|
| **Owner** (100) | everything, including settings, trusted builds and roles |
| **Head Admin** (80) | all checks, override decisions, delete, manage admins, audit log |
| **Admin** (50) | create checks, decide on own checks, export evidence |
| **Trainee** (20) | create checks; a senior records the decision |
| **Observer** (10) | read-only access to every check |

Owners can create custom roles from the permission list (Team → Roles).

## Account security

* Argon2 password hashing, minimum 10 characters, common-password check.
* **Mandatory TOTP 2FA** (Google Authenticator, Aegis, …) plus 10 one-time recovery codes. Codes cannot be replayed.
* Login lockout: 5 failures per IP+alias or 10 per alias in 15 min, plus 30 per IP per hour. nginx adds its own rate limit.
* "Sign out everywhere", password-reset links issued by a higher-ranked member, and a 2FA reset.
* Every security-relevant action is written to the **audit log**: logins, failures, role changes, decisions, deletions, exports and settings changes.
* Strict Content-Security-Policy (no inline scripts), HSTS, `X-Frame-Options: DENY`, and secure, HttpOnly, SameSite cookies.

## Operating the panel

| Task | Command |
|---|---|
| Deploy / update | `web/deploy/deploy.sh` (after `scripts/build-exe.sh` to publish a new checker) |
| Logs | `ssh moon-vps 'cd /opt/moon-panel && docker compose logs -f web worker'` |
| Config-only deploy | `MOON_SKIP_IMAGE=1 web/deploy/deploy.sh` |
| Recover owner access | `ssh moon-vps 'cd /opt/moon-panel && docker compose exec web python manage.py bootstrap_owner shadow --reset'` |
| Trust a build by hand | `… manage.py trust_build <sha256> --label "MoonCheck 1.1.0"` |
| DB backup | `ssh moon-vps 'cd /opt/moon-panel && docker compose exec -T db pg_dump -U moon moon' \| gzip > moon-$(date +%F).sql.gz` |
| Tests | `cd web && DJANGO_DEBUG=1 python manage.py test tests` |

Secrets live only in `/opt/moon-panel/.env` on the server (mode 600), which
is generated on the first deploy. The stack is three small containers: Postgres,
web (one gunicorn process, 8 threads, in-process cache) and a housekeeping
worker. Postgres is not published. Host nginx proxies straight to the web
container's fixed address `172.30.87.10:8000`, skipping Docker's userland proxy,
which is very slow on this busy host. `127.0.0.1:8710` also exists as a
local debugging fallback.

The deploy builds the image locally and ships it with `docker save | ssh docker load`,
because the VPS's connection to Docker Hub keeps timing out. Set `MOON_REMOTE_BUILD=1` to
build on the server instead, or `MOON_SKIP_IMAGE=1` for config-only deploys.

**Retention:** completed checks older than 180 days are deleted automatically.
Change this in Settings. Results contain personal data (PC name, Windows user,
Steam accounts), so do not keep them longer than you need.

### Checker side

* `MoonCheck.exe` asks for the code before a scan. Offline standalone use needs `MoonCheck.exe --offline`.
* Panel URL: bundled in `moon-client.properties`, overridable with a `moon.properties` file next to the exe (`server.url=…`) or `--server URL`. Only `https://` is accepted, except for localhost.
* Headless / scripted: `MoonCheck.exe --headless --code K7MQ-4X2P`. Exit code 5 means the results were not delivered.
* If the admin cancels the check in the panel, the running scan stops.
