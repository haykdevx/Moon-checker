# Moon Checker + Moon Panel

A CS2 PC-inspection tool for the MOON server (cs2-moon.ru).

- **Moon Checker** — a program the player runs on their own PC (Windows 10/11, Linux). It
  looks for traces of cheats and sends a signed evidence report.
- **Moon Panel** — the admins' website. It creates check codes, shows the check live, stores
  reports, and keeps decisions, appeals and statistics.

A check is an inspection, not proof. "No evidence reported" does not mean "clean PC", and a
finding asks an admin to look; it is not a verdict. What each part can and cannot establish
is written down in `docs/` (see the list at the end).

## Technical stack

| Part | Technology |
|---|---|
| Checker | Java 21, Swing + FlatLaf (window), JNA (Windows / Linux system calls), Jackson (JSON), SQLite JDBC (browser history), Maven |
| Windows package | launch4j `.exe` + bundled Eclipse Temurin 21 runtime (pinned, checksum-verified), reproducible build |
| Optional kernel parts | C: Windows WDM driver (`kernel/windows`), Linux module (`kernel/linux`) — not shipped to players |
| Panel | Python 3.13, Django 5.2, gunicorn, whitenoise, argon2 passwords, TOTP 2FA (segno for QR codes) |
| Database | PostgreSQL 17 (production), SQLite (development and tests) |
| Hosting | Docker Compose (db, web, worker) behind host nginx, Let's Encrypt certificates |
| Languages | Russian by default, English (both the checker and the panel) |

Repository layout: `src/` checker, `web/` panel, `kernel/` optional drivers, `scripts/` build,
signing and Windows test scripts, `docs/` documentation, `spec/` shared outcome rules.

## How it is used

**Admin**
1. Sign in to the panel (two-factor authentication is required for everyone).
2. **New check** → enter the player's name → the panel shows a code like `ABCD-EFGH` and a
   ready message with the download link.
3. Send the message to the player and watch over screen share. The check page updates by
   itself while the player's PC is scanned.
4. Open the result:
   - the outcome, recomputed by the panel from the evidence;
   - the findings;
   - which parts ran;
   - "About this report": what the panel checked itself and what the player's PC only claims.
5. Record a decision (clean / ban / second look / re-check). The player can see it and can
   appeal; a different admin handles appeals.

**Player**
1. Download `MoonCheck-<version>-win64.zip` from the panel's download page and unzip it.
2. Right-click `MoonCheck.exe` → *Run as administrator*.
3. Enter the admin's code, check that the admin's nickname is shown, press *Start check*.
4. Keep the window open until it says the results were delivered. The verification code on
   screen must match the one on the admin's page.

Removing it: delete the folder. Only logs stay, in `%LOCALAPPDATA%\MoonCheck`; they are
deleted after 14 days, or at once with `MoonCheck.exe --forget`. Nothing is installed.

## Build and test

```bash
# checker: tests (Docker, no local Maven needed)
docker run --rm -u $(id -u):$(id -g) -v "$PWD":/src -v "$HOME/.m2":/var/maven/.m2 -w /src \
  maven:3.9-eclipse-temurin-21 mvn -Duser.home=/var/maven -Dmaven.repo.local=/var/maven/.m2/repository -B test

# checker: Windows package -> build/MoonCheck-<version>-win64.zip (+ jar in build/panel-downloads)
bash scripts/build-exe.sh

# checker: headless use
java -jar target/moon-checker.jar --cli --offline --out reports       # scan, save the report
java -jar target/moon-checker.jar --cli --server https://panel --code ABCD-EFGH
java -jar target/moon-checker.jar --selftest | --version | --forget | --help
java -jar target/moon-checker.jar --evaluate-benign <folder>           # false-positive measurement

# panel: development
cd web
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
export DJANGO_DEBUG=1
.venv/bin/python manage.py migrate
.venv/bin/python manage.py bootstrap_owner <alias>      # prints a one-time password
.venv/bin/python manage.py runserver

# panel: tests (SQLite; set POSTGRES_* to run them against PostgreSQL too)
DJANGO_DEBUG=1 .venv/bin/python manage.py test

# panel: translations (extract, merge, compile; --check fails if anything is untranslated)
.venv/bin/python manage.py moon_i18n
```

On Windows, `scripts/windows-smoke.ps1` (run from the unpacked package as administrator)
plants harmless test files and checks that the checker reports what it must and ignores
what it must.

## Deploy the panel

```bash
bash web/deploy/deploy.sh   # ssh host alias "moon-vps"; builds the image locally and ships it
```

What `deploy.sh` does:
- syncs `web/` to `/opt/moon-panel`;
- generates secrets on the first run;
- starts the Docker Compose stack;
- configures nginx and Let's Encrypt;
- publishes the checker builds found in `build/panel-downloads/` and registers their hashes as official builds.

Back up the database first:
`docker compose exec -T db pg_dump -U moon moon | gzip > /root/moon-panel-backups/<date>.sql.gz`.

Upload protocol 3 (checker 1.3.0 and newer) binds each report to its check. Older checkers are
refused unless *Settings → Accept checkers older than 1.3* is turned on for a transition.

## Detection rules

The rules live in `src/main/resources/signatures.json`:
- cheat and tool names;
- cheat sites;
- CS2 offset names;
- vulnerable drivers;
- cleaners;
- macro tools;
- trusted certificate roots.

Every rule states its class, review status and source. An update placed next to the checker
is used only when it is signed with `scripts/sign-rules.py` and is not older than the built-in
rules. See `docs/rules-pipeline.md`.

## Documentation

| File | What it covers |
|---|---|
| `docs/report-assurance.md` | what the panel can and cannot verify about a report |
| `docs/validation.md` | measurements: fixtures, fuzzing, benign-file false-positive rates |
| `docs/rules-pipeline.md` | rule classes, provenance, signed updates, how detection would be evaluated |
| `docs/kernel.md` | the optional kernel parts, their limits and release blockers |
| `docs/windows-readiness.md` | Windows 11 test results and the test plan for a real PC |
| `docs/linux-collection.md` | Linux collectors and the support matrix |
| `docs/threat-model.md` | who attacks what |
| `docs/coverage-matrix.md` | every collector and rule |
| `docs/moon-panel.md` | panel roles, settings, operations |
| `docs/release-evidence.md` | release evidence and open blockers |
| `docs/hardening-record.md` | the security review, each finding with its fix and test |

Known limits:
- Real-cheat detection accuracy has not been measured (no labelled samples).
- `MoonCheck.exe` is not code-signed yet.
- The kernel parts are not production-signed.
