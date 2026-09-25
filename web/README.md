# Moon Panel

Results website for Moon Checker. It provides check codes, a live progress view,
verdicts, evidence and trust signals, role-based team management with mandatory
2FA, and an audit log.

Full documentation: [`../docs/moon-panel.md`](../docs/moon-panel.md).

```bash
# local development (SQLite, no Docker)
python -m venv .venv && .venv/bin/pip install -r requirements.txt
export DJANGO_DEBUG=1
.venv/bin/python manage.py migrate
.venv/bin/python manage.py bootstrap_owner yourname   # prints a one-time password
.venv/bin/python manage.py runserver

# tests
DJANGO_DEBUG=1 .venv/bin/python manage.py test tests

# production
deploy/deploy.sh          # docker compose stack behind host nginx + Let's Encrypt
```
