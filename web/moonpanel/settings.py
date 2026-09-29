"""
Moon Panel settings.

Everything deployment-specific comes from environment variables (see
``.env.example``). With ``DJANGO_DEBUG=1`` and no database variables the panel
runs on SQLite + in-memory cache, which is what the test-suite uses.
"""
import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def env(name, default=None):
    value = os.environ.get(name)
    return default if value is None or value == "" else value


def env_bool(name, default=False):
    return str(env(name, "1" if default else "0")).lower() in ("1", "true", "yes", "on")


def env_int(name, default):
    return int(env(name, str(default)))


DEBUG = env_bool("DJANGO_DEBUG")
SECRET_KEY = env("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set in production")
    SECRET_KEY = "dev-only-insecure-key-do-not-use-in-production"

PUBLIC_URL = env("MOON_PUBLIC_URL", "http://localhost:8000").rstrip("/")
ALLOWED_HOSTS = [h.strip() for h in env("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()]
CSRF_TRUSTED_ORIGINS = [PUBLIC_URL] if PUBLIC_URL.startswith("https://") else []

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
    "accounts",
    "checks",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "core.middleware.RealIpMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "core.middleware.LanguageMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "accounts.middleware.AccountGateMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "core.middleware.SecurityHeadersMiddleware",
]

ROOT_URLCONF = "moonpanel.urls"
WSGI_APPLICATION = "moonpanel.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.template.context_processors.i18n",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "core.context.panel",
            ],
        },
    },
]

if env("POSTGRES_DB"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": env("POSTGRES_DB"),
            "USER": env("POSTGRES_USER"),
            "PASSWORD": env("POSTGRES_PASSWORD"),
            "HOST": env("POSTGRES_HOST", "db"),
            "PORT": env("POSTGRES_PORT", "5432"),
            "CONN_MAX_AGE": 60,
            "CONN_HEALTH_CHECKS": True,
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": env("SQLITE_PATH", str(BASE_DIR / "dev.sqlite3")),
            # SQLite has no row locks: take the write lock when a transaction starts, so a
            # check-then-write block (last-owner protection) cannot interleave with another
            "OPTIONS": {"transaction_mode": "IMMEDIATE"},
        }
    }

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

if env("REDIS_URL"):
    CACHES = {"default": {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": env("REDIS_URL")}}
else:
    CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

# --- authentication -------------------------------------------------------
AUTH_USER_MODEL = "accounts.User"
LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "checks:dashboard"
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# --- sessions / cookies / transport ---------------------------------------
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_NAME = "moon_session"
SESSION_COOKIE_AGE = env_int("MOON_SESSION_HOURS", 12) * 3600
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_NAME = "moon_csrf"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_FAILURE_VIEW = "core.views.csrf_failure"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SECURE_HSTS_SECONDS = 0 if DEBUG else 31536000
X_FRAME_OPTIONS = "DENY"
# nginx is the only thing that can reach gunicorn (bound to 127.0.0.1); trust its X-Real-IP.
MOON_TRUST_X_REAL_IP = env_bool("MOON_TRUST_X_REAL_IP", not DEBUG)

# --- i18n / time ----------------------------------------------------------
# Russian by default (the server's admins); English through the switch in the header.
LANGUAGE_CODE = "ru"
LANGUAGES = [("ru", "Русский"), ("en", "English")]
LOCALE_PATHS = [BASE_DIR / "locale"]
LANGUAGE_COOKIE_NAME = "moon_lang"
TIME_ZONE = env("MOON_TIME_ZONE", "Europe/Moscow")
USE_I18N = True
USE_TZ = True

# --- static ---------------------------------------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"
        if DEBUG else "whitenoise.storage.CompressedManifestStaticFilesStorage"
    },
}

MESSAGE_STORAGE = "django.contrib.messages.storage.session.SessionStorage"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "plain"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {"django.security": {"handlers": ["console"], "level": "WARNING", "propagate": False}},
}

# --- Moon specific ----------------------------------------------------------
# Same key the checker embeds (core/Integrity.java). It is NOT a secret against a
# determined attacker; the server uses it only to reproduce the on-screen
# verification code so the admin can match the website to the live screen share.
MOON_VERIFICATION_KEY = env("MOON_VERIFICATION_KEY", "moon-cs2-2026::integrity::v1")
MOON_MAX_UPLOAD_BYTES = env_int("MOON_MAX_UPLOAD_BYTES", 16 * 1024 * 1024)      # on the wire (gzip)
MOON_MAX_REPORT_BYTES = env_int("MOON_MAX_REPORT_BYTES", 48 * 1024 * 1024)      # after gunzip
# a claimed check must deliver its report within this window; later uploads are refused
MOON_UPLOAD_WINDOW_MINUTES = env_int("MOON_UPLOAD_WINDOW_MINUTES", 180)
# audit events older than this are deleted by the worker (player details are removed earlier,
# with the check they belong to)
MOON_AUDIT_RETENTION_DAYS = env_int("MOON_AUDIT_RETENTION_DAYS", 730)
# the upload protocol this panel speaks: 3 = report bound to the session by a single-use value
MOON_UPLOAD_PROTOCOL = 3
MOON_MAX_FINDINGS = env_int("MOON_MAX_FINDINGS", 25000)
MOON_DOWNLOAD_DIR = Path(env("MOON_DOWNLOAD_DIR", str(BASE_DIR / "downloads")))
MOON_DOWNLOAD_URL = env("MOON_DOWNLOAD_URL", "/download/")
