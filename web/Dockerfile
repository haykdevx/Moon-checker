FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
RUN groupadd --gid 10001 moon && useradd --uid 10001 --gid moon --create-home --shell /usr/sbin/nologin moon

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
# the source is read by the unprivileged "moon" user, whatever the permissions in the build context
RUN chmod -R a+rX /app \
    && DJANGO_SECRET_KEY=collectstatic-only python manage.py collectstatic --noinput -v0 \
    && mkdir -p /app/downloads && chown -R moon:moon /app/downloads

USER moon
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"
CMD ["sh", "-c", "python manage.py migrate --noinput && exec gunicorn moonpanel.wsgi:application --bind 0.0.0.0:8000 --workers 3 --threads 4 --timeout 180 --max-requests 2000 --max-requests-jitter 200 --access-logfile - --forwarded-allow-ips='*'"]
