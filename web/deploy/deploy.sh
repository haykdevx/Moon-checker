#!/usr/bin/env bash
#
# Deploys / updates the Moon Panel on the VPS.
#
#   web/deploy/deploy.sh                 # uses ssh host alias "moon-vps"
#   MOON_DEPLOY_HOST=root@1.2.3.4 MOON_DOMAIN=panel.example.org web/deploy/deploy.sh
#
# Idempotent: generates secrets only on the first run, never touches other nginx
# sites, only (re)issues the certificate for MOON_DOMAIN. Checker builds placed in
# build/panel-downloads/ are uploaded and registered as trusted builds.
set -euo pipefail

HOST="${MOON_DEPLOY_HOST:-moon-vps}"
DOMAIN="${MOON_DOMAIN:-moon.185.182.9.52.sslip.io}"
PORT="${MOON_WEB_PORT:-8710}"
UPSTREAM="${MOON_UPSTREAM:-172.30.87.10:8000}"   # web container's fixed address (docker-compose.yml)
OWNER="${MOON_OWNER_ALIAS:-shadow}"
REMOTE=/opt/moon-panel
HERE="$(cd "$(dirname "$0")" && pwd)"
WEB="$(cd "$HERE/.." && pwd)"
DOWNLOADS="$(cd "$WEB/.." && pwd)/build/panel-downloads"

echo ">> syncing panel source to $HOST:$REMOTE"
ssh "$HOST" "mkdir -p $REMOTE/downloads && chmod 755 $REMOTE $REMOTE/downloads"
rsync -az --delete --no-owner --no-group \
  --exclude '.env' --exclude 'downloads/' --exclude '*.sqlite3' --exclude '__pycache__/' \
  --exclude 'staticfiles/' --exclude 'deploy/' \
  "$WEB/" "$HOST:$REMOTE/"
TRUST=""
if [ -d "$DOWNLOADS" ] && [ -n "$(ls -A "$DOWNLOADS" 2>/dev/null)" ]; then
  echo ">> uploading checker builds"
  rsync -az --delete --no-owner --no-group --chmod=F644,D755 "$DOWNLOADS/" "$HOST:$REMOTE/downloads/"
  # the checker reports the sha256 of the file it runs from: MoonCheck.exe inside the zip, or the jar
  for f in "$DOWNLOADS"/*; do
    case "$f" in
      *.jar) TRUST="$TRUST $(sha256sum "$f" | cut -d' ' -f1)|$(basename "$f")" ;;
      *.zip) TRUST="$TRUST $(unzip -p "$f" MoonCheck.exe | sha256sum | cut -d' ' -f1)|$(basename "$f" .zip)/MoonCheck.exe" ;;
    esac
  done
fi
scp -q "$HERE/nginx-moon-panel.conf" "$HERE/nginx-moon-panel-http.conf" "$HERE/nginx-moon-ratelimit.conf" "$HOST:$REMOTE/"

# Build here and ship the image: the VPS's link to Docker Hub is flaky.
# MOON_REMOTE_BUILD=1 builds on the server instead.
# MOON_SKIP_IMAGE=1 reuses the image already on the server (config-only deploys).
SHIPPED=0
if [ "${MOON_SKIP_IMAGE:-0}" = 1 ]; then
  echo ">> reusing the image already on the server"
  SHIPPED=1
elif [ "${MOON_REMOTE_BUILD:-0}" != 1 ] && command -v docker >/dev/null 2>&1; then
  echo ">> building image locally"
  docker build -q -t moon-panel:latest "$WEB" >/dev/null
  local_id="$(docker image inspect -f '{{.Id}}' moon-panel:latest)"
  remote_id="$(ssh "$HOST" "docker image inspect -f '{{.Id}}' moon-panel:latest 2>/dev/null" || true)"
  if [ "$local_id" != "$remote_id" ]; then
    echo ">> shipping image to $HOST"
    docker save moon-panel:latest | gzip -1 | ssh "$HOST" 'gunzip | docker load -q'
  else
    echo "   server already has this image"
  fi
  SHIPPED=1
fi

ssh "$HOST" DOMAIN="$DOMAIN" PORT="$PORT" UPSTREAM="$UPSTREAM" OWNER="$OWNER" REMOTE="$REMOTE" TRUST="'$TRUST'" SHIPPED="$SHIPPED" 'bash -s' <<'REMOTE_SCRIPT'
set -euo pipefail
cd "$REMOTE"

if [ ! -f .env ]; then
  echo ">> first deploy: generating secrets in $REMOTE/.env"
  umask 077
  cat > .env <<ENV
DJANGO_SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n/+=' | cut -c1-60)
DJANGO_ALLOWED_HOSTS=$DOMAIN,localhost,127.0.0.1
MOON_PUBLIC_URL=https://$DOMAIN
POSTGRES_DB=moon
POSTGRES_USER=moon
POSTGRES_PASSWORD=$(openssl rand -hex 24)
MOON_TIME_ZONE=Europe/Moscow
MOON_TRUST_X_REAL_IP=1
MOON_WEB_PORT=$PORT
ENV
fi
chmod 600 .env

echo ">> building and starting containers"
# plain docker build: compose's bake/buildx path is not available on every host
built=$SHIPPED
for attempt in 1 2 3; do
  [ "$built" = 1 ] && break
  if DOCKER_BUILDKIT=0 docker build -q -t moon-panel:latest . >/dev/null; then built=1; break; fi
  echo "   build attempt $attempt failed (registry/network?), retrying in 10 s"; sleep 10
done
[ "$built" = 1 ] || { echo "image build failed" >&2; exit 1; }
docker compose up -d --no-build --remove-orphans
for i in $(seq 1 120); do
  if curl -fsS -m 60 -H "Host: $DOMAIN" "http://$UPSTREAM/healthz" >/dev/null 2>&1; then echo "   web is healthy"; break; fi
  sleep 5
  [ "$i" = 120 ] && { docker compose logs --tail 80 web; echo "web did not become healthy" >&2; exit 1; }
done

echo ">> nginx site for $DOMAIN"
install -m 644 nginx-moon-ratelimit.conf /etc/nginx/conf.d/moon-panel-ratelimit.conf
mkdir -p /var/www/moon-panel-acme/.well-known/acme-challenge
CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
render_site() {
  sed -e "s/__DOMAIN__/$DOMAIN/g" -e "s/__UPSTREAM__/$UPSTREAM/g" "$1" > /etc/nginx/sites-available/moon-panel
  ln -sf /etc/nginx/sites-available/moon-panel /etc/nginx/sites-enabled/moon-panel
  if ! nginx -t; then
    echo "nginx rejected the moon-panel site; disabling it so the other sites keep working" >&2
    rm -f /etc/nginx/sites-enabled/moon-panel
    nginx -t && systemctl reload nginx
    exit 1
  fi
  systemctl reload nginx
}
if [ -f "$CERT" ]; then
  render_site nginx-moon-panel.conf
else
  render_site nginx-moon-panel-http.conf
  # wait until the reload is live and the challenge path is served (slow on a busy host)
  probe="probe-$$"; echo ok > "/var/www/moon-panel-acme/.well-known/acme-challenge/$probe"
  for i in $(seq 1 60); do
    [ "$(curl -s -m 20 -H "Host: $DOMAIN" "http://127.0.0.1/.well-known/acme-challenge/$probe")" = ok ] && break
    sleep 5
  done
  rm -f "/var/www/moon-panel-acme/.well-known/acme-challenge/$probe"
  echo ">> requesting TLS certificate"
  for attempt in 1 2 3; do
    certbot certonly --webroot -w /var/www/moon-panel-acme -d "$DOMAIN" --non-interactive --agree-tos \
      --keep-until-expiring --deploy-hook "systemctl reload nginx" && break
    echo "   certbot attempt $attempt failed, retrying in 30 s"; sleep 30
  done
  [ -f "$CERT" ] || { echo "could not obtain a certificate; the panel stays on plain HTTP" >&2; exit 1; }
  render_site nginx-moon-panel.conf
fi

echo ">> trusted checker builds"
for entry in $TRUST; do
  docker compose exec -T web python manage.py trust_build "${entry%%|*}" --label "${entry#*|}"
done

if [ "$(docker compose exec -T web python manage.py shell -v0 -c 'from accounts.models import User; print(User.objects.count())' | tail -1)" = "0" ]; then
  echo ">> creating the first owner account"
  docker compose exec -T web python manage.py bootstrap_owner "$OWNER"
fi
docker compose ps
echo ">> done: https://$DOMAIN"
REMOTE_SCRIPT
