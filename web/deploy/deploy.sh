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
DOMAIN="${MOON_DOMAIN:-cs2-moon.com}"                        # the panel's public address
ALIASES="${MOON_DOMAIN_ALIASES:-www.cs2-moon.com}"           # redirect to DOMAIN (same certificate)
EXTRA="${MOON_EXTRA_DOMAINS:-moon.185.182.9.52.sslip.io}"    # also served: checkers built before the move point here
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

ssh "$HOST" DOMAIN="$DOMAIN" ALIASES="'$ALIASES'" EXTRA="'$EXTRA'" PORT="$PORT" UPSTREAM="$UPSTREAM" OWNER="$OWNER" REMOTE="$REMOTE" TRUST="'$TRUST'" SHIPPED="$SHIPPED" 'bash -s' <<'REMOTE_SCRIPT'
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
# every served name is an allowed host; the public URL (player links, download page) is DOMAIN
ALL_HOSTS="$(echo "$DOMAIN $ALIASES $EXTRA localhost 127.0.0.1" | xargs | tr ' ' ',')"
sed -i -e "s|^DJANGO_ALLOWED_HOSTS=.*|DJANGO_ALLOWED_HOSTS=$ALL_HOSTS|" .env

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
  if curl -fsS -m 60 -H "Host: localhost" "http://$UPSTREAM/healthz" >/dev/null 2>&1; then echo "   web is healthy"; break; fi
  sleep 5
  [ "$i" = 120 ] && { docker compose logs --tail 80 web; echo "web did not become healthy" >&2; exit 1; }
done

echo ">> nginx sites"
install -m 644 nginx-moon-ratelimit.conf /etc/nginx/conf.d/moon-panel-ratelimit.conf
mkdir -p /var/www/moon-panel-acme/.well-known/acme-challenge
SERVER_IP="$(curl -4 -s -m 10 https://api.ipify.org || hostname -I | awk '{print $1}')"

# one site file per served name: moon-panel-<name>; aliases redirect to their main name
render_site() {   # template name aliases
  local file="/etc/nginx/sites-available/moon-panel-$2"
  sed -e "s/__DOMAIN__/$2/g" -e "s/__UPSTREAM__/$UPSTREAM/g" "$1" > "$file"
  if [ -n "$3" ] && [ "$1" = nginx-moon-panel.conf ]; then
    cat >> "$file" <<SITE

# aliases of $2: one canonical address
server {
    listen 80;
    listen [::]:80;
    server_name $3;
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ { root /var/www/moon-panel-acme; default_type text/plain; }
    location / { return 301 https://$2\$request_uri; }
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name $3;
    server_tokens off;
    ssl_certificate /etc/letsencrypt/live/$2/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$2/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    return 301 https://$2\$request_uri;
}
SITE
  elif [ -n "$3" ]; then
    sed -i "s/server_name $2;/server_name $2 $3;/" "$file"
  fi
  ln -sf "$file" "/etc/nginx/sites-enabled/moon-panel-$2"
  rm -f /etc/nginx/sites-enabled/moon-panel   # the single-site layout before multi-domain
  if ! nginx -t; then
    echo "nginx rejected moon-panel-$2; disabling it so the other sites keep working" >&2
    rm -f "/etc/nginx/sites-enabled/moon-panel-$2"
    nginx -t && systemctl reload nginx
    return 1
  fi
  systemctl reload nginx
}

points_here() {   # every name resolves to this server
  for n in "$@"; do
    [ "$(getent ahostsv4 "$n" | awk '{print $1; exit}')" = "$SERVER_IP" ] || return 1
  done
}

serve() {   # name aliases
  local name="$1" aliases="$2" cert="/etc/letsencrypt/live/$1/fullchain.pem"
  if [ -f "$cert" ] && { [ -z "$aliases" ] || openssl x509 -in "$cert" -noout -text | grep -q "DNS:${aliases%% *}"; }; then
    render_site nginx-moon-panel.conf "$name" "$aliases"
    echo "   https://$name served"
    return 0
  fi
  if ! points_here $name $aliases; then
    echo "   $name $aliases: DNS does not point at $SERVER_IP yet — skipped (re-run deploy once it does)"
    return 0
  fi
  render_site nginx-moon-panel-http.conf "$name" "$aliases" || return 0
  probe="probe-$$"; echo ok > "/var/www/moon-panel-acme/.well-known/acme-challenge/$probe"
  for i in $(seq 1 60); do
    [ "$(curl -s -m 20 -H "Host: $name" "http://127.0.0.1/.well-known/acme-challenge/$probe")" = ok ] && break
    sleep 5
  done
  rm -f "/var/www/moon-panel-acme/.well-known/acme-challenge/$probe"
  echo ">> requesting TLS certificate for $name $aliases"
  local d="-d $name"
  for a in $aliases; do d="$d -d $a"; done
  for attempt in 1 2 3; do
    certbot certonly --webroot -w /var/www/moon-panel-acme $d --cert-name "$name" --expand --non-interactive \
      --agree-tos --keep-until-expiring --deploy-hook "systemctl reload nginx" && break
    echo "   certbot attempt $attempt failed, retrying in 30 s"; sleep 30
  done
  [ -f "$cert" ] || { echo "could not obtain a certificate for $name; it stays on plain HTTP" >&2; return 0; }
  render_site nginx-moon-panel.conf "$name" "$aliases"
  echo "   https://$name served"
}

for extra in $EXTRA; do serve "$extra" ""; done
serve "$DOMAIN" "$ALIASES"

# the public address (player links, download page) moves to DOMAIN only once it serves HTTPS
PUBLIC="$DOMAIN"
[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ] || PUBLIC="$(echo $EXTRA | awk '{print $1}')"
if ! grep -qx "MOON_PUBLIC_URL=https://$PUBLIC" .env; then
  sed -i "s|^MOON_PUBLIC_URL=.*|MOON_PUBLIC_URL=https://$PUBLIC|" .env
  docker compose up -d --no-build
  for i in $(seq 1 60); do
    curl -fsS -m 30 -H "Host: $PUBLIC" "http://$UPSTREAM/healthz" >/dev/null 2>&1 && break
    sleep 5
  done
fi
echo "   public address: https://$PUBLIC"

echo ">> trusted checker builds"
for entry in $TRUST; do
  docker compose exec -T web python manage.py trust_build "${entry%%|*}" --label "${entry#*|}"
done

if [ "$(docker compose exec -T web python manage.py shell -v0 -c 'from accounts.models import User; print(User.objects.count())' | tail -1)" = "0" ]; then
  echo ">> creating the first owner account"
  docker compose exec -T web python manage.py bootstrap_owner "$OWNER"
fi
docker compose ps
echo ">> done"
REMOTE_SCRIPT
