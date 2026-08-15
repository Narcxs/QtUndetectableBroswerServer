#!/bin/bash
# deploy_staging.sh — déploie le serveur v3 en staging sur dev.cloudtrading.qtdashboard.fr
# N'affecte PAS la prod v2 (autre port, autre store, autre service).
# Usage (sur le VPS, dans le dossier du repo cloné) : sudo bash deploy_staging.sh
set -e

DOMAIN="dev.cloudtrading.qtdashboard.fr"
APP=/opt/antidetect-sync-dev
DATA=/var/lib/antidetect-sync-dev

echo "==> paquets"
apt-get install -y python3-venv >/dev/null

echo "==> dossiers"
mkdir -p "$APP" "$DATA/store"
cp v3/sync_server.py v3/requirements.txt "$APP/"

echo "==> venv + deps"
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt"

echo "==> env /etc/antidetect-sync-dev.env (mode comptes : pas de SYNC_TOKEN)"
cat > /etc/antidetect-sync-dev.env <<EOF
SYNC_HOST=127.0.0.1
SYNC_PORT=8899
SYNC_STORE=$DATA/store
SYNC_DB=$DATA/app.db
EOF
chmod 600 /etc/antidetect-sync-dev.env

echo "==> systemd"
cat > /etc/systemd/system/antidetect-sync-dev.service <<EOF
[Unit]
Description=Antidetect sync server v3 (staging)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP
EnvironmentFile=/etc/antidetect-sync-dev.env
ExecStart=$APP/venv/bin/python -u $APP/sync_server.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
chown -R root:root "$DATA" 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now antidetect-sync-dev
sleep 2
systemctl --no-pager --full status antidetect-sync-dev | head -5

echo "==> Caddy"
if ! grep -q "$DOMAIN" /etc/caddy/Caddyfile; then
cat >> /etc/caddy/Caddyfile <<EOF

$DOMAIN {
    reverse_proxy 127.0.0.1:8899
}
EOF
fi
systemctl reload caddy

echo "==> test local"
sleep 2
curl -s http://127.0.0.1:8899/health && echo
echo "TERMINE — teste ensuite : https://$DOMAIN/health"
