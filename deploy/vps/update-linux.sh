#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/omitest}"
SERVICE_USER="${SERVICE_USER:-omitest}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/omitest}"
BACKEND_PORT=6000
if [ -x "$INSTALL_DIR/venv/bin/python" ] && [ -f "$INSTALL_DIR/.env" ]; then
    BACKEND_PORT=$("$INSTALL_DIR/venv/bin/python" -c \
        'from dotenv import dotenv_values; print(dotenv_values("'"$INSTALL_DIR"'/.env").get("BACKEND_PORT", "6000"))')
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash $0"
    exit 1
fi

health_check() {
    local attempt
    for attempt in $(seq 1 30); do
        curl -fsS --max-time 3 "http://127.0.0.1:${BACKEND_PORT}/health" >/dev/null && {
            echo "omitest health check passed."
            return 0
        }
        sleep 2
    done
    echo "omitest did not become healthy; recent logs follow."
    journalctl -u omitest -n 80 --no-pager
    return 1
}

if [ "${1:-}" = "--health-only" ]; then
    systemctl status omitest --no-pager
    health_check
    exit
fi

[ -d "$INSTALL_DIR/.git" ] || { echo "Not a Git checkout: $INSTALL_DIR"; exit 1; }
install -d -m 0700 "$BACKUP_ROOT"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="$BACKUP_ROOT/$STAMP"
install -d -m 0700 "$BACKUP_DIR"
for runtime_file in .env kmn_cyberseek.db; do
    [ -f "$INSTALL_DIR/$runtime_file" ] && cp -p "$INSTALL_DIR/$runtime_file" "$BACKUP_DIR/"
done

echo "[omitest] Updating source..."
git -C "$INSTALL_DIR" pull --ff-only
bash -n "$INSTALL_DIR/start.sh" "$INSTALL_DIR/deploy/vps/install-linux.sh"
runuser -u "$SERVICE_USER" -- "$INSTALL_DIR/venv/bin/pip" install \
    --no-cache-dir --prefer-binary -r "$INSTALL_DIR/requirements.txt"
runuser -u "$SERVICE_USER" -- "$INSTALL_DIR/venv/bin/python" -m py_compile \
    "$INSTALL_DIR/main.py" "$INSTALL_DIR/frontend.py" "$INSTALL_DIR/docs_server.py"

SERVICE_TMP=$(mktemp)
sed -e "s|User=omitest|User=$SERVICE_USER|" \
    -e "s|Group=omitest|Group=$SERVICE_USER|" \
    -e "s|/opt/omitest|$INSTALL_DIR|g" \
    "$INSTALL_DIR/deploy/vps/omitest.service" > "$SERVICE_TMP"
install -m 0644 "$SERVICE_TMP" /etc/systemd/system/omitest.service
rm -f "$SERVICE_TMP"
systemctl daemon-reload
systemctl restart omitest
health_check
echo "Update complete. Runtime backup: $BACKUP_DIR"
