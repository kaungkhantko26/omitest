#!/usr/bin/env bash
set -Eeuo pipefail

# omitest installer for Kali, Debian, and Ubuntu.
# Override these when needed:
#   REPO_URL=https://github.com/you/fork.git INSTALL_DIR=/opt/omitest ./install-linux.sh
REPO_URL="${REPO_URL:-https://github.com/kaungkhantko26/omitest.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/omitest}"
SERVICE_USER="${SERVICE_USER:-omitest}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root: sudo bash $0"
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "This installer supports Kali, Debian, and Ubuntu (apt-get required)."
    exit 1
fi

echo "[omitest] Installing base Linux dependencies..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git curl ca-certificates python3 python3-venv python3-pip nmap libcap2-bin

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "[omitest] Updating existing checkout (fast-forward only)..."
    git -C "$INSTALL_DIR" pull --ff-only
elif [ -e "$INSTALL_DIR" ]; then
    echo "Refusing to overwrite existing non-Git path: $INSTALL_DIR"
    exit 1
else
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
    runuser -u "$SERVICE_USER" -- python3 -m venv "$INSTALL_DIR/venv"
fi
runuser -u "$SERVICE_USER" -- "$INSTALL_DIR/venv/bin/pip" install \
    --upgrade pip wheel
runuser -u "$SERVICE_USER" -- "$INSTALL_DIR/venv/bin/pip" install \
    -r "$INSTALL_DIR/requirements.txt"

if [ ! -f "$INSTALL_DIR/.env" ]; then
    runuser -u "$SERVICE_USER" -- cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    chmod 600 "$INSTALL_DIR/.env"
fi

install -m 0644 "$INSTALL_DIR/deploy/vps/omitest.service" /etc/systemd/system/omitest.service
systemctl daemon-reload
systemctl enable --now omitest

echo
echo "omitest installed successfully."
echo "Configure AI:  sudo -u $SERVICE_USER nano $INSTALL_DIR/.env"
echo "Restart:       sudo systemctl restart omitest"
echo "Status:        sudo systemctl status omitest --no-pager"
echo "Logs:          sudo journalctl -u omitest -f"
