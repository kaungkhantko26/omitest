#!/usr/bin/env bash
set -Eeuo pipefail

# omitest installer for Kali, Debian, and Ubuntu.
# Override these when needed:
#   REPO_URL=https://github.com/you/fork.git INSTALL_DIR=/opt/omitest ./install-linux.sh
REPO_URL="${REPO_URL:-https://github.com/kaungkhantko26/omitest.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/omitest}"
SERVICE_USER="${SERVICE_USER:-omitest}"
TOOL_PROFILE="${OMITEST_TOOL_PROFILE:-standard}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root: sudo bash $0"
    exit 1
fi

case "$TOOL_PROFILE" in
    minimal|standard|full) ;;
    *) echo "OMITEST_TOOL_PROFILE must be minimal, standard, or full"; exit 1 ;;
esac

FREE_KB=$(df -Pk "${INSTALL_DIR%/*}" 2>/dev/null | awk 'NR == 2 {print $4}')
MIN_FREE_KB=1048576
[ "$TOOL_PROFILE" = "standard" ] && MIN_FREE_KB=3145728
[ "$TOOL_PROFILE" = "full" ] && MIN_FREE_KB=8388608
if [ -n "$FREE_KB" ] && [ "$FREE_KB" -lt "$MIN_FREE_KB" ]; then
    echo "Not enough free disk for the '$TOOL_PROFILE' profile."
    echo "Free: $((FREE_KB / 1024)) MB; recommended: $((MIN_FREE_KB / 1024)) MB."
    echo "Use OMITEST_TOOL_PROFILE=minimal or expand/clean the VPS disk."
    exit 1
fi

MEM_MB=$(awk '/MemTotal/ {print int($2 / 1024)}' /proc/meminfo)
if [ "$MEM_MB" -lt 1900 ]; then
    echo "Warning: ${MEM_MB} MB RAM detected. Add swap before long scans."
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "This installer supports Kali, Debian, and Ubuntu (apt-get required)."
    exit 1
fi

echo "[omitest] Installing base Linux dependencies..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git curl ca-certificates python3 python3-venv python3-pip python3-dev \
    build-essential libffi-dev libssl-dev nmap libcap2-bin

# Install only packages present in this distro's configured repositories. One
# renamed optional Kali package must never abort the whole deployment.
OPTIONAL_PACKAGES=()
if [ "$TOOL_PROFILE" = "standard" ] || [ "$TOOL_PROFILE" = "full" ]; then
    OPTIONAL_PACKAGES+=(gobuster ffuf nikto hydra whatweb wafw00f sqlmap dnsrecon smbclient enum4linux-ng)
fi
if [ "$TOOL_PROFILE" = "full" ]; then
    OPTIONAL_PACKAGES+=(seclists metasploit-framework exploitdb nuclei wpscan)
fi
AVAILABLE_PACKAGES=()
for package_name in "${OPTIONAL_PACKAGES[@]}"; do
    if apt-cache show "$package_name" >/dev/null 2>&1; then
        AVAILABLE_PACKAGES+=("$package_name")
    else
        echo "[omitest] Optional package unavailable, skipping: $package_name"
    fi
done
if [ "${#AVAILABLE_PACKAGES[@]}" -gt 0 ]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${AVAILABLE_PACKAGES[@]}"
fi

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
    --no-cache-dir --upgrade pip wheel
runuser -u "$SERVICE_USER" -- "$INSTALL_DIR/venv/bin/pip" install \
    --no-cache-dir --prefer-binary -r "$INSTALL_DIR/requirements.txt"

if [ ! -f "$INSTALL_DIR/.env" ]; then
    runuser -u "$SERVICE_USER" -- cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    chmod 600 "$INSTALL_DIR/.env"
fi

SERVICE_TMP=$(mktemp)
sed -e "s|User=omitest|User=$SERVICE_USER|" \
    -e "s|Group=omitest|Group=$SERVICE_USER|" \
    -e "s|/opt/omitest|$INSTALL_DIR|g" \
    "$INSTALL_DIR/deploy/vps/omitest.service" > "$SERVICE_TMP"
install -m 0644 "$SERVICE_TMP" /etc/systemd/system/omitest.service
rm -f "$SERVICE_TMP"
systemctl daemon-reload
systemctl enable --now omitest

echo
echo "omitest installed successfully."
echo "Configure AI:  sudo -u $SERVICE_USER nano $INSTALL_DIR/.env"
echo "Restart:       sudo systemctl restart omitest"
echo "Status:        sudo systemctl status omitest --no-pager"
echo "Logs:          sudo journalctl -u omitest -f"
echo "Diagnostics:   sudo $INSTALL_DIR/deploy/vps/update-linux.sh --health-only"
