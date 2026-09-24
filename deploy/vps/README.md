# VPS deployment

This application can run security tools and must only be used against systems
you own or are explicitly authorized to test. Do not publish the FastAPI port.

## Install

### One-command Kali/Debian/Ubuntu installation

From a cloned checkout:

```bash
cd omitest
sudo bash deploy/vps/install-linux.sh
```

The default `standard` Kali profile installs useful web/network scanners while
avoiding the largest packages. Choose based on VPS disk size:

```bash
sudo env OMITEST_TOOL_PROFILE=minimal bash deploy/vps/install-linux.sh  # 1 GB free
sudo env OMITEST_TOOL_PROFILE=standard bash deploy/vps/install-linux.sh # 3 GB free
sudo env OMITEST_TOOL_PROFILE=full bash deploy/vps/install-linux.sh     # 8+ GB free
```

The installer uses `https://github.com/kaungkhantko26/omitest.git` by default,
creates an unprivileged `omitest` account, installs Python and Nmap, builds the
virtual environment, preserves an existing `.env`, and enables automatic boot
startup. Override `REPO_URL`, `INSTALL_DIR`, or `SERVICE_USER` when required.

### Manual installation

On a dedicated Kali or Debian/Ubuntu VPS, create an unprivileged service user
and install the project under `/opt/omitest`:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip curl nmap
sudo useradd --system --create-home --shell /usr/sbin/nologin omitest
sudo git clone https://github.com/YOUR-ACCOUNT/YOUR-ENHANCED-FORK.git /opt/omitest
sudo chown -R omitest:omitest /opt/omitest
sudo -u omitest python3 -m venv /opt/omitest/venv
sudo -u omitest /opt/omitest/venv/bin/pip install -r /opt/omitest/requirements.txt
sudo -u omitest cp /opt/omitest/.env.example /opt/omitest/.env
```

For small VirtualBox disks, install without retaining pip's wheel cache:

```bash
python3 -m pip cache purge || true
sudo apt clean
sudo -u omitest /opt/omitest/venv/bin/pip install --no-cache-dir --prefer-binary \
  -r /opt/omitest/requirements.txt
```

On Kali, install the optional workflow tools you intend to authorize (package
availability differs on plain Debian/Ubuntu):

```bash
sudo apt install -y gobuster ffuf nikto hydra whatweb wafw00f sqlmap dnsrecon seclists metasploit-framework
```

Edit `/opt/omitest/.env`. At minimum, set a fresh API key, a long random
`API_AUTH_TOKEN`, the compatible provider values, and retain the loopback binds:

```env
AI_PROVIDER=compatible
COMPATIBLE_BASE_URL=https://globalblamp.vercel.app/v1
COMPATIBLE_API_KEY=gk-replace-with-a-fresh-secret
COMPATIBLE_MODEL=gpt-5.4
API_AUTH_TOKEN=replace-with-a-long-random-secret
BACKEND_HOST=127.0.0.1
FRONTEND_HOST=127.0.0.1
```

Install only the pentest binaries needed for your authorized workflow. Then
install and start the service:

```bash
cd /opt/omitest
sudo cp deploy/vps/omitest.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now omitest
sudo systemctl status omitest
```

## TLS and login protection

Replace `omitest.example.com` in `nginx-omitest.conf`, obtain a TLS
certificate, and create a strong basic-auth credential:

```bash
sudo apt install nginx apache2-utils certbot python3-certbot-nginx
sudo htpasswd -c /etc/nginx/.htpasswd-omitest operator
sudo cp deploy/vps/nginx-omitest.conf /etc/nginx/sites-available/omitest
sudo ln -s /etc/nginx/sites-available/omitest /etc/nginx/sites-enabled/omitest
sudo nginx -t
sudo systemctl reload nginx
```

Allow inbound SSH and HTTPS only. Keep ports 6000, 8501, and 3500 blocked by
the VPS firewall. For reverse shells, explicitly configure `EXPLOIT_LHOST` and
open only the callback port required for the active authorized engagement.

## Operate and troubleshoot

Restart the complete supervised stack after changing `.env` or installing an
update:

```bash
sudo systemctl restart omitest
sudo systemctl status omitest --no-pager
```

Follow logs and verify the public health endpoint locally:

```bash
sudo journalctl -u omitest -f
curl -fsS http://127.0.0.1:6000/health
```

Apply later updates with an automatic `.env`/database backup and health check:

```bash
sudo /opt/omitest/deploy/vps/update-linux.sh
```

The authenticated diagnostics endpoint reports database health and missing
required/optional tools. It never returns API credentials:

```bash
API_AUTH_TOKEN=$(/opt/omitest/venv/bin/python -c \
  'from dotenv import dotenv_values; print(dotenv_values("/opt/omitest/.env")["API_AUTH_TOKEN"])')
curl -fsS -H "X-API-Key: $API_AUTH_TOKEN" \
  "http://127.0.0.1:6000/api/diagnostics?refresh_tools=true"
unset API_AUTH_TOKEN
```
