#!/bin/bash

# omitest Startup Script
# Starts both FastAPI backend and Streamlit frontend

echo "🚀 Starting omitest - AI-Driven Autonomous Red Team Operator"
echo "================================================================"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

# Check if required packages are installed
echo "📦 Checking dependencies..."
if [ ! -f "requirements.txt" ]; then
    echo "❌ requirements.txt not found!"
    exit 1
fi

# Pip caches built wheels under ~/.cache by default, which is especially easy
# to exhaust on small Kali VirtualBox disks. Report capacity up front and use
# no-cache installation below so each package is stored only in the venv.
_FREE_KB=$(df -Pk . 2>/dev/null | awk 'NR == 2 {print $4}')
if [ -n "$_FREE_KB" ] && [ "$_FREE_KB" -lt 524288 ] 2>/dev/null; then
    echo "⚠️  Low disk space: $((_FREE_KB / 1024)) MB free. At least 512 MB is recommended."
    echo "   Kali cleanup: python3 -m pip cache purge; sudo apt clean; sudo apt autoremove"
fi

# Check if virtual environment exists, create if not
if [ ! -d "venv" ]; then
    echo "🔧 Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "❌ Failed to create virtual environment"
        exit 1
    fi
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install requirements if not already installed
if [ "${SKIP_DEPENDENCY_INSTALL:-false}" != "true" ]; then
    echo "📦 Installing dependencies without a persistent pip cache..."
    python -m pip install --no-cache-dir --prefer-binary -r requirements.txt --quiet
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install dependencies"
        df -h . 2>/dev/null || true
        echo "   If the disk is full, run: python3 -m pip cache purge && sudo apt clean"
        exit 1
    fi
fi

# Check if Nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "⚠️  Warning: Nmap is not installed. Some features may not work."
    echo "   Install with: brew install nmap (macOS) or apt install nmap (Ubuntu)"
fi

# Check key pentest tools — the AI wastes turns retrying tools that aren't present
# (e.g. it kept trying sshpass on a host without it). Warn, and on Debian/Kali
# offer to apt-install the missing ones.
_MISSING_TOOLS=""
for _t in sshpass gobuster ffuf nikto hydra whatweb wafw00f sqlmap dnsrecon; do
    command -v "$_t" &> /dev/null || _MISSING_TOOLS="$_MISSING_TOOLS $_t"
done
if [ ! -d /usr/share/seclists ] && [ ! -d /usr/share/wordlists/seclists ]; then
    _MISSING_TOOLS="$_MISSING_TOOLS seclists"
fi
if [ -n "$_MISSING_TOOLS" ] && [ "${SKIP_TOOL_INSTALL:-false}" != "true" ]; then
    echo "⚠️  Missing pentest tools:$_MISSING_TOOLS"
    if command -v apt-get &> /dev/null; then
        if [ "$(id -u)" -eq 0 ]; then
            echo "   Attempting install (apt-get install ...)."
            apt-get install -y $_MISSING_TOOLS 2>/dev/null || \
                echo "   Install skipped/failed — the AI will avoid these tools and use alternatives."
        elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
            echo "   Attempting install with passwordless sudo."
            sudo -n apt-get install -y $_MISSING_TOOLS 2>/dev/null || \
                echo "   Install skipped/failed — the AI will avoid these tools and use alternatives."
        else
            echo "   Automatic install skipped (no non-interactive root access)."
            echo "   Install later as root: apt-get install -y$_MISSING_TOOLS"
        fi
    else
        echo "   Install them for best results (Kali: sudo apt install$_MISSING_TOOLS)."
    fi
fi

echo "ℹ️  AI is optional at startup — configure it from Settings in the web UI."

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "🔧 Creating .env file..."
    cp .env.example .env 2>/dev/null || touch .env
    echo "⚠️  .env created. You can configure AI settings directly from the Web UI."
fi

# ── Port helpers ─────────────────────────────────────────────────────────────

_port_in_use() {
    if command -v ss &>/dev/null; then
        ss -tlnp | grep -q ":$1 "
    elif command -v lsof &>/dev/null; then
        lsof -Pi :"$1" -sTCP:LISTEN -t >/dev/null 2>&1
    else
        return 1
    fi
}

# Find the first free port at or above $1.
_find_free_port() {
    local port=$1
    while [ "$port" -le 65535 ] && _port_in_use "$port" 2>/dev/null; do
        port=$((port + 1))
    done
    [ "$port" -le 65535 ] || return 1
    echo "$port"
}

_valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null
}

_resolve_port() {
    local name=$1 requested=$2 fallback=$3 candidate tries=0
    if ! _valid_port "$requested"; then
        echo "⚠️  ${name}=${requested:-unset} is invalid; using ${fallback}" >&2
        requested=$fallback
    fi
    candidate=$requested
    while _port_in_use "$candidate" 2>/dev/null \
          || [ "$candidate" = "${BACKEND_PORT_RESOLVED:-}" ] \
          || [ "$candidate" = "${FRONTEND_PORT_RESOLVED:-}" ]; do
        candidate=$((candidate + 1))
        [ "$candidate" -le 65535 ] || candidate=1
        tries=$((tries + 1))
        if [ "$tries" -ge 65535 ]; then
            echo "❌ No free TCP port available for ${name}" >&2
            return 1
        fi
    done
    echo "$candidate"
}

# Update or append KEY=VALUE in .env (removes duplicate lines first).
_set_env_val() {
    local key=$1 val=$2 env_tmp
    env_tmp=$(mktemp "${TMPDIR:-/tmp}/omitest-env.XXXXXX") || return 1
    awk -v wanted="$key" 'index($0, wanted "=") != 1 { print }' .env > "$env_tmp"
    echo "${key}=${val}" >> "$env_tmp"
    mv "$env_tmp" .env
}

# ── Read preferred ports from .env ───────────────────────────────────────────

BACKEND_PORT="${BACKEND_PORT:-$(grep -m1 "^BACKEND_PORT=" .env 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')}"
BACKEND_PORT="${BACKEND_PORT:-6000}"
FRONTEND_PORT="${FRONTEND_PORT:-$(grep -m1 "^FRONTEND_PORT=" .env 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')}"
FRONTEND_PORT="${FRONTEND_PORT:-8501}"
FRONTEND_HOST="${FRONTEND_HOST:-$(grep -m1 "^FRONTEND_HOST=" .env 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')}"
FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"
DOCS_PORT="${DOCS_PORT:-$(grep -m1 "^DOCS_PORT=" .env 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')}"
DOCS_PORT="${DOCS_PORT:-3500}"

# ── Resolve free ports (auto-switch if system service holds preferred port) ──

echo "🔍 Checking port availability..."
BACKEND_PORT_RESOLVED=$(_resolve_port BACKEND_PORT "$BACKEND_PORT" 6000) || exit 1
BACKEND_PORT=$BACKEND_PORT_RESOLVED
FRONTEND_PORT_RESOLVED=$(_resolve_port FRONTEND_PORT "$FRONTEND_PORT" 8501) || exit 1
FRONTEND_PORT=$FRONTEND_PORT_RESOLVED
DOCS_PORT=$(_resolve_port DOCS_PORT "$DOCS_PORT" 3500) || exit 1

if [ "${OMITEST_PERSIST_PORTS:-true}" = "true" ]; then
    _set_env_val "BACKEND_PORT" "$BACKEND_PORT"
    _set_env_val "FRONTEND_PORT" "$FRONTEND_PORT"
    _set_env_val "DOCS_PORT" "$DOCS_PORT"
fi

echo "✅ Ports: backend=${BACKEND_PORT}, frontend=${FRONTEND_PORT}, docs=${DOCS_PORT}"

export BACKEND_PORT FRONTEND_PORT FRONTEND_HOST DOCS_PORT

# ── Start services ────────────────────────────────────────────────────────────

echo "🚀 Starting services..."

cleanup() {
    echo "🛑 Shutting down services..."
    # Resume a deliberately/accidentally stopped child before SIGTERM so it can
    # process the signal, then reap every child to avoid orphaned listeners.
    for child_pid in "${BACKEND_PID:-}" "${FRONTEND_PID:-}" "${DOCS_PID:-}"; do
        [ -n "$child_pid" ] || continue
        kill -CONT "$child_pid" 2>/dev/null
        kill "$child_pid" 2>/dev/null
    done
    for child_pid in "${BACKEND_PID:-}" "${FRONTEND_PID:-}" "${DOCS_PID:-}"; do
        [ -n "$child_pid" ] || continue
        wait "$child_pid" 2>/dev/null
    done
    echo "✅ Services stopped"
    exit 0
}
trap cleanup SIGINT SIGTERM

start_backend() {
    echo "🔧 Starting FastAPI backend on http://localhost:${BACKEND_PORT}"
    python3 main.py & BACKEND_PID=$!
}

start_frontend() {
    echo "🎨 Starting Streamlit frontend on http://localhost:${FRONTEND_PORT}"
    streamlit run frontend.py --server.address "$FRONTEND_HOST" --server.port "$FRONTEND_PORT" --server.headless true &
    FRONTEND_PID=$!
}

start_docs() {
    echo "📖 Starting documentation server on http://localhost:${DOCS_PORT}"
    python3 docs_server.py & DOCS_PID=$!
}

_wait_http() {
    local url=$1 timeout_seconds=${2:-30} waited=0
    while [ "$waited" -lt "$timeout_seconds" ]; do
        if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

_stop_child() {
    local pid=$1 waited=0
    kill "$pid" 2>/dev/null || return 0
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 5 ]; do
        sleep 1
        waited=$((waited + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        echo "⚠️  Process ${pid} ignored SIGTERM; forcing shutdown."
        kill -9 "$pid" 2>/dev/null
    fi
    wait "$pid" 2>/dev/null
}

_restart_backend() {
    _stop_child "$BACKEND_PID"
    sleep 2
    start_backend
}

_restart_frontend() {
    _stop_child "$FRONTEND_PID"
    sleep 2
    start_frontend
}

_restart_docs() {
    _stop_child "$DOCS_PID"
    sleep 2
    start_docs
}

start_backend

# Wait for actual readiness instead of assuming a fixed startup duration.
if ! _wait_http "http://127.0.0.1:${BACKEND_PORT}/health" 45; then
    echo "⚠️  Backend is not ready yet; the supervisor will keep retrying it."
fi

start_frontend
start_docs

# Confirm all access points when possible. The health supervisor below remains
# active if a slow machine needs longer or a child later becomes unresponsive.
_wait_http "http://127.0.0.1:${FRONTEND_PORT}/_stcore/health" 30 || \
    echo "⚠️  Frontend is not ready yet; recovery remains active."
_wait_http "http://127.0.0.1:${DOCS_PORT}/" 15 || \
    echo "⚠️  Documentation server is not ready yet; recovery remains active."

echo ""
echo "✅ omitest started successfully!"
echo ""
echo "🌐 Access Points:"
echo "   Dashboard:    http://localhost:${FRONTEND_PORT}"
echo "   Documentation: http://localhost:${DOCS_PORT}"
echo "   API Docs:     http://localhost:${BACKEND_PORT}/api/docs"
echo "   Health Check: http://localhost:${BACKEND_PORT}/health"
echo ""
echo "📋 Quick Start:"
echo "   1. Open http://localhost:${FRONTEND_PORT} in your browser"
echo "   2. Go to ⚙️  Settings → AI Configuration to set up a local or OpenAI-compatible provider"
echo "   3. Create a new session with target IP/domain"
echo "   4. Monitor AI-driven reconnaissance and approve high-risk commands"
echo ""
echo "🛑 Press Ctrl+C to stop all services"

# Persistent supervisor: an individual service crash must not stop the whole app.
# It also restarts a process that remains alive but fails three consecutive HTTP
# checks. Restart with a short backoff until the operator explicitly stops it.
BACKEND_HEALTH_FAILURES=0
FRONTEND_HEALTH_FAILURES=0
DOCS_HEALTH_FAILURES=0
while true; do
    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
        wait "$BACKEND_PID" 2>/dev/null
        echo "⚠️  Backend exited; restarting in 2 seconds..."
        sleep 2
        start_backend
        BACKEND_HEALTH_FAILURES=0
    elif curl -fsS --max-time 3 "http://127.0.0.1:${BACKEND_PORT}/health" >/dev/null 2>&1; then
        BACKEND_HEALTH_FAILURES=0
    else
        BACKEND_HEALTH_FAILURES=$((BACKEND_HEALTH_FAILURES + 1))
        if [ "$BACKEND_HEALTH_FAILURES" -ge 3 ]; then
            echo "⚠️  Backend failed 3 health checks; restarting..."
            _restart_backend
            BACKEND_HEALTH_FAILURES=0
        fi
    fi
    if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
        wait "$FRONTEND_PID" 2>/dev/null
        echo "⚠️  Frontend exited; restarting in 2 seconds..."
        sleep 2
        start_frontend
        FRONTEND_HEALTH_FAILURES=0
    elif curl -fsS --max-time 3 "http://127.0.0.1:${FRONTEND_PORT}/_stcore/health" >/dev/null 2>&1; then
        FRONTEND_HEALTH_FAILURES=0
    else
        FRONTEND_HEALTH_FAILURES=$((FRONTEND_HEALTH_FAILURES + 1))
        if [ "$FRONTEND_HEALTH_FAILURES" -ge 3 ]; then
            echo "⚠️  Frontend failed 3 health checks; restarting..."
            _restart_frontend
            FRONTEND_HEALTH_FAILURES=0
        fi
    fi
    if ! kill -0 "$DOCS_PID" 2>/dev/null; then
        wait "$DOCS_PID" 2>/dev/null
        echo "⚠️  Documentation server exited; restarting in 2 seconds..."
        sleep 2
        start_docs
        DOCS_HEALTH_FAILURES=0
    elif curl -fsS --max-time 3 "http://127.0.0.1:${DOCS_PORT}/" >/dev/null 2>&1; then
        DOCS_HEALTH_FAILURES=0
    else
        DOCS_HEALTH_FAILURES=$((DOCS_HEALTH_FAILURES + 1))
        if [ "$DOCS_HEALTH_FAILURES" -ge 3 ]; then
            echo "⚠️  Documentation server failed 3 health checks; restarting..."
            _restart_docs
            DOCS_HEALTH_FAILURES=0
        fi
    fi
    sleep 10
done
