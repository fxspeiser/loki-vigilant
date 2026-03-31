#!/bin/bash
# Loki Vigilant - Agentic Setup
# Fully automated, non-interactive deployment for CI/CD and agent-driven installs.
# Exits 0 on success, non-zero on failure. Outputs JSON status to stdout.
#
# Usage:
#   ./agent-setup.sh              # Full auto-install (interactive prompts suppressed)
#   ./agent-setup.sh --check      # Check dependencies only, don't install
#   ./agent-setup.sh --json       # Output final status as JSON (for agent parsing)
#   ./agent-setup.sh --api-key    # Generate an API key for agent access
#   ./agent-setup.sh --headless   # Install + start as background service
#
# Environment variables:
#   LOKI_PORT=5150                # Override default port
#   LOKI_HOST=0.0.0.0            # Override bind address
#   LOKI_NO_INSTALL=1            # Skip system package installation
#   LOKI_API_KEY=<key>           # Pre-set API key instead of generating one

set -euo pipefail

cd "$(dirname "$0")"

# --- Defaults ---
MODE="install"
JSON_OUTPUT=false
GENERATE_KEY=false
HEADLESS=false
LOKI_PORT="${LOKI_PORT:-5150}"
LOKI_HOST="${LOKI_HOST:-0.0.0.0}"

# --- Parse args ---
for arg in "$@"; do
    case "$arg" in
        --check)    MODE="check" ;;
        --json)     JSON_OUTPUT=true ;;
        --api-key)  GENERATE_KEY=true ;;
        --headless) HEADLESS=true ;;
        --help|-h)
            echo "Usage: $0 [--check] [--json] [--api-key] [--headless]"
            echo ""
            echo "Options:"
            echo "  --check      Check dependencies only, don't install anything"
            echo "  --json       Output final status as JSON"
            echo "  --api-key    Generate an API key for agent access"
            echo "  --headless   Install and start as a background service"
            echo ""
            echo "Environment:"
            echo "  LOKI_PORT=5150          Override port"
            echo "  LOKI_HOST=0.0.0.0      Override bind address"
            echo "  LOKI_NO_INSTALL=1       Skip system package installation"
            echo "  LOKI_API_KEY=<key>      Pre-set API key"
            exit 0
            ;;
    esac
done

# --- OS Detection ---
detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)  echo "linux" ;;
        *)      echo "unknown" ;;
    esac
}

detect_pkg_manager() {
    if command -v brew &>/dev/null; then echo "brew"
    elif command -v apt-get &>/dev/null; then echo "apt"
    elif command -v dnf &>/dev/null; then echo "dnf"
    elif command -v yum &>/dev/null; then echo "yum"
    elif command -v pacman &>/dev/null; then echo "pacman"
    elif command -v zypper &>/dev/null; then echo "zypper"
    else echo "none"
    fi
}

OS="$(detect_os)"
PKG_MGR="$(detect_pkg_manager)"

# --- Logging ---
log() { echo "[loki-setup] $*" >&2; }
err() { echo "[loki-setup] ERROR: $*" >&2; }

# --- Dependency checks ---
DEPS_STATUS=()
MISSING_DEPS=()

check_dep() {
    local name="$1"
    local cmd="$2"
    local version=""

    if command -v "$cmd" &>/dev/null; then
        case "$cmd" in
            python3) version="$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo 'unknown')" ;;
            nmap)    version="$(nmap --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+' || echo 'unknown')" ;;
            *)       version="installed" ;;
        esac
        DEPS_STATUS+=("{\"name\":\"$name\",\"status\":\"ok\",\"version\":\"$version\"}")
        return 0
    else
        DEPS_STATUS+=("{\"name\":\"$name\",\"status\":\"missing\",\"version\":null}")
        MISSING_DEPS+=("$name")
        return 1
    fi
}

check_python_version() {
    if ! command -v python3 &>/dev/null; then return 1; fi
    local ver major minor
    ver="$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)"
    major="$(echo "$ver" | cut -d. -f1)"
    minor="$(echo "$ver" | cut -d. -f2)"
    [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]
}

check_all_deps() {
    DEPS_STATUS=()
    MISSING_DEPS=()

    log "Checking dependencies..."
    check_dep "python3" "python3" || true
    if command -v python3 &>/dev/null && ! check_python_version; then
        DEPS_STATUS=("${DEPS_STATUS[@]/${DEPS_STATUS[-1]}/}")
        DEPS_STATUS+=("{\"name\":\"python3\",\"status\":\"outdated\",\"version\":\"$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')\"}")
        MISSING_DEPS+=("python3")
    fi
    check_dep "nmap" "nmap" || true
    check_dep "tcpdump" "tcpdump" || true
    check_dep "arp" "arp" || true

    if [ "$OS" = "macos" ]; then
        check_dep "route" "route" || true
    else
        check_dep "ip" "ip" || true
    fi
}

# --- Installation ---
install_pkg() {
    local pkg="$1"
    log "Installing $pkg..."

    case "$PKG_MGR" in
        brew)   brew install "$pkg" 2>&1 ;;
        apt)    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" 2>&1 ;;
        dnf)    sudo dnf install -y -q "$pkg" 2>&1 ;;
        yum)    sudo yum install -y -q "$pkg" 2>&1 ;;
        pacman) sudo pacman -S --noconfirm --quiet "$pkg" 2>&1 ;;
        zypper) sudo zypper install -y -q "$pkg" 2>&1 ;;
        *)      err "No package manager found. Install $pkg manually."; return 1 ;;
    esac
}

install_missing() {
    if [ "${LOKI_NO_INSTALL:-0}" = "1" ]; then
        log "LOKI_NO_INSTALL set, skipping system package installation"
        return 0
    fi

    for dep in "${MISSING_DEPS[@]}"; do
        case "$dep" in
            python3)
                if [ "$OS" = "macos" ]; then
                    install_pkg "python@3" || true
                else
                    install_pkg "python3" || true
                    install_pkg "python3-venv" || true
                    install_pkg "python3-pip" || true
                fi
                ;;
            nmap)    install_pkg "nmap" || true ;;
            tcpdump) install_pkg "tcpdump" || true ;;
            ip)      install_pkg "iproute2" || true ;;
            arp)
                if [ "$OS" = "linux" ]; then
                    install_pkg "net-tools" || true
                fi
                ;;
        esac
    done
}

setup_python_env() {
    log "Setting up Python environment..."

    if [ ! -d "venv" ]; then
        python3 -m venv venv
        log "Virtual environment created"
    fi

    venv/bin/pip install -q --upgrade pip 2>&1
    venv/bin/pip install -q -r requirements.txt 2>&1
    log "Python packages installed"

    # Verify imports
    local failed=false
    for mod in flask flask_socketio nmap scapy psutil; do
        if ! venv/bin/python -c "import $mod" 2>/dev/null; then
            err "Failed to import: $mod"
            failed=true
        fi
    done

    if [ "$failed" = true ]; then
        return 1
    fi
    return 0
}

# --- API Key ---
generate_api_key() {
    local key="${LOKI_API_KEY:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))' 2>/dev/null || openssl rand -base64 32 | tr -d '=/+' | head -c 43)}"

    # Store the key
    echo "$key" > .api_key
    chmod 600 .api_key
    log "API key stored in .api_key"

    # Also write it to the database via a small Python script
    venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from backend.db import init_db, set_setting
init_db()
set_setting('agent_api_key', '$key')
print('API key saved to database')
" 2>&1

    echo "$key"
}

# --- Headless service ---
create_service() {
    local project_dir
    project_dir="$(pwd)"

    if [ "$OS" = "macos" ]; then
        local plist_path="$HOME/Library/LaunchAgents/com.loki-vigilant.plist"
        cat > "$plist_path" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.loki-vigilant</string>
    <key>ProgramArguments</key>
    <array>
        <string>sudo</string>
        <string>${project_dir}/venv/bin/python</string>
        <string>${project_dir}/app.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${project_dir}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>LOKI_PORT</key>
        <string>${LOKI_PORT}</string>
        <key>LOKI_HOST</key>
        <string>${LOKI_HOST}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${project_dir}/loki-vigilant.log</string>
    <key>StandardErrorPath</key>
    <string>${project_dir}/loki-vigilant.log</string>
</dict>
</plist>
PLIST
        launchctl load "$plist_path" 2>&1 || true
        log "macOS LaunchAgent created: $plist_path"

    elif [ "$OS" = "linux" ]; then
        local service_path="/etc/systemd/system/loki-vigilant.service"
        sudo tee "$service_path" > /dev/null << UNIT
[Unit]
Description=Loki Vigilant - Network Security Monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=${project_dir}
ExecStart=${project_dir}/venv/bin/python ${project_dir}/app.py
Restart=always
RestartSec=5
Environment=LOKI_PORT=${LOKI_PORT}
Environment=LOKI_HOST=${LOKI_HOST}

[Install]
WantedBy=multi-user.target
UNIT
        sudo systemctl daemon-reload
        sudo systemctl enable loki-vigilant
        sudo systemctl start loki-vigilant
        log "systemd service created and started"
    fi
}

# --- JSON output ---
output_json() {
    local status="$1"
    local api_key="${2:-}"
    local deps_json
    deps_json="[$(IFS=,; echo "${DEPS_STATUS[*]}")]"
    local missing_json
    missing_json="[$(printf '"%s",' "${MISSING_DEPS[@]}" 2>/dev/null | sed 's/,$//' || echo '')]"

    cat << JSON
{
  "status": "$status",
  "os": "$OS",
  "package_manager": "$PKG_MGR",
  "port": $LOKI_PORT,
  "host": "$LOKI_HOST",
  "dashboard_url": "http://${LOKI_HOST}:${LOKI_PORT}",
  "agent_api_base": "http://${LOKI_HOST}:${LOKI_PORT}/api/v1/agent",
  "api_key": ${api_key:+"\"$api_key\""}${api_key:-null},
  "dependencies": $deps_json,
  "missing": $missing_json,
  "headless": $HEADLESS,
  "project_dir": "$(pwd)"
}
JSON
}

# =============================================================================
# Main
# =============================================================================

log "Loki Vigilant - Agentic Setup"
log "OS: $OS | Package manager: $PKG_MGR"

# Step 1: Check dependencies
check_all_deps

if [ "$MODE" = "check" ]; then
    if [ ${#MISSING_DEPS[@]} -eq 0 ]; then
        log "All dependencies satisfied"
        if [ "$JSON_OUTPUT" = true ]; then output_json "ok"; fi
        exit 0
    else
        log "Missing: ${MISSING_DEPS[*]}"
        if [ "$JSON_OUTPUT" = true ]; then output_json "missing_deps"; fi
        exit 1
    fi
fi

# Step 2: Install missing system deps
if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    log "Installing missing dependencies: ${MISSING_DEPS[*]}"
    install_missing

    # Re-check
    check_all_deps
    if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
        err "Still missing after install: ${MISSING_DEPS[*]}"
        if [ "$JSON_OUTPUT" = true ]; then output_json "install_failed"; fi
        exit 1
    fi
fi

log "All system dependencies OK"

# Step 3: Python environment
if ! setup_python_env; then
    err "Python environment setup failed"
    if [ "$JSON_OUTPUT" = true ]; then output_json "python_setup_failed"; fi
    exit 1
fi

log "Python environment OK"

# Step 4: Initialize database
venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from backend.db import init_db
init_db()
print('[loki-setup] Database initialized')
" 2>&1 >&2

# Step 5: API key
API_KEY=""
if [ "$GENERATE_KEY" = true ] || [ -n "${LOKI_API_KEY:-}" ]; then
    API_KEY="$(generate_api_key)"
    log "API key: $API_KEY"
elif [ -f .api_key ]; then
    API_KEY="$(cat .api_key)"
    log "Existing API key found"
fi

# Step 6: Headless service
if [ "$HEADLESS" = true ]; then
    create_service
    log "Headless service configured"
fi

# Done
log "Setup complete!"
log "Dashboard: http://${LOKI_HOST}:${LOKI_PORT}"
if [ -n "$API_KEY" ]; then
    log "Agent API: http://${LOKI_HOST}:${LOKI_PORT}/api/v1/agent"
fi

if [ "$JSON_OUTPUT" = true ]; then
    output_json "ok" "$API_KEY"
fi

exit 0
