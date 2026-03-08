#!/bin/bash
# Loki Vigilant - Dependency Checker & Install Wizard
# Checks all required tools and walks the user through installing missing ones.

set -e

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# --- Helpers ---

print_header() {
    echo ""
    echo -e "${BOLD}============================================${RESET}"
    echo -e "${BOLD}  Loki Vigilant - Setup Wizard${RESET}"
    echo -e "${BOLD}============================================${RESET}"
    echo ""
}

check_mark() { echo -e "  ${GREEN}✓${RESET} $1"; }
warn_mark() { echo -e "  ${YELLOW}⚠${RESET} $1"; }
fail_mark() { echo -e "  ${RED}✗${RESET} $1"; }
info_mark() { echo -e "  ${BLUE}→${RESET} $1"; }

prompt_yn() {
    local prompt="$1"
    local default="${2:-y}"
    if [ "$default" = "y" ]; then
        prompt="$prompt [Y/n] "
    else
        prompt="$prompt [y/N] "
    fi
    read -r -p "  $prompt" answer
    answer="${answer:-$default}"
    case "$answer" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)  echo "linux" ;;
        *)      echo "unknown" ;;
    esac
}

detect_linux_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v yum &> /dev/null; then
        echo "yum"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    elif command -v zypper &> /dev/null; then
        echo "zypper"
    else
        echo "unknown"
    fi
}

# --- Dependency checks ---

MISSING=()
WARNINGS=()
OS="$(detect_os)"

check_python() {
    echo -e "\n${BOLD}Checking Python...${RESET}"

    if command -v python3 &> /dev/null; then
        local ver
        ver="$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
        local major minor
        major="$(echo "$ver" | cut -d. -f1)"
        minor="$(echo "$ver" | cut -d. -f2)"

        if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]; then
            check_mark "Python $ver"
        else
            fail_mark "Python $ver found, but 3.9+ is required"
            MISSING+=("python3")
        fi
    else
        fail_mark "Python 3 not found"
        MISSING+=("python3")
    fi

    # Check pip / venv
    if python3 -m venv --help &> /dev/null 2>&1; then
        check_mark "venv module available"
    else
        warn_mark "venv module not available"
        MISSING+=("python3-venv")
    fi
}

check_nmap() {
    echo -e "\n${BOLD}Checking nmap...${RESET}"

    if command -v nmap &> /dev/null; then
        local ver
        ver="$(nmap --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+')"
        check_mark "nmap $ver"

        # Check for vulners script
        local script_dir
        if [ "$OS" = "macos" ]; then
            script_dir="/opt/homebrew/share/nmap/scripts /usr/local/share/nmap/scripts"
        else
            script_dir="/usr/share/nmap/scripts"
        fi
        local found_vulners=false
        for dir in $script_dir; do
            if [ -f "$dir/vulners.nse" ]; then
                found_vulners=true
                break
            fi
        done
        # Also check via nmap itself
        if nmap --script-help vulners &> /dev/null 2>&1; then
            found_vulners=true
        fi

        if [ "$found_vulners" = true ]; then
            check_mark "vulners NSE script available"
        else
            warn_mark "vulners NSE script not found (vulnerability detection will be limited)"
            WARNINGS+=("vulners")
        fi
    else
        fail_mark "nmap not found"
        MISSING+=("nmap")
    fi
}

check_tcpdump() {
    echo -e "\n${BOLD}Checking tcpdump...${RESET}"

    if command -v tcpdump &> /dev/null; then
        check_mark "tcpdump found"
    else
        fail_mark "tcpdump not found"
        MISSING+=("tcpdump")
    fi
}

check_arp() {
    echo -e "\n${BOLD}Checking network tools...${RESET}"

    if command -v arp &> /dev/null; then
        check_mark "arp"
    else
        warn_mark "arp not found (device discovery will rely on nmap only)"
        WARNINGS+=("arp")
    fi

    if [ "$OS" = "macos" ]; then
        if command -v route &> /dev/null; then
            check_mark "route"
        else
            fail_mark "route not found"
            MISSING+=("route")
        fi
        if command -v netstat &> /dev/null; then
            check_mark "netstat"
        else
            warn_mark "netstat not found"
            WARNINGS+=("netstat")
        fi
    else
        if command -v ip &> /dev/null; then
            check_mark "ip"
        else
            fail_mark "ip command not found"
            MISSING+=("iproute2")
        fi
    fi
}

check_sudo() {
    echo -e "\n${BOLD}Checking sudo access...${RESET}"

    if command -v sudo &> /dev/null; then
        check_mark "sudo available"
        if sudo -n true 2>/dev/null; then
            check_mark "sudo credentials cached (no password needed right now)"
        else
            info_mark "sudo password will be required at launch"
        fi
    else
        fail_mark "sudo not found — root access is required for packet capture and SYN scans"
        MISSING+=("sudo")
    fi
}

check_homebrew() {
    if [ "$OS" = "macos" ]; then
        echo -e "\n${BOLD}Checking Homebrew (macOS package manager)...${RESET}"
        if command -v brew &> /dev/null; then
            check_mark "Homebrew installed"
            return 0
        else
            warn_mark "Homebrew not installed"
            return 1
        fi
    fi
    return 0
}

# --- Install helpers ---

install_homebrew() {
    echo ""
    info_mark "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    # Add to PATH for current session
    if [ -f /opt/homebrew/bin/brew ]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -f /usr/local/bin/brew ]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi
}

install_package() {
    local pkg="$1"
    local display_name="${2:-$pkg}"

    echo ""
    info_mark "Installing $display_name..."

    if [ "$OS" = "macos" ]; then
        if ! command -v brew &> /dev/null; then
            if prompt_yn "Homebrew is required to install $display_name. Install Homebrew?" "y"; then
                install_homebrew
            else
                echo -e "  ${DIM}Skipping $display_name install. You'll need to install it manually.${RESET}"
                return 1
            fi
        fi
        brew install "$pkg"

    elif [ "$OS" = "linux" ]; then
        local pm
        pm="$(detect_linux_pkg_manager)"
        case "$pm" in
            apt)
                sudo apt-get update -qq
                sudo apt-get install -y "$pkg"
                ;;
            dnf)
                sudo dnf install -y "$pkg"
                ;;
            yum)
                sudo yum install -y "$pkg"
                ;;
            pacman)
                sudo pacman -S --noconfirm "$pkg"
                ;;
            zypper)
                sudo zypper install -y "$pkg"
                ;;
            *)
                echo -e "  ${RED}Could not detect package manager. Install $display_name manually.${RESET}"
                return 1
                ;;
        esac
    fi
}

install_python_deps() {
    echo -e "\n${BOLD}Setting up Python environment...${RESET}"

    cd "$(dirname "$0")"

    if [ ! -d "venv" ]; then
        info_mark "Creating virtual environment..."
        python3 -m venv venv
        check_mark "Virtual environment created"
    else
        check_mark "Virtual environment exists"
    fi

    info_mark "Installing Python packages..."
    venv/bin/pip install -q -r requirements.txt
    check_mark "Python packages installed"

    # Verify key imports
    local failed=false
    for mod in flask flask_socketio nmap scapy psutil eventlet; do
        if venv/bin/python -c "import $mod" 2>/dev/null; then
            check_mark "$mod"
        else
            fail_mark "$mod failed to import"
            failed=true
        fi
    done

    if [ "$failed" = true ]; then
        echo ""
        fail_mark "Some Python packages failed to install. Try:"
        echo -e "    ${DIM}venv/bin/pip install -r requirements.txt${RESET}"
        return 1
    fi
}

# --- Main ---

print_header

echo -e "${BOLD}Detecting system...${RESET}"
if [ "$OS" = "macos" ]; then
    check_mark "macOS $(sw_vers -productVersion 2>/dev/null || echo '')"
elif [ "$OS" = "linux" ]; then
    local distro=""
    if [ -f /etc/os-release ]; then
        distro="$(. /etc/os-release && echo "$PRETTY_NAME")"
    fi
    check_mark "Linux ${distro}"
else
    warn_mark "Unsupported OS: $(uname -s). Some features may not work."
fi

# Run all checks
check_python
check_nmap
check_tcpdump
check_arp
check_sudo
HAS_BREW=true
if [ "$OS" = "macos" ]; then
    check_homebrew || HAS_BREW=false
fi

# --- Summary & Install ---

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

if [ ${#MISSING[@]} -eq 0 ] && [ ${#WARNINGS[@]} -eq 0 ]; then
    echo -e "\n${GREEN}${BOLD}All dependencies satisfied!${RESET}\n"
elif [ ${#MISSING[@]} -eq 0 ]; then
    echo -e "\n${YELLOW}${BOLD}All required dependencies found, with minor warnings.${RESET}\n"
else
    echo -e "\n${RED}${BOLD}Missing dependencies: ${MISSING[*]}${RESET}\n"
fi

# Offer to install missing system packages
if [ ${#MISSING[@]} -gt 0 ]; then
    echo -e "${BOLD}Would you like to install missing dependencies?${RESET}"
    echo ""

    for pkg in "${MISSING[@]}"; do
        case "$pkg" in
            python3)
                if prompt_yn "Install Python 3?" "y"; then
                    if [ "$OS" = "macos" ]; then
                        install_package "python@3" "Python 3"
                    else
                        install_package "python3" "Python 3"
                    fi
                fi
                ;;
            python3-venv)
                if [ "$OS" = "linux" ]; then
                    if prompt_yn "Install python3-venv?" "y"; then
                        install_package "python3-venv" "Python venv module"
                    fi
                fi
                ;;
            nmap)
                if prompt_yn "Install nmap?" "y"; then
                    install_package "nmap" "nmap"
                fi
                ;;
            tcpdump)
                if prompt_yn "Install tcpdump?" "y"; then
                    install_package "tcpdump" "tcpdump"
                fi
                ;;
            iproute2)
                if prompt_yn "Install iproute2?" "y"; then
                    install_package "iproute2" "iproute2"
                fi
                ;;
            *)
                warn_mark "Don't know how to install: $pkg"
                ;;
        esac
    done

    # Re-check after installs
    echo ""
    echo -e "${BOLD}Re-checking...${RESET}"
    MISSING=()
    command -v python3 &> /dev/null || MISSING+=("python3")
    command -v nmap &> /dev/null || MISSING+=("nmap")
    command -v tcpdump &> /dev/null || MISSING+=("tcpdump")

    if [ ${#MISSING[@]} -gt 0 ]; then
        echo ""
        fail_mark "Still missing: ${MISSING[*]}"
        echo -e "  ${DIM}Install them manually and run this script again.${RESET}"
        exit 1
    else
        check_mark "All system dependencies now installed"
    fi
fi

# Python environment setup
if prompt_yn "Set up Python virtual environment and install packages?" "y"; then
    install_python_deps
fi

# --- Done ---

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "\n${GREEN}${BOLD}Setup complete!${RESET}\n"
echo -e "  To start Loki Vigilant:"
echo -e "    ${BOLD}./run.sh${RESET}"
echo ""
echo -e "  Dashboard: ${BLUE}http://127.0.0.1:5150${RESET}"
echo ""
