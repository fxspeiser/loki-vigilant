#!/bin/bash
# Loki Vigilant - Launcher
# Requires: sudo (for tcpdump packet capture and nmap SYN scans)

set -e

cd "$(dirname "$0")"

# Quick dependency check — run setup wizard if anything is missing
missing=false
command -v python3 &> /dev/null || missing=true
command -v nmap &> /dev/null || missing=true
command -v tcpdump &> /dev/null || missing=true

if [ "$missing" = true ] || [ ! -d "venv" ]; then
    if [ "$missing" = true ]; then
        echo "Some dependencies are missing. Launching setup wizard..."
        echo ""
    fi
    ./setup.sh
fi

# Activate venv
source venv/bin/activate

# Ensure packages are up to date
pip install -q -r requirements.txt

echo ""
echo "============================================"
echo "  Loki Vigilant - Home Network Security"
echo "============================================"
echo ""
echo "NOTE: Running with sudo for packet capture"
echo "      and stealth (SYN) port scanning."
echo ""
echo "Dashboard will be at: http://127.0.0.1:5150"
echo ""

# Run with sudo to enable tcpdump and nmap SYN scans
sudo venv/bin/python app.py
