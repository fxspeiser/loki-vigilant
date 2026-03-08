# Loki Vigilant

A real-time home network security monitoring tool with a web dashboard. Discovers devices on your LAN, classifies them automatically, tracks live traffic per device, monitors DNS queries, detects inbound port scans from external sources, and runs stealth port scans with OS fingerprinting and vulnerability detection.

![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-green)

## Features

### Device Discovery & Classification
- **Network Discovery** — ARP table parsing + nmap ping scan finds all devices on your LAN
- **Automatic Device Classification** — identifies phones, computers, printers, TVs, routers, IoT devices, cameras, game consoles, smart speakers, and more using a 5-tier heuristic: hostname patterns, MAC vendor (100+ OUI prefixes), OS fingerprint, open port signatures, and gateway detection
- **OS Fingerprinting** — nmap `-O` flag detects operating systems during port scans, feeding back into device classification (e.g., distinguishing a Samsung phone from a Samsung TV)
- **New Device Alerts** — devices seen for the first time get a pulsing "new" badge and highlighted row for the first hour

### Live Traffic Monitoring
- **Per-Device Packet Tracking** — tcpdump-based capture tracking packet counts, bandwidth, and last-seen timestamps per device
- **Real-Time Dashboard** — WebSocket-powered frontend updates every 2 seconds
- **1-Minute Activity Ranking** — devices auto-sort by recent packet activity with pause/resume control
- **Network-Wide Totals** — header badges show aggregate packets and bandwidth across all devices
- **Expandable Device Details** — click any device row to see MAC address, vendor, total traffic, and a live 60-second activity sparkline
- **DNS/Website Tracking** — a dedicated DNS capture process intercepts port 53 queries to show which domains each device is visiting (5-minute rolling window, deduplicated, noise-filtered)

### Port Scanning & Vulnerability Detection
- **Stealth Port Scanning** — nmap SYN scan (`-sS`) with OS detection (`-O`) on the top 1000 ports, triggered per-device from the UI with live progress stages
- **Service Version Detection** — identifies running services and versions on open ports (`-sV`)
- **Vulnerability Detection** — nmap `vulners` NSE script maps discovered services to known CVEs with CVSS severity scores, color-coded by severity (Critical / High / Medium / Low)
- **Scan History** — browse previous port scan results and vulnerabilities per device

### Intrusion Detection
- **Inbound Port Scan Detection** — a dedicated tcpdump process monitors for external-to-local probes, detecting when an outside host hits 8+ unique ports within 30 seconds
- **Scan Type Identification** — classifies the attack method: SYN Stealth, FIN, XMAS, NULL, ACK, TCP Connect, or UDP scan
- **IP Spoof Verification** — multi-factor analysis determines if the scanner's IP is genuine or spoofed:
  - TTL consistency and plausibility checks
  - TCP handshake feasibility (Connect scans can't be spoofed)
  - Source port pattern analysis
  - Forward-confirmed reverse DNS (FCrDNS) validation
- **Reverse DNS Lookup** — resolves scanner hostnames with caching, displayed throughout the UI
- **Real-Time Alert Banner** — a red pulsing banner appears at the top of the dashboard during active scans, showing scan type, source IP/hostname, and spoof warnings
- **Intrusion Log Tab** — dedicated tab with statistics (total attempts, last attempt, predicted next scan based on historical intervals), and a detailed log table with source, scan type, verification status, ports probed, targets, timing, and duration
- **Persistent Storage** — all intrusion events are saved to SQLite for historical analysis

### General
- **Device Nicknames** — label any device with a custom name (inline editing, persisted in SQLite)
- **Dark Theme UI** — clean, monospace-focused dashboard designed for security monitoring
- **Responsive Design** — works on desktop and mobile browsers

## Quick Start

```bash
# Clone the repo and enter it
git clone <your-repo-url>
cd loki-vigilant

# Launch (auto-runs setup on first run)
./run.sh
```

On first run, the setup wizard runs automatically. You can also run it directly:

```bash
./setup.sh
```

The setup wizard will:

1. Detect your OS (macOS / Linux)
2. Check for all required dependencies (Python 3.9+, nmap, tcpdump, network tools)
3. Verify the nmap `vulners` NSE script is available
4. Offer to install anything missing (via Homebrew on macOS, apt/dnf/pacman/zypper on Linux)
5. Create a Python virtual environment and install all Python packages
6. Verify that all Python imports work

Once setup is complete, `./run.sh` launches the server with `sudo` (required for tcpdump and nmap privileges).

Open **http://127.0.0.1:5150** in your browser.

## Prerequisites

- **Python 3.9+**
- **nmap** — `brew install nmap` (macOS) or `sudo apt install nmap` (Linux)
- **tcpdump** — pre-installed on macOS and most Linux distributions
- **Root/sudo access** — required for packet capture, OS detection, and SYN scans

All of these are checked and can be installed by the setup wizard (`./setup.sh`).

## Manual Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo venv/bin/python app.py
```

## Usage

1. **Scan Network** — click the button in the header to run ARP + nmap discovery
2. **Monitor Traffic** — packet counts, bandwidth, and last-seen timestamps update in real time
3. **Expand Device Details** — click any device row to see MAC, vendor, total traffic, a live activity sparkline, and DNS queries (websites visited)
4. **Port Scan** — click the gear icon on any device to run a stealth SYN scan with OS detection and service fingerprinting — watch live progress through each stage (SYN scan + OS detection, service detection, vulnerability check)
5. **View Vulnerabilities** — scan results show open ports, services, versions, detected OS, and associated CVEs color-coded by severity
6. **Rename Devices** — click the pencil icon to assign a nickname to any device
7. **Scan History** — click the clipboard icon to view previous scan results
8. **Intrusion Log** — switch to the "Intrusion Log" tab to see detected inbound port scans, spoof verification, and predicted next scan timing
9. **Active Scan Alert** — when an external host is actively scanning your network, a red banner appears at the top of the page

## Project Structure

```
loki-vigilant/
├── app.py                      # Flask + SocketIO server, API routes, intrusion callbacks
├── run.sh                      # One-command launcher (auto-runs setup if needed)
├── setup.sh                    # Dependency checker & install wizard
├── requirements.txt
├── backend/
│   ├── db.py                   # SQLite persistence (devices, scans, vulns, intrusions)
│   ├── scanner.py              # ARP, nmap discovery, port scan, OS detection, classification
│   ├── packet_monitor.py       # Live tcpdump capture + DNS query tracking
│   └── intrusion_detector.py   # Inbound scan detection, spoof analysis, reverse DNS
└── frontend/
    ├── templates/index.html    # Dashboard HTML (tabs, banner, modals)
    └── static/
        ├── style.css           # Dark theme UI
        └── app.js              # Real-time frontend with WebSocket
```

## How It Works

| Layer | Tool | Purpose |
|-------|------|---------|
| Discovery | `arp -a`, `nmap -sn` | Find devices on the LAN |
| Classification | hostname, MAC vendor, OS fingerprint, open ports | Identify device types automatically |
| Packet capture | `tcpdump -e -l -n -q` | Track per-device traffic in real time |
| DNS tracking | `tcpdump udp port 53` | Monitor which domains each device queries |
| Activity window | Rolling 60s deque | Rank devices by recent activity |
| Interface stats | `netstat -ib` (macOS), `/proc/net/dev` (Linux) | Aggregate bandwidth |
| Port scanning | `nmap -sS -O -sV --script=vulners` | Stealth SYN scan + OS detection + CVE lookup |
| Intrusion detection | `tcpdump -v tcp or udp` | Detect inbound port scans from external IPs |
| Spoof verification | TTL analysis, FCrDNS, TCP flag analysis | Assess if scanner IP is genuine |
| Persistence | SQLite | Devices, nicknames, scans, vulnerabilities, intrusion log |
| Real-time push | Flask-SocketIO | Live traffic, DNS, and intrusion updates to the browser |

## Network Tools Used

**macOS:** `arp`, `tcpdump`, `netstat`, `route`, `nmap`

**Linux:** `arp`, `tcpdump`, `ip`, `nmap`, `/proc/net/dev`

## Security Notes

- The dashboard binds to `0.0.0.0:5150` — restrict access via firewall if needed, or change to `127.0.0.1` in `app.py`
- Port scans use `-T3` timing (normal) to avoid flooding target devices
- OS detection (`-O`) requires root privileges and sends additional probes to the target
- All scans are intended for **your own network only** — do not scan networks you don't own or have authorization to test
- Intrusion detection is passive (monitoring only) and does not block or respond to detected scans

## License

MIT
