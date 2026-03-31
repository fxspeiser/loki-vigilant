# Loki Vigilant

A real-time home network security monitoring tool with a web dashboard and agent API. Discovers devices on your LAN, classifies them automatically, tracks live traffic per device, monitors DNS queries, detects inbound port scans, inspects device traffic in real time, and runs stealth port scans with OS fingerprinting and vulnerability detection. Includes a full REST API for integration with AI agents (ClaudeBot, OpenClaw, etc.).

![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-green)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

## Features

### Device Discovery & Classification
- **Network Discovery** — ARP table parsing + nmap ping scan finds all devices on your LAN
- **Automatic Device Classification** — identifies phones, computers, printers, TVs, routers, IoT devices, cameras, game consoles, smart speakers, and more using a 5-tier heuristic: hostname patterns, MAC vendor (100+ OUI prefixes), OS fingerprint, open port signatures, and gateway detection
- **OS Fingerprinting** — nmap `-O` flag detects operating systems during port scans, feeding back into device classification
- **New Device Alerts** — devices seen for the first time get a pulsing "new" badge and highlighted row for the first hour
- **Device Tagging** — tag devices for auto-scan targeting or custom categorization

### Live Traffic Monitoring
- **Per-Device Packet Tracking** — tcpdump-based capture tracking packet counts, bandwidth, and last-seen timestamps per device
- **Real-Time Dashboard** — WebSocket-powered frontend updates every 2 seconds
- **1-Minute Activity Ranking** — devices auto-sort by recent packet activity with pause/resume control
- **Network-Wide Totals** — header badges show aggregate packets and bandwidth across all devices
- **Expandable Device Details** — click any device row to see MAC address, vendor, total traffic, and a live 60-second activity sparkline
- **DNS/Website Tracking** — a dedicated DNS capture process intercepts port 53 queries to show which domains each device is visiting (5-minute rolling window, deduplicated, noise-filtered)

### Traffic Inspector
- **Full-Page Device Inspector** — click the eye icon on any device to open a dedicated traffic inspection page in a new tab
- **Live Packet Stream** — real-time scrolling table of all packets to/from the device with source, destination, protocol, service, length, and encryption status
- **Content View** — click any packet to view its decoded payload in cleartext (for unencrypted protocols like HTTP, DNS, FTP, SMTP, mDNS)
- **Peer Breakdown** — left sidebar shows all IPs communicating with the device, sorted by packet count, with inbound/outbound stats and visual bar chart
- **Encryption Detection** — identifies encrypted traffic (HTTPS, SSH, TLS) by port, TLS handshake signatures, and entropy analysis
- **Service Identification** — automatically labels protocols: HTTP, HTTPS, DNS, SSH, SMTP, IMAP, mDNS, NTP, DHCP, MQTT, and more

### Port Scanning & Vulnerability Detection
- **Stealth Port Scanning** — nmap SYN scan (`-sS`) with OS detection (`-O`) on the top 1000 ports, triggered per-device from the UI with live progress stages
- **In-Row Scan Progress** — active scans highlight the device row orange with a pulsing "scanning" badge instead of a popup, with an icon to view live progress
- **Service Version Detection** — identifies running services and versions on open ports (`-sV`)
- **Vulnerability Detection** — nmap `vulners` NSE script maps discovered services to known CVEs with CVSS severity scores, color-coded by severity (Critical / High / Medium / Low)
- **Scan History** — browse previous port scan results and vulnerabilities per device

### Auto-Scan Policy
- **Configurable Auto-Scan** — when an intrusion is detected, automatically port-scan your devices to assess posture
- **Five Policies:**
  - **Scanning devices** (default) — scan all devices when someone scans your network
  - **All devices** — scan every device on the network
  - **New devices** — only scan devices seen in the last hour
  - **Tagged devices** — only scan devices tagged with "auto-scan"
  - **No devices** — disable auto-scanning entirely
- **Settings Panel** — configure from the dashboard header

### Intrusion Detection
- **Inbound Port Scan Detection** — a dedicated tcpdump process monitors for external-to-local probes, detecting when an outside host hits 8+ unique ports within 30 seconds
- **Scan Type Identification** — classifies the attack method: SYN Stealth, FIN, XMAS, NULL, ACK, TCP Connect, or UDP scan
- **IP Spoof Verification** — multi-factor analysis determines if the scanner's IP is genuine or spoofed:
  - TTL consistency and plausibility checks
  - TCP handshake feasibility (Connect scans can't be spoofed)
  - Source port pattern analysis
  - Forward-confirmed reverse DNS (FCrDNS) validation
- **Real-Time Alert Banner** — a red pulsing banner with a distinct spoof verification badge (Verified / Suspicious / Likely Spoofed / Unverified) appears during active scans
- **Malicious Scans Tab** — dedicated tab with paginated scan history (50 per page), showing scanning IP, scan type, spoof status with reason chips, ports probed, targets, timing, and duration
- **Intrusion Log Tab** — statistics (total attempts, last attempt, predicted next scan), and detailed log table
- **Persistent Storage** — all intrusion events are saved to SQLite for historical analysis

### Agent API
- **Full REST API** — programmatic access under `/api/v1/agent/` for AI agents, bots, and automation
- **Bearer Token Auth** — secure API key authentication
- **Comprehensive Endpoints** — devices, scanning, intrusions, vulnerabilities, settings, bulk operations
- See the [Agent API Reference](#agent-api-reference) section below for full documentation

### General
- **Device Nicknames** — label any device with a custom name (inline editing, persisted in SQLite)
- **Dark Theme UI** — clean, monospace-focused dashboard designed for security monitoring
- **Responsive Design** — works on desktop and mobile browsers

## Installation

### Quick Start (git clone)

```bash
git clone https://github.com/fxspeiser/loki-vigilant.git
cd loki-vigilant
./run.sh
```

### npm (GitHub Packages)

```bash
npm install -g @fxspeiser/loki-vigilant
loki-vigilant setup
loki-vigilant start
```

### RPM (Fedora / RHEL / CentOS)

```bash
sudo rpm -i loki-vigilant-1.0.0-1.noarch.rpm
sudo systemctl start loki-vigilant
sudo systemctl enable loki-vigilant
```

### Automated / CI Setup

```bash
# Non-interactive setup with API key generation
./agent-setup.sh --api-key --json

# Install as background service with API access
./agent-setup.sh --api-key --headless --json
```

See [Agentic Setup](#agentic-setup) for full options.

## Setup Wizard

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
3. **Expand Device Details** — click any device row to see MAC, vendor, total traffic, a live activity sparkline, and DNS queries
4. **Inspect Traffic** — click the eye icon on any device to open the full traffic inspector in a new tab
5. **Port Scan** — click the gear icon on any device to run a stealth SYN scan — the row highlights orange with a pulsing "scanning" badge while in progress; click the pulsing gear to view live progress
6. **View Vulnerabilities** — scan results show open ports, services, versions, detected OS, and associated CVEs color-coded by severity
7. **Rename Devices** — click the pencil icon to assign a nickname
8. **Tag Devices** — click the flag icon to toggle the "auto-scan" tag
9. **Auto-Scan Settings** — click the gear button in the header to configure auto-scan policy
10. **Malicious Scans** — switch to the "Malicious Scans" tab to browse detected scans with spoof verification, paginated 50 at a time
11. **Intrusion Log** — switch to the "Intrusion Log" tab to see statistics and predicted next scan timing
12. **Active Scan Alert** — when an external host is actively scanning your network, a red banner with spoof verification badge appears

## Agentic Setup

`agent-setup.sh` provides fully automated, non-interactive deployment for CI/CD pipelines and agent-driven installations.

```bash
# Full auto-install
./agent-setup.sh

# Check dependencies only (exit 0 if OK, exit 1 if missing)
./agent-setup.sh --check

# JSON output for machine parsing
./agent-setup.sh --json

# Generate API key for agent access
./agent-setup.sh --api-key

# Install + register as background service (systemd or launchd)
./agent-setup.sh --headless

# Combine flags
./agent-setup.sh --api-key --headless --json
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOKI_PORT` | `5150` | Override the dashboard/API port |
| `LOKI_HOST` | `0.0.0.0` | Override the bind address |
| `LOKI_NO_INSTALL` | `0` | Set to `1` to skip system package installation |
| `LOKI_API_KEY` | *(generated)* | Pre-set an API key instead of generating one |

### JSON Output

When `--json` is used, the final status is printed to stdout:

```json
{
  "status": "ok",
  "os": "linux",
  "package_manager": "apt",
  "port": 5150,
  "host": "0.0.0.0",
  "dashboard_url": "http://0.0.0.0:5150",
  "agent_api_base": "http://0.0.0.0:5150/api/v1/agent",
  "api_key": "your-generated-key-here",
  "dependencies": [...],
  "missing": [],
  "headless": false,
  "project_dir": "/opt/loki-vigilant"
}
```

## Agent API Reference

The Agent API provides full programmatic access to Loki Vigilant for integration with AI agents (ClaudeBot, OpenClaw), automation tools, CI/CD pipelines, and custom dashboards.

**Base URL:** `http://<host>:5150/api/v1/agent`

### Authentication

All agent API endpoints require authentication via API key. Generate a key during setup:

```bash
./agent-setup.sh --api-key
```

Include the key in requests using either method:

```bash
# Bearer token (recommended)
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:5150/api/v1/agent/status

# Query parameter
curl http://localhost:5150/api/v1/agent/status?api_key=YOUR_API_KEY
```

### Response Format

All responses use a consistent envelope:

```json
// Success
{ "ok": true, "data": { ... } }

// Error
{ "ok": false, "error": "Human-readable message", "code": "ERROR_CODE" }
```

### Error Codes

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| `NO_API_KEY` | 503 | API key not configured on the server |
| `UNAUTHORIZED` | 401 | Invalid or missing API key |
| `NOT_FOUND` | 404 | Requested resource does not exist |
| `INVALID_INPUT` | 400 | Missing or invalid request parameters |
| `SCAN_FAILED` | 400 | Port scan encountered an error |

### Endpoints

#### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/status` | System health, network info, device count, intrusion stats, timestamp |

```bash
curl -H "Authorization: Bearer $KEY" http://localhost:5150/api/v1/agent/status
```

#### Devices

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/devices` | List all devices. Filters: `?type=phone`, `?tag=auto-scan`, `?new=1` |
| `GET` | `/devices/<mac>` | Device detail with scan history and tags |
| `PUT` | `/devices/<mac>/nickname` | Set device nickname. Body: `{"nickname": "..."}` |
| `GET` | `/devices/<mac>/tags` | Get device tags |
| `PUT` | `/devices/<mac>/tags` | Replace all tags. Body: `{"tags": ["auto-scan", "critical"]}` |
| `POST` | `/devices/<mac>/tags` | Add a single tag (idempotent). Body: `{"tag": "auto-scan"}` |
| `DELETE` | `/devices/<mac>/tags/<tag>` | Remove a specific tag |

```bash
# List all phones
curl -H "Authorization: Bearer $KEY" "http://localhost:5150/api/v1/agent/devices?type=phone"

# Get device details
curl -H "Authorization: Bearer $KEY" http://localhost:5150/api/v1/agent/devices/aa:bb:cc:dd:ee:ff

# Tag a device
curl -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"tag": "critical"}' \
  http://localhost:5150/api/v1/agent/devices/aa:bb:cc:dd:ee:ff/tags
```

#### Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan/discover` | Trigger network discovery (ARP + nmap ping). Synchronous, ~10-30s |
| `POST` | `/scan/port` | Port scan a device. Body: `{"ip": "...", "mac": "..."}`. Synchronous, ~1-5min |

```bash
# Discover all devices on the network
curl -X POST -H "Authorization: Bearer $KEY" http://localhost:5150/api/v1/agent/scan/discover

# Port scan a specific device
curl -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}' \
  http://localhost:5150/api/v1/agent/scan/port
```

#### Intrusions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/intrusions` | Paginated intrusion log. Query: `?limit=50&offset=0` (max 500) |
| `GET` | `/intrusions/active` | Currently active inbound scans |
| `GET` | `/intrusions/stats` | Total attempts, last attempt summary |

```bash
# Get latest 10 intrusion attempts
curl -H "Authorization: Bearer $KEY" "http://localhost:5150/api/v1/agent/intrusions?limit=10"

# Check for active scans right now
curl -H "Authorization: Bearer $KEY" http://localhost:5150/api/v1/agent/intrusions/active
```

#### Vulnerabilities

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/vulnerabilities` | All CVEs across all devices. Query: `?severity=CRITICAL&limit=100` |

```bash
# Get all critical vulnerabilities
curl -H "Authorization: Bearer $KEY" "http://localhost:5150/api/v1/agent/vulnerabilities?severity=CRITICAL"
```

#### Network

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/network` | Interface, subnet, gateway, and interface statistics |

#### Settings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/settings` | Read current settings (auto_scan_policy) |
| `PUT` | `/settings` | Update settings. Body: `{"auto_scan_policy": "all"}` |

Valid `auto_scan_policy` values: `all`, `new`, `scanners`, `tagged`, `none`

#### Bulk Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/bulk/tag` | Tag multiple devices. Body: `{"macs": [...], "tag": "critical"}` |
| `POST` | `/bulk/scan` | Port scan multiple devices sequentially. Body: `{"macs": [...]}` |

```bash
# Tag multiple devices as critical
curl -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"macs": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"], "tag": "critical"}' \
  http://localhost:5150/api/v1/agent/bulk/tag
```

### Agent Integration Guide

This section provides step-by-step instructions for AI agents (ClaudeBot, OpenClaw, or similar) to autonomously set up, configure, and operate Loki Vigilant.

#### Step 1: Install and Configure

```bash
# Clone the repository
git clone https://github.com/fxspeiser/loki-vigilant.git
cd loki-vigilant

# Run automated setup with API key generation, output JSON status
./agent-setup.sh --api-key --json
```

Parse the JSON output to extract `api_key` and `agent_api_base`. If the `status` field is not `"ok"`, check the `missing` array for unresolved dependencies.

For persistent background operation:

```bash
./agent-setup.sh --api-key --headless --json
```

This registers Loki Vigilant as a systemd service (Linux) or LaunchAgent (macOS) that auto-starts on boot.

#### Step 2: Verify the System

```bash
curl -H "Authorization: Bearer $API_KEY" http://localhost:5150/api/v1/agent/status
```

Confirm `ok` is `true`. The response includes `device_count`, `intrusion_stats`, and `network` details.

#### Step 3: Discover the Network

```bash
curl -X POST -H "Authorization: Bearer $API_KEY" http://localhost:5150/api/v1/agent/scan/discover
```

This returns all discovered devices with MAC address, IP, hostname, vendor, and classified device type. The discovery scan takes 10-30 seconds.

#### Step 4: Scan for Vulnerabilities

Scan individual devices:

```bash
curl -X POST -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}' \
  http://localhost:5150/api/v1/agent/scan/port
```

Or scan multiple devices:

```bash
curl -X POST -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"macs": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]}' \
  http://localhost:5150/api/v1/agent/bulk/scan
```

Port scans are synchronous and take 1-5 minutes per device. Results include open ports, services, OS detection, and CVEs with CVSS scores.

#### Step 5: Monitor for Intrusions

```bash
# Check for active scans
curl -H "Authorization: Bearer $API_KEY" http://localhost:5150/api/v1/agent/intrusions/active

# Get intrusion history
curl -H "Authorization: Bearer $API_KEY" "http://localhost:5150/api/v1/agent/intrusions?limit=50"
```

Each intrusion record includes `source_ip`, `hostname`, `scan_type`, `scan_type_key`, `ports_hit`, `targets`, `spoof_status` (`verified`, `suspicious`, `likely_spoofed`, `unknown`), and `spoof_reasons` (array of human-readable verification check results).

#### Step 6: Configure Auto-Scan Policy

```bash
curl -X PUT -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"auto_scan_policy": "tagged"}' \
  http://localhost:5150/api/v1/agent/settings
```

Then tag the devices that should be auto-scanned on intrusion detection:

```bash
curl -X POST -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"macs": ["aa:bb:cc:dd:ee:ff"], "tag": "auto-scan"}' \
  http://localhost:5150/api/v1/agent/bulk/tag
```

#### Step 7: Retrieve Vulnerability Report

```bash
# All critical and high severity CVEs across the network
curl -H "Authorization: Bearer $API_KEY" "http://localhost:5150/api/v1/agent/vulnerabilities?severity=CRITICAL"
curl -H "Authorization: Bearer $API_KEY" "http://localhost:5150/api/v1/agent/vulnerabilities?severity=HIGH"
```

Each vulnerability includes `vuln_id` (CVE), `severity`, `port`, `service`, `version`, `device_mac`, `device_ip`, `device_name`, and `scan_time`.

#### Recommended Agent Workflow

1. **On deployment:** Run `agent-setup.sh --api-key --headless --json`, store the API key
2. **Periodically (hourly):** Call `POST /scan/discover` to keep the device list fresh
3. **On new devices:** Call `GET /devices?new=1`, then `POST /scan/port` for each
4. **Daily:** Call `GET /vulnerabilities?severity=CRITICAL` and `GET /vulnerabilities?severity=HIGH` to check for new CVEs
5. **Continuously:** Poll `GET /intrusions/active` (or monitor WebSocket events) for real-time intrusion detection
6. **On intrusion detected:** Call `GET /intrusions?limit=1` for details, assess `spoof_status`, optionally trigger additional scans

## Project Structure

```
loki-vigilant/
├── app.py                      # Flask + SocketIO server, API routes, auto-scan, inspection
├── run.sh                      # One-command launcher (auto-runs setup if needed)
├── setup.sh                    # Interactive dependency checker & install wizard
├── agent-setup.sh              # Automated non-interactive setup for agents/CI
├── package.json                # npm package configuration
├── requirements.txt            # Python dependencies
├── backend/
│   ├── db.py                   # SQLite persistence (devices, scans, vulns, intrusions, settings)
│   ├── scanner.py              # ARP, nmap discovery, port scan, OS detection, classification
│   ├── packet_monitor.py       # Live tcpdump capture + DNS query tracking
│   ├── intrusion_detector.py   # Inbound scan detection, spoof analysis, reverse DNS
│   ├── traffic_inspector.py    # Per-device packet capture with payload inspection
│   └── agent_api.py            # Agent REST API (Blueprint) with auth
├── frontend/
│   ├── templates/
│   │   ├── index.html          # Dashboard (devices, malicious scans, intrusion log tabs)
│   │   └── inspect.html        # Traffic inspector page
│   └── static/
│       ├── style.css           # Dark theme UI
│       ├── app.js              # Dashboard frontend with WebSocket
│       ├── inspect.css         # Traffic inspector styles
│       └── inspect.js          # Traffic inspector frontend
├── bin/
│   └── loki-vigilant           # CLI launcher for npm global install
├── scripts/
│   └── postinstall.js          # npm post-install instructions
├── rpm/
│   ├── loki-vigilant.spec      # RPM package spec
│   └── build-rpm.sh            # RPM build script
└── .github/
    └── workflows/
        └── publish-packages.yml  # CI: security check + npm + RPM publishing
```

## How It Works

| Layer | Tool | Purpose |
|-------|------|---------|
| Discovery | `arp -a`, `nmap -sn` | Find devices on the LAN |
| Classification | hostname, MAC vendor, OS fingerprint, open ports | Identify device types automatically |
| Packet capture | `tcpdump -e -l -n -q` | Track per-device traffic in real time |
| Traffic inspection | `tcpdump -A -s 0 host <ip>` | Full payload capture for a specific device |
| DNS tracking | `tcpdump udp port 53` | Monitor which domains each device queries |
| Activity window | Rolling 60s deque | Rank devices by recent activity |
| Interface stats | `netstat -ib` (macOS), `/proc/net/dev` (Linux) | Aggregate bandwidth |
| Port scanning | `nmap -sS -O -sV --script=vulners` | Stealth SYN scan + OS detection + CVE lookup |
| Intrusion detection | `tcpdump -v tcp or udp` | Detect inbound port scans from external IPs |
| Spoof verification | TTL analysis, FCrDNS, TCP flag analysis | Assess if scanner IP is genuine |
| Persistence | SQLite | Devices, nicknames, scans, vulnerabilities, intrusion log, settings |
| Real-time push | Flask-SocketIO | Live traffic, DNS, intrusion, and scan updates to the browser |
| Agent API | Flask Blueprint + Bearer auth | Programmatic access for bots and automation |

## Packaging

### npm (GitHub Packages)

Published automatically on GitHub Release via CI. Install globally for the `loki-vigilant` CLI:

```bash
npm install -g @fxspeiser/loki-vigilant
```

### RPM

Build locally:

```bash
./rpm/build-rpm.sh
# Output: dist/loki-vigilant-1.0.0-1.noarch.rpm
```

RPMs are also attached to GitHub Releases automatically via CI.

### CLI Commands (npm / RPM)

```bash
loki-vigilant setup          # Interactive setup wizard
loki-vigilant agent-setup    # Automated setup (--api-key, --headless, --json, --check)
loki-vigilant start          # Start the dashboard
loki-vigilant status         # Check dependencies (JSON output)
loki-vigilant version        # Show version
```

## Security Notes

- The dashboard binds to `0.0.0.0:5150` — restrict access via firewall if needed, or change to `127.0.0.1` in `app.py`
- The agent API requires a Bearer token — generate one via `./agent-setup.sh --api-key`
- API keys are stored in the SQLite database and in `.api_key` (chmod 600)
- Port scans use `-T3` timing (normal) to avoid flooding target devices
- OS detection (`-O`) requires root privileges and sends additional probes to the target
- All scans are intended for **your own network only** — do not scan networks you don't own or have authorization to test
- Intrusion detection is passive (monitoring only) and does not block or respond to detected scans
- The traffic inspector captures cleartext payloads — encrypted traffic (HTTPS, SSH) is labeled but cannot be decoded without session keys

## License

MIT
