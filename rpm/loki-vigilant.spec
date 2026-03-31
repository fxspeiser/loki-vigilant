Name:           loki-vigilant
Version:        1.0.0
Release:        1%{?dist}
Summary:        Real-time home network security monitor
License:        MIT
URL:            https://github.com/fxspeiser/loki-vigilant
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

Requires:       python3 >= 3.9
Requires:       nmap
Requires:       tcpdump
Requires:       python3-pip

%description
Loki Vigilant is a real-time home network security monitoring tool with a web
dashboard. It discovers devices on your LAN, classifies them automatically,
tracks live traffic per device, monitors DNS queries, detects inbound port
scans from external sources, and runs stealth port scans with OS fingerprinting
and vulnerability detection.

Features include an agent API for integration with ClaudeBot, OpenClaw, and
other automation tools.

%prep
%setup -q

%install
# Application directory
install -d %{buildroot}/opt/%{name}
install -d %{buildroot}/opt/%{name}/backend
install -d %{buildroot}/opt/%{name}/frontend/templates
install -d %{buildroot}/opt/%{name}/frontend/static

# Python source
install -m 644 app.py %{buildroot}/opt/%{name}/
install -m 644 requirements.txt %{buildroot}/opt/%{name}/
install -m 644 backend/*.py %{buildroot}/opt/%{name}/backend/

# Frontend
install -m 644 frontend/templates/*.html %{buildroot}/opt/%{name}/frontend/templates/
install -m 644 frontend/static/*.js %{buildroot}/opt/%{name}/frontend/static/
install -m 644 frontend/static/*.css %{buildroot}/opt/%{name}/frontend/static/

# Scripts
install -m 755 run.sh %{buildroot}/opt/%{name}/
install -m 755 setup.sh %{buildroot}/opt/%{name}/
install -m 755 agent-setup.sh %{buildroot}/opt/%{name}/

# CLI symlink
install -d %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/%{name} << 'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="/opt/loki-vigilant"

case "${1:-help}" in
    start)        cd "$INSTALL_DIR" && exec bash run.sh ;;
    setup)        cd "$INSTALL_DIR" && exec bash setup.sh ;;
    agent-setup)  cd "$INSTALL_DIR" && shift && exec bash agent-setup.sh "$@" ;;
    status)       cd "$INSTALL_DIR" && exec bash agent-setup.sh --check --json ;;
    version)      echo "%{version}" ;;
    help|--help|-h)
        echo "Usage: %{name} <command> [options]"
        echo ""
        echo "Commands: start, setup, agent-setup, status, version"
        ;;
    *)
        echo "Unknown command: $1" >&2
        exit 1
        ;;
esac
LAUNCHER
chmod 755 %{buildroot}%{_bindir}/%{name}

# Systemd service unit
install -d %{buildroot}/usr/lib/systemd/system
cat > %{buildroot}/usr/lib/systemd/system/%{name}.service << 'SERVICE'
[Unit]
Description=Loki Vigilant - Network Security Monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/loki-vigilant
ExecStartPre=/opt/loki-vigilant/agent-setup.sh --check
ExecStart=/opt/loki-vigilant/venv/bin/python /opt/loki-vigilant/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

%post
# Create venv and install Python deps on first install
if [ ! -d /opt/%{name}/venv ]; then
    echo "Setting up Python virtual environment..."
    python3 -m venv /opt/%{name}/venv
    /opt/%{name}/venv/bin/pip install -q -r /opt/%{name}/requirements.txt
fi

# Initialize database
/opt/%{name}/venv/bin/python -c "
import sys; sys.path.insert(0, '/opt/%{name}')
from backend.db import init_db
init_db()
" 2>/dev/null || true

# Reload systemd
systemctl daemon-reload

echo ""
echo "Loki Vigilant installed to /opt/%{name}"
echo ""
echo "  Start:  sudo systemctl start %{name}"
echo "  Enable: sudo systemctl enable %{name}"
echo "  CLI:    %{name} start"
echo ""

%preun
# Stop service before uninstall
systemctl stop %{name} 2>/dev/null || true
systemctl disable %{name} 2>/dev/null || true

%postun
systemctl daemon-reload

%files
%license LICENSE
%doc README.md
/opt/%{name}/
%{_bindir}/%{name}
/usr/lib/systemd/system/%{name}.service
