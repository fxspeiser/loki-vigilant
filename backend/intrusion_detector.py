"""Detect inbound port scans from external sources."""

import subprocess
import threading
import re
import socket
import time
from collections import defaultdict
from datetime import datetime
from backend.scanner import get_default_interface


# Scan type detection based on TCP flags
SCAN_TYPES = {
    'SYN': 'SYN Stealth Scan',
    'FIN': 'FIN Scan',
    'XMAS': 'XMAS Scan',
    'NULL': 'NULL Scan',
    'ACK': 'ACK Scan',
    'CONNECT': 'TCP Connect Scan',
    'UDP': 'UDP Scan',
    'UNKNOWN': 'Unknown Scan',
}

# Thresholds
SCAN_PORT_THRESHOLD = 8       # ports hit from same source = scan
SCAN_WINDOW_SECONDS = 30      # within this time window
ACTIVE_SCAN_TIMEOUT = 60      # scan considered "active" for this long after last packet
COOLDOWN_SECONDS = 120        # don't re-alert same source within this period

# Spoof detection
SPOOF_STATUS_VERIFIED = 'verified'       # IP appears legitimate
SPOOF_STATUS_LIKELY_SPOOFED = 'likely_spoofed'  # strong indicators of spoofing
SPOOF_STATUS_SUSPICIOUS = 'suspicious'   # some anomalies
SPOOF_STATUS_UNKNOWN = 'unknown'         # not enough data


class IntrusionDetector:
    """Monitors network for inbound port scan attempts."""

    def __init__(self, on_scan_detected=None, on_scan_ended=None):
        self.running = False
        self._thread = None
        self._process = None
        self._lock = threading.Lock()

        # Callbacks
        self.on_scan_detected = on_scan_detected
        self.on_scan_ended = on_scan_ended

        # Tracking: ext_ip -> list of (mono_time, local_ip, port, scan_type_hint, ttl)
        self._probe_window = defaultdict(list)

        # Confirmed active scans: ext_ip -> {start, last_seen, scan_type, ports_hit, targets, ...}
        self._active_scans = {}

        # Completed scan events: list of dicts
        self._scan_log = []

        # Cooldown: ext_ip -> mono_time of last alert
        self._cooldown = {}

        # DNS cache: ip -> hostname (or '' if lookup failed)
        self._dns_cache = {}
        self._dns_cache_ttl = {}  # ip -> mono_time of lookup

        # Analysis thread
        self._analysis_thread = None

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._capture, daemon=True)
        self._thread.start()
        self._analysis_thread = threading.Thread(target=self._analyze_loop, daemon=True)
        self._analysis_thread.start()

    def stop(self):
        self.running = False
        if self._process:
            self._process.terminate()
        if self._thread:
            self._thread.join(timeout=3)

    def get_active_scans(self):
        """Return currently active inbound scans."""
        with self._lock:
            now = time.monotonic()
            active = {}
            for ip, info in self._active_scans.items():
                if now - info['last_seen_mono'] < ACTIVE_SCAN_TIMEOUT:
                    active[ip] = {
                        'source_ip': ip,
                        'hostname': info.get('hostname', ''),
                        'scan_type': info['scan_type'],
                        'ports_hit': info['ports_hit'],
                        'targets': list(info['targets']),
                        'start': info['start'],
                        'last_seen': info['last_seen'],
                        'duration_sec': int(now - info['start_mono']),
                        'spoof_status': info.get('spoof_status', SPOOF_STATUS_UNKNOWN),
                        'spoof_reasons': info.get('spoof_reasons', []),
                    }
            return active

    def get_scan_log(self):
        """Return completed scan log."""
        with self._lock:
            return list(self._scan_log)

    # --- DNS resolution ---

    def _resolve_hostname(self, ip):
        """Reverse DNS lookup with caching (5-minute TTL)."""
        now = time.monotonic()
        cache_ttl = self._dns_cache_ttl.get(ip, 0)
        if ip in self._dns_cache and now - cache_ttl < 300:
            return self._dns_cache[ip]

        hostname = ''
        try:
            result = socket.gethostbyaddr(ip)
            hostname = result[0] if result else ''
        except (socket.herror, socket.gaierror, OSError):
            pass

        self._dns_cache[ip] = hostname
        self._dns_cache_ttl[ip] = now
        return hostname

    def _resolve_hostname_async(self, ip, callback):
        """Run DNS resolution in a background thread to avoid blocking."""
        def _do_resolve():
            hostname = self._resolve_hostname(ip)
            if callback:
                callback(ip, hostname)
        threading.Thread(target=_do_resolve, daemon=True).start()

    # --- Spoof detection ---

    def _assess_spoofing(self, src_ip, probes):
        """Analyze probe characteristics to determine if the source IP may be spoofed.

        Checks:
        1. TTL consistency — spoofed packets often have inconsistent TTLs
        2. Scan type — SYN-only (no handshake) scans are easier to spoof
        3. Source port patterns — random vs sequential source ports
        4. Reverse DNS — legitimate scanners often have rDNS
        5. TTL plausibility — very low or unusual TTL values
        """
        reasons = []
        score = 0  # higher = more likely spoofed

        # Extract TTLs from probes
        ttls = [p[4] for p in probes if p[4] is not None]

        # 1. TTL consistency check
        if len(ttls) >= 3:
            unique_ttls = set(ttls)
            if len(unique_ttls) > 3:
                reasons.append(f'Inconsistent TTL values ({len(unique_ttls)} unique): likely spoofed or multi-path')
                score += 3
            elif len(unique_ttls) == 1:
                # Consistent TTL is a good sign
                score -= 1

            # Check for implausible TTLs
            for ttl in unique_ttls:
                if ttl <= 2:
                    reasons.append(f'Implausibly low TTL ({ttl}): likely spoofed')
                    score += 4
                elif ttl > 200:
                    reasons.append(f'Unusually high TTL ({ttl}): suspicious')
                    score += 1

        # 2. Scan type assessment
        scan_types = set(p[3] for p in probes)
        if scan_types <= {'SYN'}:
            # Pure SYN scan — easy to spoof (no handshake needed)
            reasons.append('SYN-only scan (no TCP handshake required, easy to spoof)')
            score += 1
        elif 'CONNECT' in scan_types:
            # Connect scan requires full handshake — very hard to spoof
            reasons.append('TCP Connect scan detected (requires handshake, hard to spoof)')
            score -= 3

        # 3. Source port analysis
        src_ports = [p[2] for p in probes]
        if len(src_ports) >= 5:
            sorted_ports = sorted(set(src_ports))
            # Check for sequential source ports (legitimate scanners often use sequential)
            sequential = sum(1 for i in range(1, len(sorted_ports))
                           if sorted_ports[i] - sorted_ports[i-1] <= 2)
            if sequential > len(sorted_ports) * 0.5:
                reasons.append('Sequential source ports (consistent with real scanner)')
                score -= 1

        # 4. Reverse DNS check
        hostname = self._resolve_hostname(src_ip)
        if hostname:
            # Check if forward DNS matches reverse DNS
            try:
                forward_ips = socket.getaddrinfo(hostname, None)
                forward_ip_set = set(addr[4][0] for addr in forward_ips)
                if src_ip in forward_ip_set:
                    reasons.append(f'Forward-confirmed rDNS: {hostname}')
                    score -= 2
                else:
                    reasons.append(f'rDNS mismatch: {hostname} does not resolve back to {src_ip}')
                    score += 2
            except (socket.gaierror, OSError):
                reasons.append(f'rDNS found ({hostname}) but forward lookup failed')
                score += 1
        else:
            reasons.append('No reverse DNS record')
            score += 1

        # Determine status
        if score >= 4:
            status = SPOOF_STATUS_LIKELY_SPOOFED
        elif score >= 2:
            status = SPOOF_STATUS_SUSPICIOUS
        elif score <= -1:
            status = SPOOF_STATUS_VERIFIED
        else:
            status = SPOOF_STATUS_UNKNOWN

        return status, reasons, hostname

    # --- Capture ---

    def _capture(self):
        """Run tcpdump to capture inbound TCP probes and UDP scans."""
        iface, subnet, _ = get_default_interface()

        # Use -v to get TTL info for spoof detection
        cmd = [
            'tcpdump', '-i', iface, '-l', '-n', '-tt', '-v',
            'tcp or udp',
        ]

        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
        except (PermissionError, FileNotFoundError):
            print("WARNING: Intrusion detector tcpdump failed to start.")
            return

        while self.running and self._process.poll() is None:
            line = self._process.stdout.readline()
            if not line:
                continue
            self._parse_probe(line.strip())

    def _parse_probe(self, line):
        """Parse tcpdump line for potential scan probes.

        With -v flag, output includes TTL:
        1709912345.123456 IP (tos 0x0, ttl 64, ...) 203.0.113.5.54321 > 192.168.1.100.22: Flags [S], ...
        """
        # Extract src and dst with ports
        m = re.search(
            r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)',
            line
        )
        if not m:
            return

        src_ip = m.group(1)
        src_port = int(m.group(2))
        dst_ip = m.group(3)
        dst_port = int(m.group(4))

        # Only care about external -> local
        if self._is_local(src_ip) or not self._is_local(dst_ip):
            return

        # Extract TTL
        ttl = None
        ttl_match = re.search(r'ttl\s+(\d+)', line)
        if ttl_match:
            ttl = int(ttl_match.group(1))

        # Determine scan type hint from flags
        scan_hint = 'UNKNOWN'
        flags_match = re.search(r'Flags \[([^\]]+)\]', line)
        if flags_match:
            flags = flags_match.group(1)
            if flags == 'S':
                scan_hint = 'SYN'
            elif flags == 'F':
                scan_hint = 'FIN'
            elif flags in ('FPU', 'FP', 'FU', 'PU'):
                scan_hint = 'XMAS'
            elif flags == 'none' or flags == '.':
                if flags == 'none':
                    scan_hint = 'NULL'
                else:
                    scan_hint = 'ACK'
            elif 'S' in flags and 'A' not in flags:
                scan_hint = 'SYN'
        elif 'UDP' in line:
            scan_hint = 'UDP'
        else:
            scan_hint = 'CONNECT'

        mono = time.monotonic()

        with self._lock:
            self._probe_window[src_ip].append((mono, dst_ip, dst_port, scan_hint, ttl))

    def _analyze_loop(self):
        """Periodically analyze probe data for scan patterns."""
        while self.running:
            time.sleep(2)
            self._analyze()

    def _analyze(self):
        """Check if any external IP is scanning us."""
        now_mono = time.monotonic()
        now_ts = datetime.now().isoformat()

        with self._lock:
            # Prune old probes
            cutoff = now_mono - SCAN_WINDOW_SECONDS
            for ip in list(self._probe_window.keys()):
                self._probe_window[ip] = [
                    p for p in self._probe_window[ip] if p[0] >= cutoff
                ]
                if not self._probe_window[ip]:
                    del self._probe_window[ip]

            # Check for new scans
            for src_ip, probes in self._probe_window.items():
                unique_ports = set((p[1], p[2]) for p in probes)

                if len(unique_ports) >= SCAN_PORT_THRESHOLD:
                    # Determine dominant scan type
                    type_counts = defaultdict(int)
                    for p in probes:
                        type_counts[p[3]] += 1
                    scan_type = max(type_counts, key=type_counts.get)

                    targets = set(p[1] for p in probes)
                    ports_hit = len(unique_ports)

                    if src_ip in self._active_scans:
                        # Update existing active scan
                        active = self._active_scans[src_ip]
                        active['last_seen'] = now_ts
                        active['last_seen_mono'] = now_mono
                        active['ports_hit'] = max(active['ports_hit'], ports_hit)
                        active['targets'].update(targets)
                        active['scan_type'] = scan_type

                        # Re-assess spoofing periodically (every 10s)
                        if now_mono - active.get('last_spoof_check', 0) > 10:
                            status, reasons, hostname = self._assess_spoofing(src_ip, probes)
                            active['spoof_status'] = status
                            active['spoof_reasons'] = reasons
                            active['hostname'] = hostname
                            active['last_spoof_check'] = now_mono
                    else:
                        # Check cooldown
                        if src_ip in self._cooldown and now_mono - self._cooldown[src_ip] < COOLDOWN_SECONDS:
                            continue

                        # Assess spoofing for new scan
                        status, reasons, hostname = self._assess_spoofing(src_ip, probes)

                        # New scan detected
                        self._active_scans[src_ip] = {
                            'start': now_ts,
                            'start_mono': now_mono,
                            'last_seen': now_ts,
                            'last_seen_mono': now_mono,
                            'scan_type': scan_type,
                            'ports_hit': ports_hit,
                            'targets': targets,
                            'hostname': hostname,
                            'spoof_status': status,
                            'spoof_reasons': reasons,
                            'last_spoof_check': now_mono,
                        }
                        self._cooldown[src_ip] = now_mono

                        if self.on_scan_detected:
                            self.on_scan_detected({
                                'source_ip': src_ip,
                                'hostname': hostname,
                                'scan_type': SCAN_TYPES.get(scan_type, scan_type),
                                'scan_type_key': scan_type,
                                'ports_hit': ports_hit,
                                'targets': list(targets),
                                'start': now_ts,
                                'spoof_status': status,
                                'spoof_reasons': reasons,
                            })

            # Check for ended scans
            for src_ip in list(self._active_scans.keys()):
                info = self._active_scans[src_ip]
                if now_mono - info['last_seen_mono'] >= ACTIVE_SCAN_TIMEOUT:
                    # Scan ended
                    event = {
                        'source_ip': src_ip,
                        'hostname': info.get('hostname', ''),
                        'scan_type': SCAN_TYPES.get(info['scan_type'], info['scan_type']),
                        'scan_type_key': info['scan_type'],
                        'ports_hit': info['ports_hit'],
                        'targets': list(info['targets']),
                        'start': info['start'],
                        'end': now_ts,
                        'duration_sec': int(now_mono - info['start_mono']),
                        'spoof_status': info.get('spoof_status', SPOOF_STATUS_UNKNOWN),
                        'spoof_reasons': info.get('spoof_reasons', []),
                    }
                    self._scan_log.append(event)

                    if self.on_scan_ended:
                        self.on_scan_ended(event)

                    del self._active_scans[src_ip]

    @staticmethod
    def _is_local(ip):
        return (
            ip.startswith('192.168.') or
            ip.startswith('10.') or
            ip.startswith('172.16.') or ip.startswith('172.17.') or
            ip.startswith('172.18.') or ip.startswith('172.19.') or
            ip.startswith('172.2') or ip.startswith('172.30.') or
            ip.startswith('172.31.')
        )
