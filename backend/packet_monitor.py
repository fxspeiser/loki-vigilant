"""Live packet capture using tcpdump for per-device traffic tracking."""

import subprocess
import threading
import re
import platform
import time
from collections import defaultdict, deque
from datetime import datetime
from backend.db import update_device_traffic, upsert_device
from backend.scanner import get_default_interface


class PacketMonitor:
    """Captures packets via tcpdump and tracks per-IP stats."""

    def __init__(self):
        self.running = False
        self.thread = None
        self.process = None
        self._dns_thread = None
        self._dns_process = None
        # ip -> {packets, bytes, last_seen}
        self.live_stats = defaultdict(lambda: {
            'packets': 0, 'bytes': 0,
            'last_seen': None, 'bps': 0
        })
        self._lock = threading.Lock()
        self._flush_interval = 10  # flush to db every N seconds
        self._last_flush = datetime.now()
        self._pending = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        # mac_map: ip -> mac (populated by ARP scans)
        self.mac_map = {}
        # Rolling window: deque of (monotonic_time, ip, packet_count, byte_count)
        self._window = deque()
        self._window_seconds = 60
        # DNS tracking: ip -> deque of {domain, timestamp}
        self._dns_queries = defaultdict(lambda: deque(maxlen=50))
        self._dns_window_seconds = 300  # keep last 5 minutes of DNS

    def update_mac_map(self, devices):
        """Update IP-to-MAC mapping from discovered devices."""
        for d in devices:
            if d.get('ip') and d.get('mac'):
                self.mac_map[d['ip']] = d['mac']

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._capture, daemon=True)
        self.thread.start()
        self._dns_thread = threading.Thread(target=self._capture_dns, daemon=True)
        self._dns_thread.start()

    def stop(self):
        self.running = False
        if self.process:
            self.process.terminate()
        if self._dns_process:
            self._dns_process.terminate()
        if self.thread:
            self.thread.join(timeout=3)
        if self._dns_thread:
            self._dns_thread.join(timeout=3)

    def get_stats(self):
        with self._lock:
            self._prune_window()
            self._prune_dns()
            # Compute per-IP recent counts from the rolling window
            recent = defaultdict(lambda: {'packets': 0, 'bytes': 0})
            for _, ip, pkts, nbytes in self._window:
                recent[ip]['packets'] += pkts
                recent[ip]['bytes'] += nbytes
            result = {}
            for ip, s in self.live_stats.items():
                result[ip] = dict(s)
                r = recent.get(ip)
                result[ip]['recent_packets'] = r['packets'] if r else 0
                result[ip]['recent_bytes'] = r['bytes'] if r else 0
                # Include DNS queries for this IP (strip internal _mono key)
                dns = self._dns_queries.get(ip)
                if dns:
                    result[ip]['dns_queries'] = [
                        {'domain': e['domain'], 'time': e['time']} for e in dns
                    ]
                else:
                    result[ip]['dns_queries'] = []
            return result

    def _prune_window(self):
        cutoff = time.monotonic() - self._window_seconds
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()

    def _capture(self):
        iface, _, _ = get_default_interface()
        system = platform.system()

        cmd = ['tcpdump', '-i', iface, '-l', '-n', '-q', '-e']
        if system == 'Darwin':
            cmd.extend(['-tt'])  # unix timestamp

        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
        except PermissionError:
            # Try with sudo hint
            print("WARNING: tcpdump requires root. Run with sudo or grant permissions.")
            self.running = False
            return
        except FileNotFoundError:
            print("WARNING: tcpdump not found.")
            self.running = False
            return

        while self.running and self.process.poll() is None:
            line = self.process.stdout.readline()
            if not line:
                continue
            self._parse_line(line.strip())

            # Periodic flush to DB
            now = datetime.now()
            if (now - self._last_flush).seconds >= self._flush_interval:
                self._flush_to_db()
                self._last_flush = now

    def _parse_line(self, line):
        """Parse tcpdump output to extract src/dst IPs and packet size."""
        # Extract IPs from the line
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        ips = re.findall(ip_pattern, line)

        # Extract packet length
        length = 0
        len_match = re.search(r'length\s+(\d+)', line)
        if len_match:
            length = int(len_match.group(1))

        # Extract MAC addresses from ethernet header (tcpdump -e)
        mac_pattern = r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})'
        macs = re.findall(mac_pattern, line.lower())

        now = datetime.now().isoformat()

        mono = time.monotonic()

        with self._lock:
            # Track both src and dst local IPs
            local_ips = [ip for ip in ips if self._is_local(ip)]
            for ip in local_ips:
                self.live_stats[ip]['packets'] += 1
                self.live_stats[ip]['bytes'] += length
                self.live_stats[ip]['last_seen'] = now
                self._pending[ip]['packets'] += 1
                self._pending[ip]['bytes'] += length
                self._window.append((mono, ip, 1, length))

            # Update mac_map from captured MACs
            if len(macs) >= 2 and len(ips) >= 2:
                for i, ip in enumerate(ips[:2]):
                    if i < len(macs) and self._is_local(ip):
                        self.mac_map[ip] = macs[i]

    def _is_local(self, ip):
        """Check if IP is a private/local address."""
        return (
            ip.startswith('192.168.') or
            ip.startswith('10.') or
            ip.startswith('172.16.') or ip.startswith('172.17.') or
            ip.startswith('172.18.') or ip.startswith('172.19.') or
            ip.startswith('172.2') or ip.startswith('172.30.') or
            ip.startswith('172.31.')
        )

    def _prune_dns(self):
        """Remove DNS entries older than the window."""
        cutoff = time.monotonic() - self._dns_window_seconds
        for ip in list(self._dns_queries.keys()):
            dq = self._dns_queries[ip]
            while dq and dq[0].get('_mono', 0) < cutoff:
                dq.popleft()
            if not dq:
                del self._dns_queries[ip]

    def _capture_dns(self):
        """Capture DNS queries via a separate tcpdump process."""
        iface, _, _ = get_default_interface()

        cmd = ['tcpdump', '-i', iface, '-l', '-n', 'udp', 'port', '53']

        try:
            self._dns_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
        except (PermissionError, FileNotFoundError):
            print("WARNING: DNS capture tcpdump failed to start.")
            return

        while self.running and self._dns_process.poll() is None:
            line = self._dns_process.stdout.readline()
            if not line:
                continue
            self._parse_dns_line(line.strip())

    def _parse_dns_line(self, line):
        """Parse DNS query from tcpdump output.

        Typical format:
        14:23:01.123456 IP 192.168.1.100.52345 > 192.168.1.1.53: 12345+ A? example.com. (30)
        """
        # Match: src_ip.src_port > dst_ip.53: ... A? domain or AAAA? domain
        m = re.search(
            r'(\d+\.\d+\.\d+\.\d+)\.\d+\s+>\s+\d+\.\d+\.\d+\.\d+\.53:\s+.*?\s+(?:A\??|AAAA\??)\s+([^\s?]+)',
            line
        )
        if not m:
            return

        src_ip = m.group(1)
        domain = m.group(2).rstrip('.')

        if not self._is_local(src_ip):
            return

        # Skip internal/noise domains
        if self._is_noise_domain(domain):
            return

        mono = time.monotonic()
        now = datetime.now().isoformat()

        with self._lock:
            dq = self._dns_queries[src_ip]
            # Deduplicate: don't add if same domain was queried in last 10 seconds
            dominated = False
            for entry in reversed(dq):
                if mono - entry.get('_mono', 0) > 10:
                    break
                if entry['domain'] == domain:
                    dominated = True
                    break
            if not dominated:
                dq.append({'domain': domain, 'time': now, '_mono': mono})

    @staticmethod
    def _is_noise_domain(domain):
        """Filter out noisy internal/tracking domains."""
        noise_suffixes = (
            '.local', '.arpa', '.internal',
            '.home', '.lan', '.localdomain',
        )
        return any(domain.endswith(s) for s in noise_suffixes)

    def _flush_to_db(self):
        """Flush accumulated stats to the database."""
        with self._lock:
            pending = dict(self._pending)
            self._pending.clear()

        for ip, stats in pending.items():
            mac = self.mac_map.get(ip)
            if mac:
                update_device_traffic(mac, stats['packets'], stats['bytes'])
