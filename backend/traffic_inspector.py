"""Targeted per-device traffic capture with payload inspection."""

import subprocess
import threading
import re
import time
import platform
from collections import defaultdict
from datetime import datetime
from backend.scanner import get_default_interface


class TrafficInspector:
    """Captures full packet data for a single device and streams it."""

    def __init__(self, target_ip, emit_callback):
        self.target_ip = target_ip
        self.emit = emit_callback
        self.running = False
        self.process = None
        self.thread = None
        self._lock = threading.Lock()
        # Per-peer stats: remote_ip -> {packets, bytes, first_seen, last_seen, inbound, outbound}
        self.peer_stats = defaultdict(lambda: {
            'packets': 0, 'bytes': 0,
            'inbound_packets': 0, 'inbound_bytes': 0,
            'outbound_packets': 0, 'outbound_bytes': 0,
            'first_seen': None, 'last_seen': None,
        })
        self._packet_count = 0

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._capture, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        if self.thread:
            self.thread.join(timeout=3)

    def get_peer_stats(self):
        with self._lock:
            return {ip: dict(s) for ip, s in self.peer_stats.items()}

    def _capture(self):
        iface, _, _ = get_default_interface()

        # Capture packets to/from target with full payload
        # -A prints ASCII payload, -s 0 captures full packets,
        # -l line-buffered, -n no DNS resolution
        cmd = [
            'tcpdump', '-i', iface, '-l', '-n', '-A', '-s', '0',
            'host', self.target_ip
        ]

        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
        except (PermissionError, FileNotFoundError) as e:
            self.emit('inspect_error', {
                'ip': self.target_ip,
                'error': f'tcpdump failed: {e}'
            })
            self.running = False
            return

        current_packet = None
        payload_lines = []

        while self.running and self.process.poll() is None:
            line = self.process.stdout.readline()
            if not line:
                continue

            line = line.rstrip('\n')

            # tcpdump -A output: packet header lines start with a timestamp,
            # payload lines follow until the next header
            header = self._parse_header(line)
            if header:
                # Emit previous packet if we have one
                if current_packet:
                    self._finalize_and_emit(current_packet, payload_lines)
                current_packet = header
                payload_lines = []
            elif current_packet:
                payload_lines.append(line)

        # Emit last packet
        if current_packet:
            self._finalize_and_emit(current_packet, payload_lines)

    def _parse_header(self, line):
        """Parse a tcpdump packet header line.

        Format: HH:MM:SS.usec IP src.port > dst.port: flags, ...  length N
        """
        # Match the tcpdump header pattern
        m = re.match(
            r'(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
            r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+'
            r'(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+'
            r'(.*)',
            line
        )
        if not m:
            return None

        timestamp = m.group(1)
        src_ip = m.group(2)
        src_port = int(m.group(3))
        dst_ip = m.group(4)
        dst_port = int(m.group(5))
        remainder = m.group(6)

        # Extract protocol indicators and length
        proto = 'TCP'
        flags = ''
        length = 0

        if 'UDP' in remainder or 'udp' in line:
            proto = 'UDP'

        flag_m = re.search(r'Flags \[([^\]]*)\]', remainder)
        if flag_m:
            flags = flag_m.group(1)

        len_m = re.search(r'length\s+(\d+)', remainder)
        if len_m:
            length = int(len_m.group(1))

        # Determine direction relative to our target
        if src_ip == self.target_ip:
            direction = 'outbound'
            peer_ip = dst_ip
        else:
            direction = 'inbound'
            peer_ip = src_ip

        return {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'proto': proto,
            'flags': flags,
            'length': length,
            'direction': direction,
            'peer_ip': peer_ip,
        }

    def _finalize_and_emit(self, packet, payload_lines):
        """Process payload and emit the packet."""
        self._packet_count += 1
        now = datetime.now().isoformat()

        # Build payload — filter out hex dump lines, keep ASCII-readable content
        payload_text = self._extract_readable_payload(payload_lines)

        # Detect protocol/content from ports and payload
        service = self._identify_service(
            packet['src_port'], packet['dst_port'], payload_text
        )

        # Determine if traffic is encrypted
        encrypted = self._is_encrypted(
            packet['src_port'], packet['dst_port'], payload_text, payload_lines
        )

        packet['payload'] = payload_text[:2000]  # cap payload size
        packet['service'] = service
        packet['encrypted'] = encrypted
        packet['time'] = now
        packet['id'] = self._packet_count

        # Update peer stats
        peer = packet['peer_ip']
        with self._lock:
            s = self.peer_stats[peer]
            s['packets'] += 1
            s['bytes'] += packet['length']
            s['last_seen'] = now
            if not s['first_seen']:
                s['first_seen'] = now
            if packet['direction'] == 'inbound':
                s['inbound_packets'] += 1
                s['inbound_bytes'] += packet['length']
            else:
                s['outbound_packets'] += 1
                s['outbound_bytes'] += packet['length']

        # Emit to frontend
        self.emit('inspect_packet', {
            'ip': self.target_ip,
            'packet': packet,
        })

        # Emit peer stats periodically (every 10 packets)
        if self._packet_count % 10 == 0:
            self.emit('inspect_peers', {
                'ip': self.target_ip,
                'peers': self.get_peer_stats(),
            })

    def _extract_readable_payload(self, lines):
        """Extract human-readable content from tcpdump -A payload lines."""
        if not lines:
            return ''

        readable = []
        for line in lines:
            # Skip empty lines and hex-only lines
            if not line.strip():
                continue
            # tcpdump -A shows ASCII with dots for non-printable chars
            # Skip lines that are mostly non-printable (ethernet/IP headers)
            printable_ratio = sum(1 for c in line if c.isprintable()) / max(len(line), 1)
            if printable_ratio > 0.6 and len(line.strip()) > 1:
                readable.append(line)

        return '\n'.join(readable)

    def _identify_service(self, src_port, dst_port, payload):
        """Identify the application-layer service from ports and payload."""
        ports = {src_port, dst_port}
        pl = payload[:500].lower() if payload else ''

        # HTTP
        if 80 in ports or 8080 in ports or 8000 in ports:
            if any(kw in pl for kw in ['http/', 'get ', 'post ', 'put ', 'host:', 'content-type']):
                return 'HTTP'
            return 'HTTP'
        if 443 in ports or 8443 in ports:
            return 'HTTPS/TLS'

        # DNS
        if 53 in ports:
            return 'DNS'

        # Mail
        if 25 in ports or 587 in ports:
            return 'SMTP'
        if 993 in ports or 143 in ports:
            return 'IMAP'
        if 995 in ports or 110 in ports:
            return 'POP3'

        # SSH/SFTP
        if 22 in ports:
            return 'SSH'

        # FTP
        if 21 in ports or 20 in ports:
            return 'FTP'

        # MDNS
        if 5353 in ports:
            return 'mDNS'

        # NTP
        if 123 in ports:
            return 'NTP'

        # DHCP
        if 67 in ports or 68 in ports:
            return 'DHCP'

        # MQTT
        if 1883 in ports or 8883 in ports:
            return 'MQTT'

        # Various TLS ports
        if any(p in ports for p in [465, 636, 989, 990, 992, 5061]):
            return 'TLS'

        # Payload-based detection
        if payload:
            if pl.startswith('get ') or pl.startswith('post ') or 'http/' in pl[:20]:
                return 'HTTP'
            if 'ssh-' in pl[:20]:
                return 'SSH'
            if pl.startswith('220 ') or 'smtp' in pl[:50]:
                return 'SMTP'

        return 'Unknown'

    def _is_encrypted(self, src_port, dst_port, payload, raw_lines):
        """Determine if the traffic appears to be encrypted."""
        ports = {src_port, dst_port}

        # Known encrypted ports
        encrypted_ports = {443, 8443, 465, 636, 989, 990, 992, 993, 995, 5061, 8883}
        if ports & encrypted_ports:
            return True

        # SSH
        if 22 in ports:
            return True

        # Check for TLS handshake signature in raw payload
        if raw_lines:
            joined = ''.join(raw_lines[:5])
            # TLS record starts with 0x16 (handshake) or 0x17 (application data)
            if any(c in joined[:10] for c in ['\x16\x03', '\x17\x03']):
                return True

        # High entropy / low printable ratio suggests encryption
        if payload and len(payload) > 20:
            printable = sum(1 for c in payload if c.isprintable() and c != '.')
            ratio = printable / len(payload)
            if ratio < 0.3:
                return True

        return False
