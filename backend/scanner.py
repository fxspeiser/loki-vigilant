"""Network scanning utilities using native OS tools and nmap."""

import subprocess
import platform
import re
import socket
import json
import nmap
from backend.db import upsert_device, save_port_scan, save_vulnerability, update_device_type, get_device


def get_default_interface():
    """Get the default network interface and subnet."""
    system = platform.system()
    try:
        if system == 'Darwin':
            route = subprocess.check_output(
                ['route', '-n', 'get', 'default'], text=True, timeout=5
            )
            iface = re.search(r'interface:\s*(\S+)', route)
            gateway = re.search(r'gateway:\s*(\S+)', route)
            if iface and gateway:
                gw = gateway.group(1)
                subnet = '.'.join(gw.split('.')[:3]) + '.0/24'
                return iface.group(1), subnet, gw
        else:  # Linux
            route = subprocess.check_output(
                ['ip', 'route', 'show', 'default'], text=True, timeout=5
            )
            match = re.search(r'default via (\S+) dev (\S+)', route)
            if match:
                gw = match.group(1)
                iface = match.group(2)
                subnet = '.'.join(gw.split('.')[:3]) + '.0/24'
                return iface, subnet, gw
    except Exception:
        pass
    return 'en0', '192.168.1.0/24', '192.168.1.1'


def arp_scan():
    """Discover devices using ARP table."""
    system = platform.system()
    devices = []
    try:
        if system == 'Darwin':
            output = subprocess.check_output(['arp', '-a'], text=True, timeout=10)
        else:
            output = subprocess.check_output(['arp', '-n'], text=True, timeout=10)

        for line in output.strip().split('\n'):
            # macOS: hostname (ip) at mac on iface ...
            m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)', line)
            if not m:
                # Linux: ip ... mac ...
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+([0-9a-fA-F:]+)', line)
            if m:
                ip = m.group(1)
                mac = normalize_mac(m.group(2))
                if mac == '(incomplete)' or mac == 'ff:ff:ff:ff:ff:ff':
                    continue
                hostname = resolve_hostname(ip)
                vendor = get_mac_vendor_prefix(mac)
                dtype = classify_device(hostname, vendor, ip=ip)
                devices.append({
                    'ip': ip, 'mac': mac,
                    'hostname': hostname, 'vendor': vendor,
                    'device_type': dtype
                })
                upsert_device(mac, ip, hostname, vendor, dtype)
    except Exception as e:
        print(f"ARP scan error: {e}")
    return devices


def nmap_discovery(subnet=None):
    """Use nmap ping scan for device discovery."""
    if not subnet:
        _, subnet, _ = get_default_interface()
    devices = []
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments='-sn -T4')
        for host in nm.all_hosts():
            addr = nm[host].get('addresses', {})
            ip = addr.get('ipv4', host)
            mac_raw = addr.get('mac', '')
            mac = normalize_mac(mac_raw) if mac_raw else ''
            vendor_dict = nm[host].get('vendor', {})
            vendor = list(vendor_dict.values())[0] if vendor_dict else ''
            hostname = ''
            hostnames = nm[host].get('hostnames', [])
            if hostnames and hostnames[0].get('name'):
                hostname = hostnames[0]['name']
            if not hostname:
                hostname = resolve_hostname(ip)
            if mac:
                dtype = classify_device(hostname, vendor, ip=ip)
                devices.append({
                    'ip': ip, 'mac': mac,
                    'hostname': hostname, 'vendor': vendor,
                    'device_type': dtype
                })
                upsert_device(mac, ip, hostname, vendor, dtype)
    except Exception as e:
        print(f"Nmap discovery error: {e}")
    return devices


def normalize_mac(mac):
    """Normalize MAC address to xx:xx:xx:xx:xx:xx format with leading zeros."""
    parts = mac.lower().split(':')
    return ':'.join(p.zfill(2) for p in parts)


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ''


def get_mac_vendor_prefix(mac):
    """Basic vendor lookup from MAC OUI prefix."""
    oui = {
        # Raspberry Pi
        'dc:a6:32': 'Raspberry Pi', 'b8:27:eb': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
        '28:cd:c1': 'Raspberry Pi', 'd8:3a:dd': 'Raspberry Pi', '2c:cf:67': 'Raspberry Pi',
        # VMware / VirtualBox
        '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:05:69': 'VMware',
        '08:00:27': 'VirtualBox',
        # Apple
        'ac:de:48': 'Apple', '3c:22:fb': 'Apple', 'f8:ff:c2': 'Apple',
        '00:1a:79': 'Apple', '88:e9:fe': 'Apple', 'a4:83:e7': 'Apple',
        '14:7d:da': 'Apple', '78:7b:8a': 'Apple', 'a8:60:b6': 'Apple',
        '7c:d1:c3': 'Apple', 'a0:78:17': 'Apple', '8c:85:90': 'Apple',
        '38:f9:d3': 'Apple', 'f0:18:98': 'Apple', 'bc:d0:74': 'Apple',
        '48:a1:95': 'Apple', 'f4:5c:89': 'Apple', '6c:96:cf': 'Apple',
        'd0:81:7a': 'Apple', '64:b0:a6': 'Apple', '20:a2:e4': 'Apple',
        'cc:29:f5': 'Apple', '90:fd:61': 'Apple', 'a4:b1:c1': 'Apple',
        '2c:f0:a2': 'Apple', '5c:e9:1e': 'Apple', 'b0:34:95': 'Apple',
        # Google
        'a4:77:33': 'Google', '54:60:09': 'Google', 'f4:f5:d8': 'Google',
        '30:fd:38': 'Google', '94:b8:6d': 'Google', '48:d6:d5': 'Google',
        '20:df:b9': 'Google', '7c:2e:bd': 'Google', 'e4:f0:42': 'Google',
        # TP-Link
        'b0:be:76': 'TP-Link', '50:c7:bf': 'TP-Link', 'e8:de:27': 'TP-Link',
        'c0:25:e9': 'TP-Link', '18:d6:c7': 'TP-Link', '98:da:c4': 'TP-Link',
        '60:32:b1': 'TP-Link', 'b0:4e:26': 'TP-Link',
        # Samsung
        '44:32:c8': 'Samsung', '8c:f5:a3': 'Samsung', 'a0:cc:2b': 'Samsung',
        '00:26:37': 'Samsung', 'fc:a1:3e': 'Samsung', 'c4:73:1e': 'Samsung',
        '78:47:1d': 'Samsung', 'b4:3a:28': 'Samsung', '34:14:5f': 'Samsung',
        'cc:07:ab': 'Samsung', '84:11:9e': 'Samsung',
        # Netgear
        'c4:3d:c7': 'Netgear', 'b0:7f:b9': 'Netgear', '20:0c:c8': 'Netgear',
        '28:80:88': 'Netgear', '6c:b0:ce': 'Netgear',
        # Linksys/Belkin
        'c0:56:27': 'Linksys', '58:6d:8f': 'Linksys', '14:91:82': 'Belkin',
        # Asus
        'f0:79:59': 'Asus', '2c:fd:a1': 'Asus', '04:d4:c4': 'Asus',
        '1c:87:2c': 'Asus', '50:46:5d': 'Asus',
        # Amazon
        'f0:f0:a4': 'Amazon', '74:c2:46': 'Amazon', 'fc:65:de': 'Amazon',
        '68:54:fd': 'Amazon', '40:b4:cd': 'Amazon', 'a0:02:dc': 'Amazon',
        '84:d6:d0': 'Amazon', '44:00:49': 'Amazon',
        # Sonos
        '48:a6:b8': 'Sonos', 'b8:e9:37': 'Sonos', '5c:aa:fd': 'Sonos',
        '00:0e:58': 'Sonos', '78:28:ca': 'Sonos', '34:7e:5c': 'Sonos',
        # Roku
        'dc:3a:5e': 'Roku', 'b0:a7:37': 'Roku', 'cc:6d:a0': 'Roku',
        '10:59:32': 'Roku', 'd8:31:34': 'Roku',
        # Ring
        '2c:aa:8e': 'Ring', '4c:eb:d6': 'Ring', '00:62:6e': 'Ring',
        # Wyze
        '2c:aa:8e': 'Wyze',
        # HP
        '3c:d9:2b': 'HP', '00:1e:0b': 'HP', 'a0:d3:c1': 'HP',
        '98:e7:f4': 'HP', '64:51:06': 'HP',
        # Canon
        '18:0c:ac': 'Canon', '00:1e:8f': 'Canon', 'c4:ac:59': 'Canon',
        # Epson
        '00:26:ab': 'Epson', 'ac:18:26': 'Epson', '64:eb:8c': 'Epson',
        # Brother
        '00:80:77': 'Brother', '00:1b:a9': 'Brother', '30:05:5c': 'Brother',
        # Intel (PCs)
        '00:1b:21': 'Intel', '3c:97:0e': 'Intel', '8c:ec:4b': 'Intel',
        'a4:4c:c8': 'Intel', 'f8:63:3f': 'Intel', 'b4:96:91': 'Intel',
        # Dell
        '00:14:22': 'Dell', 'f8:db:88': 'Dell', '00:1a:a0': 'Dell',
        '18:03:73': 'Dell', '34:17:eb': 'Dell',
        # Lenovo
        '8c:16:45': 'Lenovo', '98:fa:9b': 'Lenovo', 'e8:2a:ea': 'Lenovo',
        '5c:80:b6': 'Lenovo',
        # Microsoft
        '7c:1e:52': 'Microsoft', '28:18:78': 'Microsoft', 'c8:3f:26': 'Microsoft',
        # Sony
        'fc:0f:e6': 'Sony', '00:04:1f': 'Sony', '00:1d:0d': 'Sony',
        'a8:e3:ee': 'Sony', '78:c8:81': 'Sony',
        # LG
        '00:1c:62': 'LG', '10:68:3f': 'LG', 'a8:23:fe': 'LG',
        '58:a2:b5': 'LG', '74:40:be': 'LG',
        # Ubiquiti
        '80:2a:a8': 'Ubiquiti', 'f0:9f:c2': 'Ubiquiti', '68:d7:9a': 'Ubiquiti',
        '78:8a:20': 'Ubiquiti', 'fc:ec:da': 'Ubiquiti', '24:5a:4c': 'Ubiquiti',
        # Cisco
        '00:1b:0d': 'Cisco', '00:25:45': 'Cisco', 'f4:cf:e2': 'Cisco',
        # Espressif (ESP32/ESP8266 IoT)
        '24:6f:28': 'Espressif', '30:ae:a4': 'Espressif', 'a4:cf:12': 'Espressif',
        'bc:dd:c2': 'Espressif', '08:3a:f2': 'Espressif', 'ec:fa:bc': 'Espressif',
        # Philips Hue
        '00:17:88': 'Philips Hue',
        # Nest/Google Nest
        '18:b4:30': 'Nest', '64:16:66': 'Nest',
    }
    prefix = mac[:8].lower()
    return oui.get(prefix, '')


def classify_device(hostname='', vendor='', open_ports=None, ip='', os_info=''):
    """Classify device type based on hostname, vendor, open ports, OS, and network role."""
    h = (hostname or '').lower()
    v = (vendor or '').lower()
    ports = set(open_ports or [])
    os_lower = (os_info or '').lower()

    # Check if this device is the gateway/router
    if ip:
        try:
            _, _, gateway = get_default_interface()
            if ip == gateway:
                return 'router'
        except Exception:
            pass

    # Hostname-based classification (highest confidence)
    hostname_rules = [
        (['iphone', 'iphones'], 'phone'),
        (['ipad'], 'tablet'),
        (['android', 'pixel', 'galaxy', 'oneplus', 'huawei', 'xiaomi', 'redmi', 'oppo', 'samsung-sm', 'sm-'], 'phone'),
        (['macbook', 'macbook-pro', 'macbook-air', 'mbp-', 'mba-'], 'computer'),
        (['imac', 'mac-pro', 'mac-mini', 'macmini', 'macpro', 'mac-studio'], 'computer'),
        (['desktop', 'laptop', 'workstation', 'thinkpad', 'dell-', 'lenovo-', 'hp-', 'surface'], 'computer'),
        (['windows', 'msft', 'win10', 'win11'], 'computer'),
        (['.local'], 'computer'),  # mDNS names often indicate macOS/Linux computers
        (['printer', 'epson', 'brother', 'canon-', 'laserjet', 'deskjet', 'officejet', 'pixma'], 'printer'),
        (['roku', 'fire-tv', 'firetv', 'apple-tv', 'appletv', 'chromecast', 'smarttv',
          'lg-tv', 'samsung-tv', 'bravia', 'vizio', 'shield', 'firestick'], 'tv'),
        (['echo', 'alexa', 'home-mini', 'homemini', 'nest-mini', 'nest-hub', 'nest-audio',
          'google-home', 'homepod', 'sonos'], 'smart-speaker'),
        (['playstation', 'ps4', 'ps5', 'xbox', 'nintendo', 'switch'], 'game-console'),
        (['raspberrypi', 'raspberry', 'pi-hole', 'pihole', 'homebridge'], 'iot'),
        (['cam', 'camera', 'doorbell', 'ring-', 'arlo', 'blink', 'wyze', 'eufy'], 'camera'),
        (['thermostat', 'hue', 'bulb', 'plug', 'switch', 'sensor', 'wemo', 'smartthings',
          'tuya', 'shelly', 'tasmota', 'esp-', 'esp32', 'esp8266'], 'iot'),
        (['router', 'gateway', 'modem', 'access-point', 'ap-', 'unifi', 'eero', 'orbi',
          'deco', 'mesh', 'airport'], 'router'),
        (['nas', 'synology', 'qnap', 'freenas', 'truenas', 'plex', 'media-server'], 'server'),
    ]
    for keywords, dtype in hostname_rules:
        if any(kw in h for kw in keywords):
            return dtype

    # Vendor-based classification
    vendor_rules = [
        (['raspberry pi', 'espressif'], 'iot'),
        (['philips hue'], 'iot'),
        (['vmware', 'virtualbox'], 'computer'),
        (['intel', 'dell', 'lenovo', 'microsoft'], 'computer'),
        (['hp', 'brother', 'canon', 'epson', 'lexmark', 'xerox', 'ricoh', 'kyocera'], 'printer'),
        (['roku'], 'tv'),
        (['sonos'], 'smart-speaker'),
        (['ring', 'arlo', 'wyze'], 'camera'),
        (['nest'], 'smart-speaker'),
        (['tp-link', 'netgear', 'linksys', 'ubiquiti', 'asus', 'cisco', 'mikrotik',
          'arris', 'motorola', 'eero', 'belkin'], 'router'),
        (['amazon'], 'smart-speaker'),
        (['sony'], 'game-console'),
        (['nintendo'], 'game-console'),
        (['lg', 'vizio', 'tcl', 'hisense'], 'tv'),
    ]
    for keywords, dtype in vendor_rules:
        if any(kw in v for kw in keywords):
            return dtype

    # OS-based classification (from nmap -O detection)
    if os_lower:
        os_rules = [
            (['ios', 'iphone os'], 'phone'),
            (['ipad'], 'tablet'),
            (['android'], 'phone'),
            (['mac os x', 'macos', 'os x'], 'computer'),
            (['windows'], 'computer'),
            (['linux'], None),  # Linux is too broad — skip, use other signals
            (['freebsd', 'openbsd', 'netbsd'], 'server'),
            (['printer', 'jetdirect'], 'printer'),
            (['roku os'], 'tv'),
            (['tizen', 'webos', 'smart tv', 'smarttv'], 'tv'),
            (['playstation', 'xbox', 'nintendo'], 'game-console'),
            (['routeros', 'dd-wrt', 'openwrt', 'pfsense', 'vyos', 'edgeos', 'ubiquiti'], 'router'),
        ]
        for keywords, dtype in os_rules:
            if dtype and any(kw in os_lower for kw in keywords):
                return dtype

    # Apple disambiguation (needs hostname or ports)
    if 'apple' in v or 'apple' in h:
        if 62078 in ports:
            # Port 62078 = Apple iDevice (lockdownd) — iPhone or iPad
            return 'phone'
        if any(kw in h for kw in ['macbook', 'imac', 'mac-pro', 'mac-mini', 'mac-studio']):
            return 'computer'
        # Apple devices with AirPlay (3689) are likely Apple TV
        if 3689 in ports or 7000 in ports:
            return 'tv'
        # Default Apple: if hostname ends with .local or has common Mac patterns
        if h.endswith('.local') or any(kw in h for kw in ['-mac', 'mac.local', 's-mac']):
            return 'computer'
        return 'computer'  # most Apple devices on home networks are Macs/iPhones

    # Samsung disambiguation
    if 'samsung' in v:
        if 9197 in ports or 8001 in ports or 8002 in ports:
            return 'tv'
        if 'tv' in h or 'tizen' in h:
            return 'tv'
        return 'phone'

    # Google disambiguation
    if 'google' in v:
        if 8008 in ports or 8443 in ports or 8009 in ports:
            return 'smart-speaker'
        return 'phone'

    # Port-based classification (lowest confidence)
    if ports:
        if 631 in ports or 9100 in ports or 515 in ports:
            return 'printer'
        if (8008 in ports and 8443 in ports) or 8009 in ports:
            return 'tv'  # Chromecast / smart TV
        if 62078 in ports:
            return 'phone'
        if 80 in ports and 53 in ports:
            return 'router'
        if 548 in ports or 445 in ports or 139 in ports:
            return 'computer'  # AFP/SMB file sharing = computer
        if 22 in ports or 3389 in ports:
            return 'computer'

    return 'unknown'


def stealth_port_scan(ip, mac, progress_callback=None):
    """Run nmap stealth SYN scan with service/version detection."""
    def _progress(stage, message):
        if progress_callback:
            progress_callback(mac, ip, stage, message)

    try:
        nm = nmap.PortScanner()
        results = {'ports': [], 'os': ''}

        # Stage 1: SYN stealth scan + OS detection to find open ports
        _progress('syn_scan', 'Running SYN stealth scan with OS detection on top 1000 ports...')
        nm.scan(hosts=ip, arguments='-sS -O -T3 -Pn --top-ports 1000')

        open_ports = []
        if ip in nm.all_hosts():
            # Extract OS detection from SYN scan
            host = nm[ip]
            if 'osmatch' in host:
                os_matches = host['osmatch']
                if os_matches:
                    results['os'] = os_matches[0].get('name', '')
                    # Store all OS matches for classification
                    results['os_matches'] = [
                        {'name': m.get('name', ''), 'accuracy': m.get('accuracy', '0')}
                        for m in os_matches[:5]
                    ]
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto]:
                    if nm[ip][proto][port].get('state') == 'open':
                        open_ports.append(port)

        if not open_ports:
            _progress('complete', 'Scan complete — no open ports found.')
            scan_id = save_port_scan(mac, ip, results)
            results['scan_id'] = scan_id
            # Refine device classification with OS info
            device = get_device(mac)
            if device:
                dtype = classify_device(
                    device.get('hostname', ''), device.get('vendor', ''),
                    [], ip=ip, os_info=results.get('os', '')
                )
                update_device_type(mac, dtype)
            return results

        port_list = ','.join(str(p) for p in open_ports)
        _progress('service_detection', f'Detecting services on {len(open_ports)} open port{"s" if len(open_ports) != 1 else ""}...')

        # Stage 2: Service version detection on open ports only
        nm.scan(hosts=ip, ports=port_list, arguments='-sV -Pn -T3')

        if ip in nm.all_hosts():
            host = nm[ip]
            if 'osmatch' in host:
                os_matches = host['osmatch']
                if os_matches:
                    results['os'] = os_matches[0].get('name', '')

            for proto in host.all_protocols():
                for port in sorted(host[proto].keys()):
                    port_info = host[proto][port]
                    results['ports'].append({
                        'port': port,
                        'protocol': proto,
                        'state': port_info.get('state', ''),
                        'service': port_info.get('name', ''),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                        'extra_info': port_info.get('extrainfo', ''),
                        'cpe': port_info.get('cpe', ''),
                        'vulns': []
                    })

        # Stage 3: Vulnerability scan on open ports
        _progress('vuln_scan', 'Checking for known vulnerabilities (CVEs)...')
        nm.scan(hosts=ip, ports=port_list, arguments='-sV --script=vulners -Pn -T3')

        if ip in nm.all_hosts():
            host = nm[ip]
            for proto in host.all_protocols():
                for port in host[proto]:
                    script_output = host[proto][port].get('script', {})
                    if 'vulners' in script_output:
                        vulns = parse_vulners_output(script_output['vulners'])
                        # Attach vulns to matching port in results
                        for pd in results['ports']:
                            if pd['port'] == port and pd['protocol'] == proto:
                                pd['vulns'] = vulns
                                break

        # Save results
        _progress('saving', 'Saving results...')
        scan_id = save_port_scan(mac, ip, results)

        for port_data in results['ports']:
            for vuln in port_data.get('vulns', []):
                save_vulnerability(
                    scan_id, port_data['port'],
                    port_data['service'], port_data['version'],
                    vuln.get('id', ''), vuln.get('description', ''),
                    vuln.get('severity', '')
                )

        # Refine device classification with discovered ports and OS info
        device = get_device(mac)
        if device:
            dtype = classify_device(
                device.get('hostname', ''), device.get('vendor', ''),
                open_ports, ip=ip, os_info=results.get('os', '')
            )
            update_device_type(mac, dtype)

        total_vulns = sum(len(pd.get('vulns', [])) for pd in results['ports'])
        _progress('complete', f'Scan complete — {len(open_ports)} open port{"s" if len(open_ports) != 1 else ""}, {total_vulns} vulnerabilit{"ies" if total_vulns != 1 else "y"}.')

        results['scan_id'] = scan_id
        return results

    except Exception as e:
        _progress('error', f'Scan failed: {str(e)}')
        return {'error': str(e), 'ports': []}


def parse_vulners_output(raw):
    """Parse nmap vulners script output into structured data."""
    vulns = []
    if not raw:
        return vulns
    for line in raw.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('cpe:'):
            continue
        # Format: CVE-XXXX-XXXX  score  url
        parts = re.split(r'\s+', line, maxsplit=2)
        if len(parts) >= 2:
            vuln_id = parts[0].strip()
            try:
                score = float(parts[1])
            except ValueError:
                score = 0.0
            severity = 'LOW'
            if score >= 9.0:
                severity = 'CRITICAL'
            elif score >= 7.0:
                severity = 'HIGH'
            elif score >= 4.0:
                severity = 'MEDIUM'
            vulns.append({
                'id': vuln_id,
                'score': score,
                'severity': severity,
                'description': f'{vuln_id} (CVSS: {score})',
                'url': parts[2].strip() if len(parts) > 2 else ''
            })
    # Sort by severity score descending
    vulns.sort(key=lambda v: v.get('score', 0), reverse=True)
    return vulns


def get_network_stats():
    """Get basic network interface statistics."""
    system = platform.system()
    stats = {}
    try:
        if system == 'Darwin':
            output = subprocess.check_output(
                ['netstat', '-ib'], text=True, timeout=5
            )
            for line in output.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 7 and not parts[0].startswith('lo'):
                    iface = parts[0]
                    stats[iface] = {
                        'ipkts': int(parts[4]) if parts[4].isdigit() else 0,
                        'ibytes': int(parts[6]) if parts[6].isdigit() else 0,
                        'opkts': int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else 0,
                        'obytes': int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0,
                    }
        else:
            output = subprocess.check_output(
                ['cat', '/proc/net/dev'], text=True, timeout=5
            )
            for line in output.strip().split('\n')[2:]:
                parts = line.split()
                iface = parts[0].rstrip(':')
                if iface != 'lo':
                    stats[iface] = {
                        'ibytes': int(parts[1]),
                        'ipkts': int(parts[2]),
                        'obytes': int(parts[9]),
                        'opkts': int(parts[10]),
                    }
    except Exception as e:
        print(f"Network stats error: {e}")
    return stats
