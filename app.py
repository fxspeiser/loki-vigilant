#!/usr/bin/env python3
"""Loki Vigilant - Home Network Security Monitor."""

import os
import json
import threading
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

from backend.db import (
    init_db, get_all_devices, get_device, set_nickname,
    get_scan_history, get_vulns_for_scan,
    save_intrusion_attempt, get_intrusion_attempts, get_intrusion_stats
)
from backend.scanner import (
    arp_scan, nmap_discovery, stealth_port_scan,
    get_network_stats, get_default_interface
)
from backend.packet_monitor import PacketMonitor
from backend.intrusion_detector import IntrusionDetector

app = Flask(
    __name__,
    template_folder='frontend/templates',
    static_folder='frontend/static'
)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*')

# Initialize
init_db()
monitor = PacketMonitor()

# Intrusion detector with SocketIO callbacks
def on_scan_detected(event):
    hostname = event.get('hostname', '')
    spoof = event.get('spoof_status', 'unknown')
    label = f"{event['source_ip']}"
    if hostname:
        label += f" ({hostname})"
    print(f"[INTRUSION] Scan detected from {label}: {event['scan_type']} [spoof: {spoof}]")
    socketio.emit('intrusion_detected', event)

def on_scan_ended(event):
    hostname = event.get('hostname', '')
    spoof = event.get('spoof_status', 'unknown')
    label = f"{event['source_ip']}"
    if hostname:
        label += f" ({hostname})"
    print(f"[INTRUSION] Scan ended from {label}: {event['scan_type']} ({event['duration_sec']}s, {event['ports_hit']} ports) [spoof: {spoof}]")
    save_intrusion_attempt(
        event['source_ip'], event['scan_type'], event['scan_type_key'],
        event['ports_hit'], event['targets'],
        event['start'], event['end'], event['duration_sec'],
        hostname=event.get('hostname', ''),
        spoof_status=event.get('spoof_status', 'unknown'),
        spoof_reasons=event.get('spoof_reasons', []),
    )
    socketio.emit('intrusion_ended', event)

intrusion_detector = IntrusionDetector(
    on_scan_detected=on_scan_detected,
    on_scan_ended=on_scan_ended
)

# Background scan state
_scan_lock = threading.Lock()
_active_scans = set()


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/devices')
def api_devices():
    """Get all discovered devices with live traffic stats."""
    devices = get_all_devices()
    live = monitor.get_stats()
    for d in devices:
        ip = d['ip']
        if ip in live:
            d['live_packets'] = live[ip]['packets']
            d['live_bytes'] = live[ip]['bytes']
            d['live_last_seen'] = live[ip]['last_seen']
            d['live_bps'] = live[ip].get('bps', 0)
            d['recent_packets'] = live[ip].get('recent_packets', 0)
            d['recent_bytes'] = live[ip].get('recent_bytes', 0)
        else:
            d['live_packets'] = 0
            d['live_bytes'] = 0
            d['live_last_seen'] = d.get('last_seen')
            d['live_bps'] = 0
            d['recent_packets'] = 0
            d['recent_bytes'] = 0
    return jsonify(devices)


@app.route('/api/scan/discover', methods=['POST'])
def api_discover():
    """Run network discovery (ARP + nmap ping scan)."""
    devices = arp_scan()
    try:
        nmap_devices = nmap_discovery()
        # Merge — nmap may find devices ARP missed, and fill in vendor info
        dev_by_mac = {d['mac']: d for d in devices}
        for nd in nmap_devices:
            if nd['mac'] in dev_by_mac:
                # Fill in vendor/hostname from nmap if our OUI table missed it
                existing = dev_by_mac[nd['mac']]
                if nd.get('vendor') and not existing.get('vendor'):
                    existing['vendor'] = nd['vendor']
                if nd.get('hostname') and not existing.get('hostname'):
                    existing['hostname'] = nd['hostname']
            else:
                devices.append(nd)
    except Exception as e:
        print(f"Nmap discovery fallback: {e}")

    monitor.update_mac_map(devices)
    return jsonify({'status': 'ok', 'count': len(devices), 'devices': devices})


@app.route('/api/scan/ports', methods=['POST'])
def api_port_scan():
    """Trigger stealth port scan on a specific device."""
    data = request.get_json()
    ip = data.get('ip')
    mac = data.get('mac')
    if not ip or not mac:
        return jsonify({'error': 'ip and mac required'}), 400

    if mac in _active_scans:
        return jsonify({'error': 'Scan already in progress for this device'}), 409

    _active_scans.add(mac)
    socketio.emit('scan_started', {'mac': mac, 'ip': ip})

    def run_scan():
        def progress_cb(_mac, _ip, stage, message):
            print(f"[scan] {_ip} stage={stage}: {message}")
            socketio.emit('scan_progress', {
                'mac': _mac, 'ip': _ip,
                'stage': stage, 'message': message
            })

        try:
            print(f"[scan] Starting port scan for {ip} ({mac})")
            results = stealth_port_scan(ip, mac, progress_callback=progress_cb)
            print(f"[scan] Complete for {ip}: {len(results.get('ports', []))} ports")
            socketio.emit('scan_complete', {
                'mac': mac, 'ip': ip, 'results': results
            })
        except Exception as e:
            print(f"[scan] Error for {ip}: {e}")
            socketio.emit('scan_error', {
                'mac': mac, 'ip': ip, 'error': str(e)
            })
        finally:
            _active_scans.discard(mac)

    socketio.start_background_task(run_scan)

    return jsonify({'status': 'scanning', 'mac': mac, 'ip': ip})


@app.route('/api/device/nickname', methods=['POST'])
def api_set_nickname():
    """Set a nickname for a device."""
    data = request.get_json()
    mac = data.get('mac')
    nickname = data.get('nickname', '')
    if not mac:
        return jsonify({'error': 'mac required'}), 400
    set_nickname(mac, nickname)
    return jsonify({'status': 'ok'})


@app.route('/api/device/<mac>/scans')
def api_device_scans(mac):
    """Get port scan history for a device."""
    scans = get_scan_history(mac)
    for s in scans:
        s['results'] = json.loads(s['results']) if isinstance(s['results'], str) else s['results']
        s['vulns'] = get_vulns_for_scan(s['id'])
    return jsonify(scans)


@app.route('/api/network/stats')
def api_network_stats():
    """Get network interface stats."""
    iface, subnet, gateway = get_default_interface()
    stats = get_network_stats()
    return jsonify({
        'interface': iface,
        'subnet': subnet,
        'gateway': gateway,
        'interfaces': stats
    })


@app.route('/api/intrusions')
def api_intrusions():
    """Get intrusion attempt log."""
    attempts = get_intrusion_attempts(limit=200)
    return jsonify(attempts)


@app.route('/api/intrusions/stats')
def api_intrusion_stats():
    """Get intrusion statistics."""
    stats = get_intrusion_stats()
    active = intrusion_detector.get_active_scans()
    stats['active_scans'] = list(active.values())
    return jsonify(stats)


# --- WebSocket events ---

@socketio.on('connect')
def handle_connect():
    socketio.emit('status', {'monitoring': monitor.running})
    # Send active intrusions on connect
    active = intrusion_detector.get_active_scans()
    if active:
        for scan in active.values():
            socketio.emit('intrusion_detected', scan)


# --- Background tasks ---

def periodic_discovery():
    """Run ARP scan every 60 seconds to keep device list fresh."""
    while True:
        time.sleep(60)
        try:
            devices = arp_scan()
            monitor.update_mac_map(devices)
            socketio.emit('devices_updated', {})
        except Exception as e:
            print(f"Periodic discovery error: {e}")


def emit_live_stats():
    """Push live traffic stats to frontend every 2 seconds."""
    while True:
        time.sleep(2)
        try:
            stats = monitor.get_stats()
            socketio.emit('traffic_update', stats)
            # Also push intrusion status
            active = intrusion_detector.get_active_scans()
            socketio.emit('intrusion_status', {
                'active_scans': list(active.values())
            })
        except Exception:
            pass


def start_background_services():
    """Start packet monitor, intrusion detector, and background threads."""
    print("\n=== Loki Vigilant ===")
    print("Starting packet monitor (requires root for tcpdump)...")
    monitor.start()

    print("Starting intrusion detector...")
    intrusion_detector.start()

    threading.Thread(target=periodic_discovery, daemon=True).start()
    threading.Thread(target=emit_live_stats, daemon=True).start()

    iface, subnet, gw = get_default_interface()
    print(f"Interface: {iface} | Subnet: {subnet} | Gateway: {gw}")
    print("Dashboard: http://127.0.0.1:5150\n")


# Start services on import (works with both `python app.py` and `flask run`)
start_background_services()


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5150, debug=False)
