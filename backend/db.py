"""SQLite persistence for device nicknames and scan results."""

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'loki-vigilant.db')


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            hostname TEXT,
            nickname TEXT DEFAULT '',
            vendor TEXT DEFAULT '',
            device_type TEXT DEFAULT '',
            first_seen TEXT,
            last_seen TEXT,
            total_packets INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS port_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            ip TEXT,
            scan_time TEXT,
            results TEXT,
            FOREIGN KEY (mac) REFERENCES devices(mac)
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            port INTEGER,
            service TEXT,
            version TEXT,
            vuln_id TEXT,
            description TEXT,
            severity TEXT,
            FOREIGN KEY (scan_id) REFERENCES port_scans(id)
        );
        CREATE TABLE IF NOT EXISTS intrusion_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            hostname TEXT DEFAULT '',
            scan_type TEXT,
            scan_type_key TEXT,
            ports_hit INTEGER DEFAULT 0,
            targets TEXT DEFAULT '[]',
            started_at TEXT,
            ended_at TEXT,
            duration_sec INTEGER DEFAULT 0,
            spoof_status TEXT DEFAULT 'unknown',
            spoof_reasons TEXT DEFAULT '[]'
        );
    """)
    # Migrate existing DBs that lack columns
    migrations = [
        ("ALTER TABLE devices ADD COLUMN device_type TEXT DEFAULT ''", None),
        ("ALTER TABLE intrusion_attempts ADD COLUMN hostname TEXT DEFAULT ''", None),
        ("ALTER TABLE intrusion_attempts ADD COLUMN spoof_status TEXT DEFAULT 'unknown'", None),
        ("ALTER TABLE intrusion_attempts ADD COLUMN spoof_reasons TEXT DEFAULT '[]'", None),
    ]
    for sql, _ in migrations:
        try:
            conn.execute(sql)
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.commit()
    conn.close()


def upsert_device(mac, ip, hostname='', vendor='', device_type=''):
    conn = get_conn()
    now = datetime.now().isoformat()
    conn.execute("""
        INSERT INTO devices (mac, ip, hostname, vendor, device_type, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            ip = excluded.ip,
            hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END,
            vendor = CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE devices.vendor END,
            device_type = CASE WHEN excluded.device_type != '' THEN excluded.device_type ELSE devices.device_type END,
            last_seen = excluded.last_seen
    """, (mac, ip, hostname, vendor, device_type, now, now))
    conn.commit()
    conn.close()


def update_device_traffic(mac, packets=0, nbytes=0):
    conn = get_conn()
    now = datetime.now().isoformat()
    conn.execute("""
        UPDATE devices SET
            total_packets = total_packets + ?,
            total_bytes = total_bytes + ?,
            last_seen = ?
        WHERE mac = ?
    """, (packets, nbytes, now, mac))
    conn.commit()
    conn.close()


def update_device_type(mac, device_type):
    conn = get_conn()
    conn.execute("UPDATE devices SET device_type = ? WHERE mac = ?", (device_type, mac))
    conn.commit()
    conn.close()


def set_nickname(mac, nickname):
    conn = get_conn()
    conn.execute("UPDATE devices SET nickname = ? WHERE mac = ?", (nickname, mac))
    conn.commit()
    conn.close()


def get_all_devices():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_device(mac):
    conn = get_conn()
    row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    conn.close()
    return dict(row) if row else None


def save_port_scan(mac, ip, results):
    conn = get_conn()
    now = datetime.now().isoformat()
    cursor = conn.execute(
        "INSERT INTO port_scans (mac, ip, scan_time, results) VALUES (?, ?, ?, ?)",
        (mac, ip, now, json.dumps(results))
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def save_vulnerability(scan_id, port, service, version, vuln_id, description, severity):
    conn = get_conn()
    conn.execute("""
        INSERT INTO vulnerabilities (scan_id, port, service, version, vuln_id, description, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (scan_id, port, service, version, vuln_id, description, severity))
    conn.commit()
    conn.close()


def get_scan_history(mac):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM port_scans WHERE mac = ? ORDER BY scan_time DESC LIMIT 10",
        (mac,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_intrusion_attempt(source_ip, scan_type, scan_type_key, ports_hit, targets,
                           started_at, ended_at, duration_sec,
                           hostname='', spoof_status='unknown', spoof_reasons=None):
    conn = get_conn()
    conn.execute("""
        INSERT INTO intrusion_attempts
            (source_ip, hostname, scan_type, scan_type_key, ports_hit, targets,
             started_at, ended_at, duration_sec, spoof_status, spoof_reasons)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (source_ip, hostname, scan_type, scan_type_key, ports_hit,
          json.dumps(targets), started_at, ended_at, duration_sec,
          spoof_status, json.dumps(spoof_reasons or [])))
    conn.commit()
    conn.close()


def get_intrusion_attempts(limit=100):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM intrusion_attempts ORDER BY started_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get('targets'), str):
            d['targets'] = json.loads(d['targets'])
        if isinstance(d.get('spoof_reasons'), str):
            d['spoof_reasons'] = json.loads(d['spoof_reasons'])
        result.append(d)
    return result


def get_intrusion_stats():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM intrusion_attempts").fetchone()[0]
    last = conn.execute(
        "SELECT * FROM intrusion_attempts ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return {
        'total_attempts': total,
        'last_attempt': dict(last) if last else None,
    }


def get_vulns_for_scan(scan_id):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM vulnerabilities WHERE scan_id = ?",
        (scan_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
