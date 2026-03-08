// Loki Vigilant - Frontend

const socket = io();
let devices = [];
let scanningDevices = new Set();
let sortPaused = false;
let renamingMac = null;
let expandedMacs = new Set();
// Per-device activity history: mac -> [{time, packets, bytes}, ...]
let activityHistory = {};
const ACTIVITY_HISTORY_SECONDS = 60;
const NEW_DEVICE_WINDOW_MS = 60 * 60 * 1000; // 1 hour

// Intrusion state
let intrusionLog = [];
let activeIntrusions = {};
let bannerDismissed = false;
let currentTab = 'devices';

const DEVICE_TYPE_LABELS = {
    'router': '\u{1F310} Router',
    'computer': '\u{1F4BB} Computer',
    'phone': '\u{1F4F1} Phone',
    'tablet': '\u{1F4F1} Tablet',
    'tv': '\u{1F4FA} TV',
    'printer': '\u{1F5A8}\uFE0F Printer',
    'iot': '\u{1F50C} IoT',
    'smart-speaker': '\u{1F50A} Speaker',
    'server': '\u{1F5A5}\uFE0F Server',
    'game-console': '\u{1F3AE} Console',
    'camera': '\u{1F4F7} Camera',
    'unknown': '\u2753 Unknown',
};

const SCAN_STAGE_ORDER = ['syn_scan', 'service_detection', 'vuln_scan', 'saving', 'complete'];
const SCAN_STAGE_LABELS = {
    'syn_scan': 'SYN stealth scan + OS detection',
    'service_detection': 'Service detection',
    'vuln_scan': 'Vulnerability check',
    'saving': 'Saving results',
    'complete': 'Complete',
};

// --- Init ---

document.addEventListener('DOMContentLoaded', () => {
    fetchNetworkInfo();
    fetchDevices();
    fetchIntrusionLog();
});

// --- Tab switching ---

function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tab);
    });
    document.querySelectorAll('.tab-content').forEach(section => {
        section.classList.toggle('active', section.id === `tab-${tab}`);
    });
    if (tab === 'intrusions') {
        fetchIntrusionLog();
    }
}

// --- API calls ---

async function fetchDevices() {
    try {
        const resp = await fetch('/api/devices');
        devices = await resp.json();
        renderDevices();
        updateNetworkTotals();
        document.getElementById('device-count').textContent = `Devices: ${devices.length}`;
    } catch (e) {
        console.error('Failed to fetch devices:', e);
    }
}

async function fetchNetworkInfo() {
    try {
        const resp = await fetch('/api/network/stats');
        const data = await resp.json();
        document.getElementById('network-info').textContent =
            `${data.interface} | ${data.subnet}`;
    } catch (e) {
        console.error('Failed to fetch network info:', e);
    }
}

async function fetchIntrusionLog() {
    try {
        const resp = await fetch('/api/intrusions');
        intrusionLog = await resp.json();
        renderIntrusionLog();
        updateIntrusionStats();
    } catch (e) {
        console.error('Failed to fetch intrusion log:', e);
    }
}

async function runDiscovery() {
    const btn = document.getElementById('btn-discover');
    btn.disabled = true;
    btn.textContent = 'Scanning...';
    try {
        const resp = await fetch('/api/scan/discover', { method: 'POST' });
        const data = await resp.json();
        await fetchDevices();
        // Show completion state
        btn.textContent = '\u2713 Found ' + (data.count || 0) + ' devices';
        btn.classList.add('btn-scan-done');
        setTimeout(() => {
            btn.textContent = 'Scan Network';
            btn.classList.remove('btn-scan-done');
        }, 3000);
    } catch (e) {
        console.error('Discovery failed:', e);
        btn.textContent = '\u2717 Scan failed';
        setTimeout(() => { btn.textContent = 'Scan Network'; }, 2000);
    } finally {
        btn.disabled = false;
    }
}

async function startPortScan(ip, mac) {
    if (scanningDevices.has(mac)) return;
    scanningDevices.add(mac);
    renderDevices();

    showScanModal(ip, mac);

    try {
        await fetch('/api/scan/ports', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, mac })
        });
    } catch (e) {
        console.error('Port scan failed:', e);
        scanningDevices.delete(mac);
        renderDevices();
    }
}

async function saveNicknameInline(mac, newNickname) {
    try {
        await fetch('/api/device/nickname', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac, nickname: newNickname })
        });
        const device = devices.find(d => d.mac === mac);
        if (device) device.nickname = newNickname;
        renderDevices();
    } catch (e) {
        console.error('Failed to save nickname:', e);
        renderDevices();
    }
}

function startInlineRename(mac) {
    const device = devices.find(d => d.mac === mac);
    if (!device) return;

    const cell = document.querySelector(`[data-rename-mac="${mac}"]`);
    if (!cell) return;

    renamingMac = mac;

    const current = device.nickname || '';
    const placeholder = device.hostname || device.ip;

    cell.innerHTML = `<input type="text" class="inline-rename-input" value="${escapeAttr(current)}" placeholder="${escapeAttr(placeholder)}" maxlength="50" data-mac="${escapeAttr(mac)}">`;

    const input = cell.querySelector('input');
    input.focus();
    input.select();

    let saved = false;
    const finish = (doSave) => {
        if (saved) return;
        saved = true;
        renamingMac = null;
        if (doSave) {
            const val = input.value.trim();
            if (val !== current) {
                saveNicknameInline(mac, val);
                return;
            }
        }
        renderDevices();
    };

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); finish(true); }
        if (e.key === 'Escape') { e.preventDefault(); finish(false); }
    });
    input.addEventListener('blur', () => finish(true));
}

async function viewScanHistory(ip, mac) {
    try {
        const resp = await fetch(`/api/device/${encodeURIComponent(mac)}/scans`);
        const scans = await resp.json();
        if (scans.length === 0) {
            showScanModal(ip, mac);
            document.getElementById('scan-loading').classList.add('hidden');
            document.getElementById('scan-results').innerHTML =
                '<p class="no-ports">No previous scans found. Run a port scan first.</p>';
            return;
        }
        const latest = scans[0];
        showScanResults(ip, mac, latest.results);
    } catch (e) {
        console.error('Failed to fetch scan history:', e);
    }
}

// --- Network totals ---

function updateNetworkTotals() {
    let totalPackets = 0;
    let totalBytes = 0;
    for (const d of devices) {
        totalPackets += (d.recent_packets || 0);
        totalBytes += (d.recent_bytes || 0);
    }
    document.getElementById('network-packets').textContent = `1m: ${formatNumber(totalPackets)} pkts`;
    document.getElementById('network-bandwidth').textContent = `1m: ${formatBytes(totalBytes)}`;
}

// --- Expand/collapse ---

function toggleExpand(mac) {
    if (expandedMacs.has(mac)) {
        expandedMacs.delete(mac);
        delete activityHistory[mac];
    } else {
        expandedMacs.add(mac);
        activityHistory[mac] = [];
    }
    renderDevices();
}

// --- Sort control ---

function toggleSortPause() {
    sortPaused = !sortPaused;
    const btn = document.getElementById('btn-sort-pause');
    if (sortPaused) {
        btn.textContent = '\u25B6 Resume Sort';
        btn.classList.add('btn-paused');
    } else {
        btn.textContent = '\u23F8 Pause Sort';
        btn.classList.remove('btn-paused');
        renderDevices();
    }
}

// --- Activity history tracking ---

function recordActivity(mac, recentPackets, recentBytes) {
    if (!expandedMacs.has(mac)) return;
    if (!activityHistory[mac]) activityHistory[mac] = [];

    const now = Date.now();
    activityHistory[mac].push({ time: now, packets: recentPackets || 0, bytes: recentBytes || 0 });

    const cutoff = now - (ACTIVITY_HISTORY_SECONDS * 1000);
    activityHistory[mac] = activityHistory[mac].filter(e => e.time >= cutoff);
}

function renderActivityBar(mac) {
    const history = activityHistory[mac];
    if (!history || history.length === 0) {
        return '<span style="color: var(--text-dim); font-size: 0.75rem;">Collecting data...</span>';
    }

    const now = Date.now();
    const bucketCount = 30;
    const bucketMs = 2000;
    const buckets = new Array(bucketCount).fill(0);

    for (const entry of history) {
        const age = now - entry.time;
        const idx = bucketCount - 1 - Math.floor(age / bucketMs);
        if (idx >= 0 && idx < bucketCount) {
            buckets[idx] += entry.packets;
        }
    }

    const maxVal = Math.max(...buckets, 1);
    const bars = buckets.map(v => {
        const h = Math.max(1, Math.round((v / maxVal) * 18));
        const opacity = v > 0 ? 0.8 : 0.15;
        return `<div class="activity-bar-segment" style="height:${h}px;opacity:${opacity}"></div>`;
    }).join('');

    return `<div class="activity-bar">${bars}</div>`;
}

// --- DNS display ---

function renderDnsQueries(dnsQueries) {
    if (!dnsQueries || dnsQueries.length === 0) {
        return '<span style="color: var(--text-dim); font-size: 0.75rem;">No DNS queries captured yet</span>';
    }

    // Group by domain, show most recent first, deduplicate
    const seen = new Map();
    for (const q of dnsQueries) {
        const existing = seen.get(q.domain);
        if (!existing || q.time > existing.time) {
            seen.set(q.domain, q);
        }
    }

    // Sort by most recent
    const sorted = [...seen.entries()].sort((a, b) =>
        b[1].time.localeCompare(a[1].time)
    );

    const items = sorted.slice(0, 30).map(([domain, q]) => {
        const ago = formatTimestamp(q.time);
        return `<div class="dns-entry">
            <span class="dns-domain">${escapeHtml(domain)}</span>
            <span class="dns-time">${ago}</span>
        </div>`;
    }).join('');

    return `<div class="dns-list">${items}</div>`;
}

// --- Intrusion banner ---

function updateIntrusionBanner() {
    const banner = document.getElementById('intrusion-banner');
    const text = document.getElementById('intrusion-banner-text');
    const activeCount = Object.keys(activeIntrusions).length;

    if (activeCount > 0 && !bannerDismissed) {
        const scans = Object.values(activeIntrusions);
        const sources = scans.map(s => {
            let label = s.source_ip;
            if (s.hostname) label += ` (${s.hostname})`;
            return label;
        }).join(', ');
        const types = [...new Set(scans.map(s => s.scan_type))].join(', ');
        const spoofHints = scans.map(s => {
            if (s.spoof_status === 'likely_spoofed') return ' [LIKELY SPOOFED]';
            if (s.spoof_status === 'suspicious') return ' [SUSPICIOUS IP]';
            return '';
        }).join('');
        text.textContent = `ACTIVE PORT SCAN DETECTED \u2014 ${types} from ${sources}${spoofHints}`;
        banner.classList.remove('hidden');
    } else {
        banner.classList.add('hidden');
    }
}

function dismissBanner() {
    bannerDismissed = true;
    document.getElementById('intrusion-banner').classList.add('hidden');
}

// --- Intrusion log ---

function renderIntrusionLog() {
    const tbody = document.getElementById('intrusions-body');

    if (intrusionLog.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No intrusion attempts detected yet</td></tr>';
        return;
    }

    let html = '';
    for (const a of intrusionLog) {
        const targets = Array.isArray(a.targets) ? a.targets.join(', ') : a.targets;
        const started = formatTimestamp(a.started_at);
        const duration = a.duration_sec ? formatDurationSec(a.duration_sec) : '--';
        const scanTypeClass = getScanTypeClass(a.scan_type_key || '');
        const spoofClass = getSpoofClass(a.spoof_status);
        const spoofLabel = getSpoofLabel(a.spoof_status);
        const spoofReasons = Array.isArray(a.spoof_reasons) ? a.spoof_reasons : [];
        const reasonsTooltip = spoofReasons.length > 0
            ? spoofReasons.map(r => escapeAttr(r)).join('&#10;')
            : '';

        html += `<tr>
            <td>
                <div class="source-info">
                    <span class="ip-addr">${escapeHtml(a.source_ip)}</span>
                    ${a.hostname ? `<span class="source-hostname">${escapeHtml(a.hostname)}</span>` : ''}
                </div>
            </td>
            <td><span class="scan-type-badge ${scanTypeClass}">${escapeHtml(a.scan_type)}</span></td>
            <td>
                <span class="spoof-badge ${spoofClass}" ${reasonsTooltip ? `title="${reasonsTooltip}"` : ''}>
                    ${spoofLabel}
                </span>
            </td>
            <td>${a.ports_hit || 0}</td>
            <td><span class="intrusion-targets">${escapeHtml(targets)}</span></td>
            <td><span class="timestamp">${started}</span></td>
            <td>${duration}</td>
        </tr>`;
    }

    tbody.innerHTML = html;
}

function getSpoofClass(status) {
    const map = {
        'verified': 'spoof-verified',
        'likely_spoofed': 'spoof-likely',
        'suspicious': 'spoof-suspicious',
        'unknown': 'spoof-unknown',
    };
    return map[status] || 'spoof-unknown';
}

function getSpoofLabel(status) {
    const map = {
        'verified': '\u2713 Verified',
        'likely_spoofed': '\u26A0 Likely Spoofed',
        'suspicious': '? Suspicious',
        'unknown': '\u2014 Unknown',
    };
    return map[status] || '\u2014 Unknown';
}

function updateIntrusionStats() {
    const totalEl = document.getElementById('stat-total-attempts');
    const lastEl = document.getElementById('stat-last-attempt');
    const predictedEl = document.getElementById('stat-predicted-next');

    totalEl.textContent = intrusionLog.length;

    if (intrusionLog.length > 0) {
        lastEl.textContent = formatTimestamp(intrusionLog[0].started_at);
    } else {
        lastEl.textContent = 'Never';
    }

    // Prediction: average interval between scans
    predictedEl.textContent = predictNextScan();

    // Update badge on tab
    const badge = document.getElementById('intrusion-count-badge');
    if (intrusionLog.length > 0) {
        badge.textContent = intrusionLog.length;
        badge.classList.remove('hidden');
    }

    // Active scan card
    const activeCard = document.getElementById('stat-active-card');
    const activeEl = document.getElementById('stat-active-scan');
    const activeCount = Object.keys(activeIntrusions).length;
    if (activeCount > 0) {
        activeCard.classList.remove('hidden');
        const sources = Object.values(activeIntrusions).map(s => {
            let label = s.source_ip;
            if (s.hostname) label += ` (${s.hostname})`;
            return label;
        }).join(', ');
        activeEl.textContent = `${activeCount} from ${sources}`;
    } else {
        activeCard.classList.add('hidden');
    }
}

function predictNextScan() {
    if (intrusionLog.length < 2) return '--';

    // Get timestamps sorted oldest first
    const times = intrusionLog
        .map(a => new Date(a.started_at).getTime())
        .filter(t => !isNaN(t))
        .sort((a, b) => a - b);

    if (times.length < 2) return '--';

    // Calculate average interval
    let totalInterval = 0;
    for (let i = 1; i < times.length; i++) {
        totalInterval += times[i] - times[i - 1];
    }
    const avgInterval = totalInterval / (times.length - 1);

    // Predict next = last + avg interval
    const lastTime = times[times.length - 1];
    const predictedTime = lastTime + avgInterval;
    const now = Date.now();

    if (predictedTime <= now) {
        // Overdue
        const overdue = formatDuration(now - predictedTime);
        return `Overdue by ${overdue}`;
    }

    const remaining = predictedTime - now;
    return `~${formatDuration(remaining)}`;
}

function getScanTypeClass(typeKey) {
    const map = {
        'SYN': 'scan-type-syn',
        'FIN': 'scan-type-fin',
        'XMAS': 'scan-type-xmas',
        'NULL': 'scan-type-null',
        'UDP': 'scan-type-udp',
        'ACK': 'scan-type-ack',
        'CONNECT': 'scan-type-connect',
    };
    return map[typeKey] || 'scan-type-unknown';
}

function formatDurationSec(sec) {
    if (sec < 60) return `${sec}s`;
    const min = Math.floor(sec / 60);
    const s = sec % 60;
    if (min < 60) return `${min}m ${s}s`;
    const hr = Math.floor(min / 60);
    return `${hr}h ${min % 60}m`;
}

// --- Time formatting ---

function isNewDevice(firstSeen) {
    if (!firstSeen) return false;
    const diff = Date.now() - new Date(firstSeen).getTime();
    return diff < NEW_DEVICE_WINDOW_MS;
}

function formatDuration(ms) {
    if (ms < 0) ms = 0;
    const sec = Math.floor(ms / 1000);
    if (sec < 60) return `${sec}s`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h`;
    const days = Math.floor(hr / 24);
    return `${days}d`;
}

function formatFirstSeen(ts) {
    if (!ts) return '\u2014';
    const date = new Date(ts);
    const agMs = Date.now() - date.getTime();
    const ago = formatDuration(agMs);
    // Short date: e.g. "Mar 8, 14:32"
    const short = date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
        + ', ' + date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    return `<div class="first-seen">
        <span class="first-seen-age">${ago} ago</span>
        <span class="first-seen-ago">${short}</span>
    </div>`;
}

// --- Rendering ---

function renderDevices() {
    if (renamingMac) return;

    const tbody = document.getElementById('devices-body');
    if (devices.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Click "Scan Network" to discover devices</td></tr>';
        return;
    }

    const sorted = [...devices];
    if (!sortPaused) {
        sorted.sort((a, b) => (b.recent_packets || 0) - (a.recent_packets || 0));
    }

    let html = '';
    for (const d of sorted) {
        const displayName = d.nickname || d.hostname || d.ip;
        const subName = d.nickname ? (d.hostname || d.ip) : '';
        const isScanning = scanningDevices.has(d.mac);
        const isExpanded = expandedMacs.has(d.mac);
        const lastSeen = d.live_last_seen || d.last_seen;
        const newDevice = isNewDevice(d.first_seen);

        const typeKey = d.device_type || 'unknown';
        const typeLabel = DEVICE_TYPE_LABELS[typeKey] || DEVICE_TYPE_LABELS['unknown'];

        const rowClasses = ['device-row'];
        if (isExpanded) rowClasses.push('expanded');
        if (newDevice) rowClasses.push('new-device');

        html += `<tr class="${rowClasses.join(' ')}" onclick="toggleExpand('${escapeAttr(d.mac)}')">
            <td style="padding:12px 8px 12px 16px;width:36px">
                <span class="expand-chevron">&#9654;</span>
            </td>
            <td>
                <div class="device-name" data-rename-mac="${escapeAttr(d.mac)}">
                    <div class="device-name-row">
                        <span class="${d.nickname ? 'device-nickname' : ''}">${escapeHtml(displayName)}</span>
                        <span class="rename-icon" onclick="event.stopPropagation(); startInlineRename('${escapeAttr(d.mac)}')" title="Rename">&#9998;</span>
                        ${newDevice ? '<span class="new-device-badge">new</span>' : ''}
                    </div>
                    ${subName ? `<span class="device-hostname">${escapeHtml(subName)}</span>` : ''}
                </div>
            </td>
            <td><span class="device-type type-${typeKey}">${typeLabel}</span></td>
            <td><span class="ip-addr">${escapeHtml(d.ip)}</span></td>
            <td>
                <span class="recent-activity">${formatNumber(d.recent_packets || 0)}</span>
                <span class="recent-bytes">${formatBytes(d.recent_bytes || 0)}</span>
            </td>
            <td>${formatFirstSeen(d.first_seen)}</td>
            <td><span class="timestamp">${formatTimestamp(lastSeen)}</span></td>
            <td>
                <div class="actions" onclick="event.stopPropagation()">
                    <button class="action-icon scan-action" onclick="startPortScan('${escapeAttr(d.ip)}', '${escapeAttr(d.mac)}')"
                        ${isScanning ? 'disabled' : ''} title="${isScanning ? 'Scanning...' : 'Port Scan'}">
                        ${isScanning ? '&#8987;' : '&#9881;'}
                    </button>
                    <button class="action-icon history-action" onclick="viewScanHistory('${escapeAttr(d.ip)}', '${escapeAttr(d.mac)}')" title="Scan History">
                        &#128203;
                    </button>
                </div>
            </td>
        </tr>`;

        // Detail row
        if (isExpanded) {
            const packets = (d.total_packets || 0) + (d.live_packets || 0);
            const bytes = (d.total_bytes || 0) + (d.live_bytes || 0);
            const osInfo = d.os || '';

            html += `<tr class="detail-row">
                <td colspan="8">
                    <div class="detail-panel">
                        <div class="detail-grid">
                            <div class="detail-stat">
                                <span class="detail-label">MAC Address</span>
                                <span class="detail-value mono">${escapeHtml(d.mac)}</span>
                            </div>
                            <div class="detail-stat">
                                <span class="detail-label">Vendor</span>
                                <span class="detail-value">${escapeHtml(d.vendor || 'Unknown')}</span>
                            </div>
                            <div class="detail-stat">
                                <span class="detail-label">Total Packets</span>
                                <span class="detail-value">${formatNumber(packets)}</span>
                            </div>
                            <div class="detail-stat">
                                <span class="detail-label">Total Bandwidth</span>
                                <span class="detail-value">${formatBytes(bytes)}</span>
                            </div>
                            <div class="detail-stat">
                                <span class="detail-label">1m Packets</span>
                                <span class="detail-value green">${formatNumber(d.recent_packets || 0)}</span>
                            </div>
                            <div class="detail-stat">
                                <span class="detail-label">1m Bandwidth</span>
                                <span class="detail-value green">${formatBytes(d.recent_bytes || 0)}</span>
                            </div>
                        </div>
                        <div style="margin-top:14px">
                            <span class="detail-label">Live Activity (${ACTIVITY_HISTORY_SECONDS}s)</span>
                            <div style="margin-top:6px">${renderActivityBar(d.mac)}</div>
                        </div>
                        <div style="margin-top:14px">
                            <span class="detail-label">Websites Visited (5m)</span>
                            <div style="margin-top:6px">${renderDnsQueries(d.dns_queries)}</div>
                        </div>
                    </div>
                </td>
            </tr>`;
        }
    }

    tbody.innerHTML = html;
}

function showScanModal(ip, mac) {
    const modal = document.getElementById('scan-modal');
    const device = devices.find(d => d.mac === mac);
    const name = device?.nickname || device?.hostname || ip;
    document.getElementById('scan-modal-title').textContent = `Port Scan: ${name} (${ip})`;

    // Reset loading section — restore spinner if it was replaced by checkmark
    const loadingEl = document.getElementById('scan-loading');
    const existingIcon = loadingEl.querySelector('.scan-done-icon');
    if (existingIcon) {
        existingIcon.outerHTML = '<div class="spinner"></div>';
    }
    loadingEl.classList.remove('hidden');

    document.getElementById('scan-stage-message').textContent = 'Initializing scan...';
    document.getElementById('scan-stages').innerHTML = renderScanStages(null);
    document.getElementById('scan-results').innerHTML = '';
    modal.classList.remove('hidden');
}

function renderScanStages(currentStage) {
    const currentIdx = SCAN_STAGE_ORDER.indexOf(currentStage);
    return SCAN_STAGE_ORDER.map((stage, i) => {
        let cls = 'scan-stage-item pending';
        let icon = '\u25CB';
        if (currentStage && i < currentIdx) {
            cls = 'scan-stage-item complete';
            icon = '\u2713';
        } else if (stage === currentStage) {
            cls = 'scan-stage-item active';
            icon = '\u25C9';
        }
        return `<div class="${cls}"><span class="stage-icon">${icon}</span> ${SCAN_STAGE_LABELS[stage]}</div>`;
    }).join('');
}

function showScanResults(ip, mac, results) {
    const modal = document.getElementById('scan-modal');
    const device = devices.find(d => d.mac === mac);
    const name = device?.nickname || device?.hostname || ip;
    document.getElementById('scan-modal-title').textContent = `Port Scan: ${name} (${ip})`;
    document.getElementById('scan-loading').classList.add('hidden');
    modal.classList.remove('hidden');

    const container = document.getElementById('scan-results');
    const ports = results.ports || [];

    if (ports.length === 0) {
        container.innerHTML = '<p class="no-ports">No open ports detected (top 1000 ports scanned)</p>';
        return;
    }

    const totalVulns = ports.reduce((sum, p) => sum + (p.vulns?.length || 0), 0);
    const criticalVulns = ports.reduce((sum, p) =>
        sum + (p.vulns?.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length || 0), 0);

    let html = `
        <div class="scan-summary">
            <span>Open Ports: <strong>${ports.length}</strong></span>
            <span>Vulnerabilities: <strong>${totalVulns}</strong></span>
            ${criticalVulns > 0 ? `<span style="color: var(--red)">Critical/High: <strong>${criticalVulns}</strong></span>` : ''}
            ${results.os ? `<span>OS: <strong>${escapeHtml(results.os)}</strong></span>` : ''}
        </div>
    `;

    html += ports.map(p => {
        const stateClass = p.state === 'open' ? 'state-open' :
            p.state === 'filtered' ? 'state-filtered' : 'state-closed';
        const serviceName = [p.product, p.service].filter(Boolean).join(' / ') || 'unknown';
        const version = p.version || '';

        let vulnHtml = '';
        if (p.vulns && p.vulns.length > 0) {
            vulnHtml = `<div class="vuln-list">
                ${p.vulns.slice(0, 10).map(v => `
                    <div class="vuln-item">
                        <span class="vuln-severity sev-${v.severity.toLowerCase()}">${v.severity}</span>
                        <span class="vuln-id">${escapeHtml(v.id)}</span>
                        <span class="vuln-score">CVSS: ${v.score}</span>
                        ${v.url ? `<a href="${escapeAttr(v.url)}" target="_blank" rel="noopener" style="color: var(--accent); font-size: 0.75rem;">details</a>` : ''}
                    </div>
                `).join('')}
                ${p.vulns.length > 10 ? `<div class="vuln-item" style="color: var(--text-dim)">...and ${p.vulns.length - 10} more</div>` : ''}
            </div>`;
        }

        return `<div class="port-card">
            <div class="port-header">
                <div>
                    <span class="port-number">${p.port}/${p.protocol}</span>
                    <span class="port-service">${escapeHtml(serviceName)}</span>
                    ${version ? `<span class="port-version">${escapeHtml(version)}</span>` : ''}
                </div>
                <span class="port-state ${stateClass}">${p.state}</span>
            </div>
            ${p.cpe ? `<div class="port-version">CPE: ${escapeHtml(p.cpe)}</div>` : ''}
            ${vulnHtml}
        </div>`;
    }).join('');

    container.innerHTML = html;
}

function closeModal() {
    document.getElementById('scan-modal').classList.add('hidden');
}


// --- Socket.IO events ---

socket.on('connect', () => {
    document.getElementById('monitor-status').textContent = 'Connected';
    document.getElementById('monitor-status').className = 'badge badge-active';
});

socket.on('disconnect', () => {
    document.getElementById('monitor-status').textContent = 'Disconnected';
    document.getElementById('monitor-status').className = 'badge badge-inactive';
});

socket.on('status', (data) => {
    const el = document.getElementById('monitor-status');
    if (data.monitoring) {
        el.textContent = 'Monitor: Active';
        el.className = 'badge badge-active';
    }
});

socket.on('devices_updated', () => {
    fetchDevices();
});

socket.on('traffic_update', (stats) => {
    for (const d of devices) {
        if (stats[d.ip]) {
            d.live_packets = stats[d.ip].packets;
            d.live_bytes = stats[d.ip].bytes;
            d.live_last_seen = stats[d.ip].last_seen;
            d.recent_packets = stats[d.ip].recent_packets || 0;
            d.recent_bytes = stats[d.ip].recent_bytes || 0;
            d.dns_queries = stats[d.ip].dns_queries || [];
        } else {
            d.recent_packets = 0;
            d.recent_bytes = 0;
        }
        recordActivity(d.mac, d.recent_packets, d.recent_bytes);
    }
    updateNetworkTotals();
    renderDevices();
});

socket.on('scan_progress', (data) => {
    const msgEl = document.getElementById('scan-stage-message');
    const stagesEl = document.getElementById('scan-stages');
    const spinnerEl = document.querySelector('#scan-loading .spinner');

    if (data.stage === 'complete') {
        // Replace spinner with checkmark
        if (spinnerEl) spinnerEl.outerHTML = '<div class="scan-done-icon">\u2713</div>';
        msgEl.textContent = data.message;
        stagesEl.innerHTML = renderScanStages(data.stage);
    } else {
        msgEl.textContent = data.message;
        stagesEl.innerHTML = renderScanStages(data.stage);
    }
});

socket.on('scan_complete', (data) => {
    scanningDevices.delete(data.mac);
    renderDevices();
    // Brief pause to show the checkmark, then show results
    setTimeout(() => {
        showScanResults(data.ip, data.mac, data.results);
    }, 800);
});

socket.on('scan_error', (data) => {
    scanningDevices.delete(data.mac);
    renderDevices();
    const spinnerEl = document.querySelector('#scan-loading .spinner');
    if (spinnerEl) spinnerEl.outerHTML = '<div class="scan-done-icon error">\u2717</div>';
    document.getElementById('scan-stage-message').textContent = `Scan failed: ${data.error}`;
    // Also show in results area after a moment
    setTimeout(() => {
        document.getElementById('scan-loading').classList.add('hidden');
        document.getElementById('scan-results').innerHTML =
            `<p class="no-ports" style="color: var(--red)">Scan failed: ${escapeHtml(data.error)}</p>`;
    }, 1500);
});

// Intrusion events
socket.on('intrusion_detected', (data) => {
    activeIntrusions[data.source_ip] = data;
    bannerDismissed = false;
    updateIntrusionBanner();
    updateIntrusionStats();
});

socket.on('intrusion_ended', (data) => {
    delete activeIntrusions[data.source_ip];
    updateIntrusionBanner();
    // Refresh log
    fetchIntrusionLog();
});

socket.on('intrusion_status', (data) => {
    const newActive = {};
    for (const scan of (data.active_scans || [])) {
        newActive[scan.source_ip] = scan;
    }
    const hadActive = Object.keys(activeIntrusions).length > 0;
    const hasActive = Object.keys(newActive).length > 0;
    activeIntrusions = newActive;

    // Only show banner if there are active scans and user hasn't dismissed
    if (hasActive && !hadActive) {
        bannerDismissed = false;
    }
    updateIntrusionBanner();

    // If on intrusion tab, update active card
    if (currentTab === 'intrusions') {
        updateIntrusionStats();
    }
});

// --- Utilities ---

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

function formatNumber(n) {
    if (!n) return '0';
    return n.toLocaleString();
}

function formatTimestamp(ts) {
    if (!ts) return '\u2014';
    const date = new Date(ts);
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);

    if (diffSec < 5) return 'just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function escapeAttr(str) {
    if (!str) return '';
    return str.replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

// Close modals on Escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal();
    }
});

// Close modals on backdrop click
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.add('hidden');
        }
    });
});
