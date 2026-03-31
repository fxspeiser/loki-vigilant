// Traffic Inspector - Frontend

const socket = io();
let capturing = false;
let packets = [];
let filteredPackets = [];
let peers = {};
let selectedPacket = null;
let autoScroll = true;
let currentFilter = '';
let activeInspectTab = 'stream';
const MAX_PACKETS = 5000;

// --- Init ---

document.addEventListener('DOMContentLoaded', () => {
    // Auto-start capture
    startCapture();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (capturing) {
        // Fire-and-forget stop request
        navigator.sendBeacon('/api/inspect/stop',
            new Blob([JSON.stringify({ ip: TARGET_IP })], { type: 'application/json' })
        );
    }
});

// --- Capture control ---

async function startCapture() {
    try {
        await fetch('/api/inspect/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: TARGET_IP })
        });
        capturing = true;
        updateCaptureUI();
    } catch (e) {
        console.error('Failed to start capture:', e);
    }
}

async function stopCapture() {
    try {
        await fetch('/api/inspect/stop', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: TARGET_IP })
        });
        capturing = false;
        updateCaptureUI();
    } catch (e) {
        console.error('Failed to stop capture:', e);
    }
}

function toggleCapture() {
    if (capturing) {
        stopCapture();
    } else {
        startCapture();
    }
}

function updateCaptureUI() {
    const btn = document.getElementById('btn-capture');
    const status = document.getElementById('capture-status');
    if (capturing) {
        btn.textContent = 'Stop Capture';
        btn.classList.add('btn-stop');
        status.textContent = 'Capturing';
        status.className = 'badge badge-active';
    } else {
        btn.textContent = 'Start Capture';
        btn.classList.remove('btn-stop');
        status.textContent = 'Stopped';
        status.className = 'badge badge-inactive';
    }
}

function clearPackets() {
    packets = [];
    filteredPackets = [];
    peers = {};
    selectedPacket = null;
    renderPackets();
    renderPeers();
    document.getElementById('packet-counter').textContent = 'Packets: 0';
    document.getElementById('content-view').innerHTML =
        '<div class="empty-state">Click a packet in the stream to view its content</div>';
}

// --- Tab switching ---

function switchInspectTab(tab) {
    activeInspectTab = tab;
    document.querySelectorAll('.inspect-tab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tab);
    });
    document.querySelectorAll('.inspect-tab-content').forEach(section => {
        section.classList.toggle('active', section.id === `tab-${tab}`);
    });
}

// --- Filter ---

function applyFilter() {
    currentFilter = document.getElementById('filter-input').value.toLowerCase().trim();
    if (!currentFilter) {
        filteredPackets = [...packets];
    } else {
        filteredPackets = packets.filter(p => matchesFilter(p, currentFilter));
    }
    renderPackets();
}

function matchesFilter(packet, filter) {
    // Search across multiple fields
    const fields = [
        packet.src_ip, String(packet.src_port),
        packet.dst_ip, String(packet.dst_port),
        packet.proto, packet.service,
        packet.direction, packet.payload || '',
        packet.flags,
    ];
    return fields.some(f => f && f.toLowerCase().includes(filter));
}

// --- Rendering ---

function renderPackets() {
    const tbody = document.getElementById('packets-body');
    const display = filteredPackets;

    if (display.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="empty-state">' +
            (capturing ? 'Waiting for packets...' : 'Click "Start Capture" to begin inspecting traffic') +
            '</td></tr>';
        return;
    }

    // Only render last 500 visible rows for performance
    const visible = display.slice(-500);

    let html = '';
    for (const p of visible) {
        const dirClass = p.direction === 'inbound' ? 'dir-in' : 'dir-out';
        const dirIcon = p.direction === 'inbound' ? '\u2B07' : '\u2B06';
        const encIcon = p.encrypted ? '\u{1F512}' : '\u{1F513}';
        const encClass = p.encrypted ? 'enc-yes' : 'enc-no';
        const selected = selectedPacket && selectedPacket.id === p.id ? 'selected' : '';
        const hasPayload = p.payload && p.payload.trim().length > 0;

        html += `<tr class="packet-row ${dirClass} ${selected}" onclick="selectPacket(${p.id})" ${hasPayload ? 'style="cursor:pointer"' : ''}>
            <td class="mono pkt-id">${p.id}</td>
            <td class="mono pkt-time">${escapeHtml(p.timestamp)}</td>
            <td class="${dirClass}">${dirIcon}</td>
            <td class="mono">${escapeHtml(p.src_ip)}:${p.src_port}</td>
            <td class="mono">${escapeHtml(p.dst_ip)}:${p.dst_port}</td>
            <td><span class="proto-badge proto-${p.proto.toLowerCase()}">${escapeHtml(p.proto)}</span></td>
            <td><span class="service-label">${escapeHtml(p.service)}</span></td>
            <td class="mono">${p.length}</td>
            <td><span class="${encClass}" title="${p.encrypted ? 'Encrypted' : 'Unencrypted'}">${encIcon}</span></td>
        </tr>`;
    }

    tbody.innerHTML = html;

    // Auto-scroll to bottom
    if (autoScroll) {
        const container = document.querySelector('#tab-stream');
        if (container) container.scrollTop = container.scrollHeight;
    }
}

function renderPeers() {
    const container = document.getElementById('peers-list');
    const entries = Object.entries(peers);

    if (entries.length === 0) {
        container.innerHTML = '<div class="empty-state-sm">No peers observed yet</div>';
        return;
    }

    // Sort by total packets descending
    entries.sort((a, b) => b[1].packets - a[1].packets);

    let html = '';
    for (const [ip, stats] of entries) {
        const pct = entries.length > 0
            ? Math.round((stats.packets / Math.max(packets.length, 1)) * 100)
            : 0;

        html += `<div class="peer-card" onclick="filterByPeer('${escapeAttr(ip)}')">
            <div class="peer-header">
                <span class="peer-ip">${escapeHtml(ip)}</span>
                <span class="peer-total">${formatNumber(stats.packets)} pkts</span>
            </div>
            <div class="peer-bar-bg">
                <div class="peer-bar-fill" style="width:${Math.max(pct, 2)}%"></div>
            </div>
            <div class="peer-details">
                <span class="peer-in">\u2B07 ${formatNumber(stats.inbound_packets)} / ${formatBytes(stats.inbound_bytes)}</span>
                <span class="peer-out">\u2B06 ${formatNumber(stats.outbound_packets)} / ${formatBytes(stats.outbound_bytes)}</span>
            </div>
        </div>`;
    }

    container.innerHTML = html;
}

function filterByPeer(ip) {
    const input = document.getElementById('filter-input');
    if (input.value === ip) {
        input.value = '';
    } else {
        input.value = ip;
    }
    applyFilter();
}

function selectPacket(id) {
    const pkt = packets.find(p => p.id === id);
    if (!pkt) return;
    selectedPacket = pkt;

    // Update content view
    renderContentView(pkt);

    // If on stream tab, show payload modal for packets with content
    if (activeInspectTab === 'stream' && pkt.payload && pkt.payload.trim()) {
        showPayloadModal(pkt);
    } else {
        switchInspectTab('content');
    }

    renderPackets();
}

function renderContentView(pkt) {
    const container = document.getElementById('content-view');

    const dirLabel = pkt.direction === 'inbound' ? 'Inbound' : 'Outbound';
    const dirClass = pkt.direction === 'inbound' ? 'dir-in' : 'dir-out';
    const encLabel = pkt.encrypted ? 'Encrypted' : 'Cleartext';
    const encClass = pkt.encrypted ? 'enc-yes' : 'enc-no';

    let payloadHtml;
    if (pkt.encrypted) {
        payloadHtml = `<div class="payload-encrypted">
            <span class="enc-icon">\u{1F512}</span>
            <p>This traffic is encrypted (${escapeHtml(pkt.service)}).</p>
            <p class="enc-hint">Encrypted traffic cannot be decoded without the session keys.
            Common encrypted protocols: HTTPS/TLS, SSH, encrypted MQTT, IMAPS, etc.</p>
        </div>`;
    } else if (pkt.payload && pkt.payload.trim()) {
        payloadHtml = `<pre class="payload-text">${escapeHtml(pkt.payload)}</pre>`;
    } else {
        payloadHtml = `<div class="payload-empty">No readable payload (control packet or empty)</div>`;
    }

    container.innerHTML = `
        <div class="content-header">
            <div class="content-meta">
                <span class="content-id">#${pkt.id}</span>
                <span class="${dirClass}">${dirLabel}</span>
                <span class="proto-badge proto-${pkt.proto.toLowerCase()}">${escapeHtml(pkt.proto)}</span>
                <span class="service-label">${escapeHtml(pkt.service)}</span>
                <span class="${encClass}">${encLabel}</span>
                <span class="mono">${pkt.length} bytes</span>
            </div>
            <div class="content-endpoints">
                <span class="mono">${escapeHtml(pkt.src_ip)}:${pkt.src_port}</span>
                <span class="content-arrow">\u2192</span>
                <span class="mono">${escapeHtml(pkt.dst_ip)}:${pkt.dst_port}</span>
            </div>
        </div>
        <div class="content-payload">
            <h4>Payload</h4>
            ${payloadHtml}
        </div>
    `;
}

function showPayloadModal(pkt) {
    const modal = document.getElementById('payload-modal');
    const title = document.getElementById('payload-modal-title');
    const body = document.getElementById('payload-modal-body');

    const dirLabel = pkt.direction === 'inbound' ? '\u2B07 Inbound' : '\u2B06 Outbound';
    title.textContent = `#${pkt.id} ${pkt.service} ${dirLabel} (${pkt.length} bytes)`;

    if (pkt.encrypted) {
        body.innerHTML = `<div class="payload-encrypted">
            <span class="enc-icon">\u{1F512}</span>
            <p>Encrypted ${escapeHtml(pkt.service)} traffic</p>
        </div>`;
    } else if (pkt.payload && pkt.payload.trim()) {
        body.innerHTML = `<div class="payload-modal-meta">
            <span class="mono">${escapeHtml(pkt.src_ip)}:${pkt.src_port} \u2192 ${escapeHtml(pkt.dst_ip)}:${pkt.dst_port}</span>
            <span>${escapeHtml(pkt.proto)} / ${escapeHtml(pkt.service)}</span>
        </div>
        <pre class="payload-text">${escapeHtml(pkt.payload)}</pre>`;
    } else {
        body.innerHTML = '<div class="payload-empty">No readable payload</div>';
    }

    modal.classList.remove('hidden');
}

function closePayloadModal() {
    document.getElementById('payload-modal').classList.add('hidden');
}

// --- Socket.IO events ---

socket.on('connect', () => {
    console.log('Connected to inspector');
});

socket.on('inspect_packet', (data) => {
    if (data.ip !== TARGET_IP) return;

    const pkt = data.packet;
    packets.push(pkt);

    // Cap stored packets
    if (packets.length > MAX_PACKETS) {
        packets = packets.slice(-MAX_PACKETS);
    }

    // Update peer stats locally
    const peer = pkt.peer_ip;
    if (!peers[peer]) {
        peers[peer] = {
            packets: 0, bytes: 0,
            inbound_packets: 0, inbound_bytes: 0,
            outbound_packets: 0, outbound_bytes: 0,
        };
    }
    const ps = peers[peer];
    ps.packets++;
    ps.bytes += pkt.length;
    if (pkt.direction === 'inbound') {
        ps.inbound_packets++;
        ps.inbound_bytes += pkt.length;
    } else {
        ps.outbound_packets++;
        ps.outbound_bytes += pkt.length;
    }

    // Apply filter
    if (!currentFilter || matchesFilter(pkt, currentFilter)) {
        filteredPackets.push(pkt);
        if (filteredPackets.length > MAX_PACKETS) {
            filteredPackets = filteredPackets.slice(-MAX_PACKETS);
        }
    }

    // Update counter
    document.getElementById('packet-counter').textContent = `Packets: ${formatNumber(packets.length)}`;

    // Throttled rendering
    requestAnimationFrame(() => {
        renderPackets();
        // Update peers less frequently
        if (packets.length % 5 === 0) {
            renderPeers();
        }
    });
});

socket.on('inspect_peers', (data) => {
    if (data.ip !== TARGET_IP) return;
    peers = data.peers;
    renderPeers();
});

socket.on('inspect_error', (data) => {
    if (data.ip !== TARGET_IP) return;
    console.error('Inspector error:', data.error);
    capturing = false;
    updateCaptureUI();
});

// --- Utilities ---

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

function formatNumber(n) {
    if (!n) return '0';
    return n.toLocaleString();
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

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closePayloadModal();
    // Space to toggle capture when not in input
    if (e.key === ' ' && e.target.tagName !== 'INPUT') {
        e.preventDefault();
        toggleCapture();
    }
});

// Close modal on backdrop click
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.classList.add('hidden');
    });
});
