"""Accessible, offline-first Web Control Center hosted on the Master phone."""

from __future__ import annotations

import json
import logging
import shlex
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .auth import verify_token
from .config import (
    DEFAULT_SSH_PORT,
    DEFAULT_WORKER_PORT,
    NodeConfig,
    save_config,
)
from .discovery import detect_local_ip, discover_lan_nodes
from .doctor import run_doctor
from .master import JobSpec, MasterController

LOG = logging.getLogger("phonecluster.dashboard")

MAX_DASHBOARD_BODY = 2 * 1024 * 1024

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en" data-theme="dark" data-scale="normal">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>PhoneCluster — Unified Control Center</title>
<style>
  :root {
    --font-size: 16px;
    --bg: #0d1117;
    --surface: #161b22;
    --surface-2: #1f2630;
    --border: #30363d;
    --fg: #e6edf3;
    --muted: #9aa7b8;
    --accent: #58a6ff;
    --accent-fg: #0b1016;
    --ok: #3fb950;
    --ok-bg: rgba(63, 185, 80, 0.16);
    --warn: #e3b341;
    --warn-bg: rgba(227, 179, 65, 0.18);
    --bad: #f85149;
    --bad-bg: rgba(248, 81, 73, 0.18);
    --focus: #ffd33d;
  }
  [data-theme="light"] {
    --bg: #f4f6f9;
    --surface: #ffffff;
    --surface-2: #eef2f6;
    --border: #cbd5e1;
    --fg: #0f172a;
    --muted: #475569;
    --accent: #1d4ed8;
    --accent-fg: #ffffff;
    --ok: #15803d;
    --ok-bg: #dcfce7;
    --warn: #a16207;
    --warn-bg: #fef3c7;
    --bad: #b91c1c;
    --bad-bg: #fee2e2;
    --focus: #1d4ed8;
  }
  [data-theme="contrast"] {
    --bg: #000000;
    --surface: #0a0a0a;
    --surface-2: #161616;
    --border: #ffffff;
    --fg: #ffffff;
    --muted: #e5e5e5;
    --accent: #ffea00;
    --accent-fg: #000000;
    --ok: #00ff66;
    --ok-bg: #003314;
    --warn: #ffea00;
    --warn-bg: #332e00;
    --bad: #ff4d4d;
    --bad-bg: #3b0000;
    --focus: #00ffff;
  }
  [data-scale="large"] { --font-size: 18px; }
  [data-scale="xl"] { --font-size: 20px; }

  * { box-sizing: border-box; }
  html { font-size: var(--font-size); }
  body {
    margin: 0;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--fg);
    line-height: 1.5;
  }
  .skip-link {
    position: absolute; left: -9999px; top: 8px;
    background: var(--accent); color: var(--accent-fg);
    padding: 8px 14px; border-radius: 6px; font-weight: 700; z-index: 1000;
  }
  .skip-link:focus { left: 12px; }
  :focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }

  .wrap { max-width: 1180px; margin: 0 auto; padding: 16px; }
  header.topbar {
    display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between;
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 14px 18px; margin-bottom: 14px;
  }
  .brand h1 { margin: 0; font-size: 1.35rem; line-height: 1.2; }
  .brand .sub { color: var(--muted); font-size: 0.85rem; margin-top: 2px; }
  .controls { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }

  button, input, select, textarea {
    font: inherit; color: var(--fg); background: var(--surface-2);
    border: 1px solid var(--border); border-radius: 8px; padding: 7px 11px;
  }
  button { cursor: pointer; font-weight: 600; transition: opacity .15s; }
  button:hover { opacity: 0.9; }
  button.primary { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
  button.danger { background: var(--bad-bg); color: var(--bad); border-color: var(--bad); }
  button.ghost { background: transparent; }
  button.small { padding: 5px 9px; font-size: 0.85rem; }

  nav.tabs {
    display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px;
    border-bottom: 2px solid var(--border); padding-bottom: 10px;
  }
  nav.tabs button[role="tab"] {
    background: var(--surface); border: 1px solid var(--border); color: var(--fg);
    padding: 8px 14px; border-radius: 8px;
  }
  nav.tabs button[role="tab"][aria-selected="true"] {
    background: var(--accent); color: var(--accent-fg); border-color: var(--accent);
  }

  .panel { display: none; }
  .panel.active { display: block; }

  .banner {
    border-radius: 10px; padding: 12px 16px; margin-bottom: 14px;
    border: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; gap: 12px;
  }
  .banner.warn { background: var(--warn-bg); border-color: var(--warn); }
  .banner.ok { background: var(--ok-bg); border-color: var(--ok); }
  .banner.hidden { display: none; }

  .stats-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px; margin-bottom: 16px;
  }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px; margin-bottom: 14px;
  }
  .card h2, .card h3 { margin: 0 0 10px; font-size: 1.05rem; }
  .stat-label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
  .stat-val { font-size: 1.55rem; font-weight: 700; margin-top: 4px; }

  .nodes-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(310px, 1fr)); gap: 14px;
  }
  .node-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 15px;
  }
  .node-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 10px; }
  .node-title { font-weight: 700; font-size: 1.05rem; }
  .node-meta { color: var(--muted); font-size: 0.85rem; }

  .pill {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 3px 9px; border-radius: 999px; font-size: 0.8rem; font-weight: 700; white-space: nowrap;
  }
  .pill.ok { background: var(--ok-bg); color: var(--ok); border: 1px solid var(--ok); }
  .pill.warn { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn); }
  .pill.bad { background: var(--bad-bg); color: var(--bad); border: 1px solid var(--bad); }
  .pill.neutral { background: var(--surface-2); color: var(--muted); border: 1px solid var(--border); }

  .metric-row { margin: 8px 0; font-size: 0.88rem; }
  .metric-head { display: flex; justify-content: space-between; margin-bottom: 3px; }
  .bar { height: 8px; background: var(--surface-2); border-radius: 999px; overflow: hidden; border: 1px solid var(--border); }
  .bar > span { display: block; height: 100%; background: var(--accent); }
  .bar.warn > span { background: var(--warn); }
  .bar.bad > span { background: var(--bad); }
  .bar.ok > span { background: var(--ok); }

  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
  .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
  .col-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 14px; }
  textarea { width: 100%; min-height: 110px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.88rem; }
  pre.code {
    background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
    padding: 12px; overflow: auto; max-height: 360px; margin: 8px 0 0;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85rem; white-space: pre-wrap;
  }
  .auth-bar {
    background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
    padding: 10px 14px; margin-bottom: 14px; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: space-between;
  }
  .check-item {
    border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; margin-bottom: 8px;
    background: var(--surface-2);
  }
  .hint { color: var(--muted); font-size: 0.85rem; margin-top: 4px; }
  .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0,0,0,0); }

  @media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation: none !important; }
  }
</style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
<div class="wrap">
  <header class="topbar">
    <div class="brand">
      <h1 id="cluster-title">PhoneCluster</h1>
      <div class="sub" id="last-updated" aria-live="polite">Connecting to cluster...</div>
    </div>
    <div class="controls" aria-label="Display and refresh controls">
      <label class="sr-only" for="theme-select">Color theme</label>
      <select id="theme-select" title="Color theme" aria-label="Color theme">
        <option value="dark">Theme: Dark</option>
        <option value="light">Theme: Light</option>
        <option value="contrast">Theme: High Contrast</option>
      </select>
      <label class="sr-only" for="scale-select">Text size</label>
      <select id="scale-select" title="Text size" aria-label="Text size">
        <option value="normal">Text: Normal</option>
        <option value="large">Text: Large</option>
        <option value="xl">Text: XL</option>
      </select>
      <button id="btn-auto" class="small" aria-pressed="true" onclick="toggleAutoRefresh()">Auto-Refresh: ON</button>
      <button class="small primary" onclick="refreshAll()">Refresh Now</button>
    </div>
  </header>

  <section class="auth-bar" aria-label="Cluster authentication">
    <div class="row" style="margin:0; flex:1; min-width:240px;">
      <span id="auth-pill" class="pill neutral">Read-Only Mode</span>
      <label class="sr-only" for="auth-token">Cluster auth token</label>
      <input id="auth-token" type="password" placeholder="Paste auth_token from cluster.json to unlock Run / Add Phone" style="flex:1; min-width:220px" />
      <button class="small primary" onclick="saveToken()">Unlock</button>
      <button class="small ghost" onclick="clearToken()">Lock</button>
    </div>
    <div class="hint" style="margin:0;">Status &amp; diagnostics work without unlocking; running commands requires your token.</div>
  </section>

  <div id="battery-banner" class="banner warn hidden" role="status" aria-live="polite">
    <div><strong>24/7 Battery Safety Alert:</strong> <span id="battery-banner-text"></span></div>
  </div>

  <nav class="tabs" role="tablist" aria-label="Control Center Sections">
    <button role="tab" id="tab-overview" aria-selected="true" aria-controls="panel-overview" onclick="selectTab('overview')">1. Overview</button>
    <button role="tab" id="tab-jobs" aria-selected="false" aria-controls="panel-jobs" onclick="selectTab('jobs')">2. Run &amp; Parallel Jobs</button>
    <button role="tab" id="tab-workloads" aria-selected="false" aria-controls="panel-workloads" onclick="selectTab('workloads')">3. Workloads (AI / Compiler / HA)</button>
    <button role="tab" id="tab-setup" aria-selected="false" aria-controls="panel-setup" onclick="selectTab('setup')">4. Add Phone &amp; Doctor</button>
  </nav>

  <main id="main-content">
    <!-- TAB 1: OVERVIEW -->
    <section id="panel-overview" class="panel active" role="tabpanel" aria-labelledby="tab-overview">
      <div class="stats-grid" aria-label="Unified cluster totals">
        <div class="card" style="margin:0"><div class="stat-label">Phones Ready</div><div class="stat-val" id="s-nodes">-</div></div>
        <div class="card" style="margin:0"><div class="stat-label">Combined CPU</div><div class="stat-val" id="s-cores">-</div></div>
        <div class="card" style="margin:0"><div class="stat-label">Combined Free RAM</div><div class="stat-val" id="s-ram">-</div></div>
        <div class="card" style="margin:0"><div class="stat-label">Peak Temp</div><div class="stat-val" id="s-temp">-</div></div>
      </div>
      <div id="nodes-grid" class="nodes-grid" aria-live="polite"></div>
    </section>

    <!-- TAB 2: RUN & PARALLEL JOBS -->
    <section id="panel-jobs" class="panel" role="tabpanel" aria-labelledby="tab-jobs">
      <div class="col-grid">
        <div class="card">
          <h2>Run Single Command</h2>
          <div class="row">
            <label for="run-target">Target:</label>
            <select id="run-target">
              <option value="best">Smart: Best Coolest Phone</option>
              <option value="all">All Ready Phones</option>
            </select>
          </div>
          <div class="row">
            <label class="sr-only" for="run-cmd">Shell command</label>
            <input id="run-cmd" type="text" placeholder="e.g. uname -a && nproc" style="flex:1; min-width:200px" />
            <button class="primary" onclick="runSingleCmd()">Run</button>
          </div>
          <div class="row" aria-label="Quick presets">
            <span class="hint" style="margin:0">Presets:</span>
            <button class="small" onclick="setPreset('uname -a && nproc')">System Info</button>
            <button class="small" onclick="setPreset('df -h ~')">Disk Space</button>
            <button class="small" onclick="setPreset('uptime && free -m 2>/dev/null || head -n 3 /proc/meminfo')">Load &amp; RAM</button>
          </div>
          <pre id="run-out" class="code" aria-live="polite">Output will appear here.</pre>
        </div>

        <div class="card">
          <h2>Parallel Batch Runner (All Ready Phones)</h2>
          <div class="row">
            <label for="map-mode">Mode:</label>
            <select id="map-mode" onchange="toggleMapMode()">
              <option value="commands">List of Shell Commands (1 per line)</option>
              <option value="script">Ship &amp; Run Script + Arguments List</option>
            </select>
            <button class="primary" onclick="runParallelMap()">Run Batch Across Cluster</button>
          </div>
          <div id="map-commands-box">
            <label for="map-commands" class="hint">Commands (one per line):</label>
            <textarea id="map-commands">echo "Job 1 on $PHONECLUSTER_NODE_ID"
echo "Job 2 on $PHONECLUSTER_NODE_ID"
echo "Job 3 on $PHONECLUSTER_NODE_ID"
echo "Job 4 on $PHONECLUSTER_NODE_ID"</textarea>
          </div>
          <div id="map-script-box" style="display:none">
            <div class="row">
              <label for="map-interp">Interpreter:</label>
              <select id="map-interp">
                <option value="python3">python3</option>
                <option value="bash">bash</option>
                <option value="sh">sh</option>
              </select>
            </div>
            <label for="map-script" class="hint">Script source (automatically shipped to every ready phone):</label>
            <textarea id="map-script">import os, sys
n = int(sys.argv[1])
print(f"node={os.environ.get('PHONECLUSTER_NODE_ID')} square({n})={n*n}")</textarea>
            <label for="map-args" class="hint">Arguments list (one run per line):</label>
            <textarea id="map-args" style="min-height:80px">10
20
30
40</textarea>
          </div>
          <pre id="map-out" class="code" aria-live="polite">Batch results will appear here.</pre>
        </div>
      </div>
    </section>

    <!-- TAB 3: WORKLOADS -->
    <section id="panel-workloads" class="panel" role="tabpanel" aria-labelledby="tab-workloads">
      <div class="col-grid">
        <div class="card">
          <h2>Compiler PC (distcc)</h2>
          <p class="hint">Spread C/C++ builds across all healthy ARM64 cores.</p>
          <div class="row">
            <input id="distcc-cidr" type="text" value="192.168.1.0/24" aria-label="Allowed LAN subnet" style="width:165px" />
            <button class="small primary" onclick="workloadAction('distcc-start')">Start All</button>
            <button class="small danger" onclick="workloadAction('distcc-stop')">Stop All</button>
            <button class="small" onclick="copyEl('wl-distcc')">Copy Export</button>
          </div>
          <pre id="wl-distcc" class="code">Loading...</pre>
        </div>

        <div class="card">
          <h2>Local AI (llama.cpp RPC)</h2>
          <p class="hint">Pool phone RAM via RPC, or use Parallel Batch to run compact 1.5B–3B models per phone.</p>
          <div class="row">
            <button class="small primary" onclick="workloadAction('llama-rpc-start')">Start RPC Workers</button>
            <button class="small danger" onclick="workloadAction('llama-rpc-stop')">Stop All</button>
            <button class="small" onclick="copyEl('wl-llama')">Copy Flag</button>
          </div>
          <pre id="wl-llama" class="code">Loading...</pre>
        </div>

        <div class="card">
          <h2>OpenMPI HPC Hostfile</h2>
          <div class="row">
            <button class="small" onclick="copyEl('wl-mpi')">Copy Hostfile</button>
          </div>
          <pre id="wl-mpi" class="code">Loading...</pre>
        </div>

        <div class="card">
          <h2>Home Assistant, Debian 13 &amp; Docker</h2>
          <div id="wl-services" class="hint">Checking cluster services...</div>
          <pre id="wl-action-out" class="code" style="display:none"></pre>
        </div>
      </div>
    </section>

    <!-- TAB 4: ADD PHONE & DOCTOR -->
    <section id="panel-setup" class="panel" role="tabpanel" aria-labelledby="tab-setup">
      <div class="col-grid">
        <div class="card">
          <h2>Auto-Discover Phones on Wi-Fi</h2>
          <p class="hint">Boot a new phone with Termux + PhoneCluster worker, then scan your LAN to add it in one click.</p>
          <div class="row">
            <button class="primary" onclick="scanLan()">Scan Wi-Fi Now (2s)</button>
          </div>
          <div id="discover-list" aria-live="polite" class="hint">Click "Scan Wi-Fi Now" to find nearby phones.</div>
          <h3 style="margin-top:16px">One-Command Phone Installer</h3>
          <p class="hint">Run this inside Termux on any Android 7+ phone:</p>
          <pre id="install-snippet" class="code">pkg install -y git && git clone &lt;your-repo-url&gt; ~/phonecluster && bash ~/phonecluster/install.sh</pre>
        </div>

        <div class="card">
          <h2>Cluster Doctor (Health &amp; Safety Audit)</h2>
          <p class="hint">Checks SSH, Termux:API, thermal throttling, config security, and 24/7 battery safety.</p>
          <div class="row">
            <button class="primary" onclick="runDoctorUi()">Run Doctor Now</button>
          </div>
          <div id="doctor-list" aria-live="polite" class="hint">Click "Run Doctor Now" to inspect your cluster.</div>
        </div>
      </div>
    </section>
  </main>
</div>

<script>
let autoRefresh = true;
let refreshTimer = null;
let lastSummary = null;

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function getToken() {
  return sessionStorage.getItem('pc_token') || '';
}
function updateAuthBadge() {
  const pill = document.getElementById('auth-pill');
  const inp = document.getElementById('auth-token');
  if (getToken()) {
    pill.textContent = '✓ Unlocked';
    pill.className = 'pill ok';
    inp.value = '••••••••••••';
  } else {
    pill.textContent = 'Read-Only Mode';
    pill.className = 'pill neutral';
    inp.value = '';
  }
}
function saveToken() {
  const v = document.getElementById('auth-token').value.trim();
  if (!v || v.startsWith('••')) return;
  sessionStorage.setItem('pc_token', v);
  updateAuthBadge();
}
function clearToken() {
  sessionStorage.removeItem('pc_token');
  updateAuthBadge();
}

function initPreferences() {
  const savedTheme = localStorage.getItem('pc_theme') ||
    (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  const savedScale = localStorage.getItem('pc_scale') || 'normal';
  document.documentElement.dataset.theme = savedTheme;
  document.documentElement.dataset.scale = savedScale;
  document.getElementById('theme-select').value = savedTheme;
  document.getElementById('scale-select').value = savedScale;

  document.getElementById('theme-select').addEventListener('change', e => {
    document.documentElement.dataset.theme = e.target.value;
    localStorage.setItem('pc_theme', e.target.value);
  });
  document.getElementById('scale-select').addEventListener('change', e => {
    document.documentElement.dataset.scale = e.target.value;
    localStorage.setItem('pc_scale', e.target.value);
  });
}

function selectTab(name) {
  const tabs = ['overview', 'jobs', 'workloads', 'setup'];
  for (const t of tabs) {
    const btn = document.getElementById('tab-' + t);
    const panel = document.getElementById('panel-' + t);
    const active = t === name;
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
    panel.classList.toggle('active', active);
  }
  if (name === 'workloads') loadWorkloads();
}

document.querySelector('nav.tabs').addEventListener('keydown', e => {
  const btns = Array.from(document.querySelectorAll('nav.tabs button[role="tab"]'));
  const idx = btns.indexOf(document.activeElement);
  if (idx === -1) return;
  if (e.key === 'ArrowRight') { btns[(idx + 1) % btns.length].focus(); btns[(idx + 1) % btns.length].click(); }
  if (e.key === 'ArrowLeft') { btns[(idx - 1 + btns.length) % btns.length].focus(); btns[(idx - 1 + btns.length) % btns.length].click(); }
});

function toggleAutoRefresh() {
  autoRefresh = !autoRefresh;
  const btn = document.getElementById('btn-auto');
  btn.textContent = 'Auto-Refresh: ' + (autoRefresh ? 'ON' : 'OFF');
  btn.setAttribute('aria-pressed', autoRefresh ? 'true' : 'false');
}

function metricBar(label, valueText, pct, tone) {
  const clamped = Math.max(0, Math.min(100, pct || 0));
  return '<div class="metric-row">'
    + '<div class="metric-head"><span>' + esc(label) + '</span><span>' + esc(valueText) + '</span></div>'
    + '<div class="bar ' + esc(tone || '') + '"><span style="width:' + clamped + '%"></span></div>'
    + '</div>';
}

async function refreshStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    lastSummary = d;

    document.getElementById('cluster-title').textContent = d.cluster_name + ' — Unified Control Center';
    document.getElementById('last-updated').textContent = 'Last synced ' + new Date().toLocaleTimeString();
    document.getElementById('s-nodes').textContent = d.nodes_ready + ' / ' + d.nodes_total;
    document.getElementById('s-cores').textContent = d.total_cores + ' cores';
    document.getElementById('s-ram').textContent = (d.mem_available_mb / 1024).toFixed(2) + ' / ' + (d.mem_total_mb / 1024).toFixed(2) + ' GB';
    document.getElementById('s-temp').textContent = d.max_temp_c !== null ? d.max_temp_c.toFixed(1) + ' °C' : 'N/A';

    // Populate individual target selector cleanly
    const targetSel = document.getElementById('run-target');
    const prevVal = targetSel.value;
    targetSel.innerHTML = '<option value="best">Smart: Best Coolest Phone</option><option value="all">All Ready Phones</option>';
    for (const n of d.nodes) {
      const opt = document.createElement('option');
      opt.value = n.id;
      opt.textContent = n.id + ' (' + n.role + ' — ' + n.host + ')';
      targetSel.appendChild(opt);
    }
    if (Array.from(targetSel.options).some(o => o.value === prevVal)) targetSel.value = prevVal;

    // 24/7 Battery safety banner
    const batWarnings = [];
    const grid = document.getElementById('nodes-grid');
    grid.innerHTML = '';

    for (const n of d.nodes) {
      const h = n.health || {};
      let badge = '<span class="pill bad">✕ OFFLINE</span>';
      if (n.online && n.ready_for_jobs) badge = '<span class="pill ok">✓ READY (' + (h.active_jobs || 0) + '/' + (h.max_concurrency || 2) + ')</span>';
      else if (n.online) badge = '<span class="pill warn">⚠ ' + esc((h.not_ready_reasons || ['PAUSED']).join(', ')) + '</span>';

      if (n.online && h.battery_pct != null && h.battery_pct >= 60 && (h.battery_status === 'CHARGING' || h.battery_status === 'FULL')) {
        batWarnings.push(n.id + ' is at ' + h.battery_pct + '% (' + h.battery_status + ')');
      }

      let bodyHtml = '';
      if (!n.online) {
        bodyHtml = '<p class="hint">Unreachable: ' + esc(n.error || 'connection refused') + '</p>';
      } else {
        const cores = h.cpu_cores || 1;
        const loadPct = ((h.load_1m || 0) / cores) * 100;
        const ramUsedPct = h.mem_total_mb ? ((h.mem_total_mb - h.mem_available_mb) / h.mem_total_mb) * 100 : 0;
        const temp = h.temp_c;
        const tempTone = temp == null ? '' : (temp >= 40 ? 'bad' : (temp >= 37 ? 'warn' : 'ok'));
        const bat = h.battery_pct;
        const batTone = bat == null ? '' : (bat >= 80 && h.battery_status === 'CHARGING' ? 'warn' : (bat < 20 ? 'bad' : 'ok'));

        bodyHtml += metricBar('CPU Load', cores + ' cores · load ' + (h.load_1m ?? 0), loadPct, loadPct > 85 ? 'warn' : '');
        bodyHtml += metricBar('RAM Used', (h.mem_available_mb || 0) + ' MB free / ' + (h.mem_total_mb || 0) + ' MB', ramUsedPct, ramUsedPct > 85 ? 'bad' : '');
        bodyHtml += metricBar('Temperature', temp != null ? temp.toFixed(1) + ' °C' : 'N/A', temp != null ? (temp / 50) * 100 : 0, tempTone);
        bodyHtml += metricBar('Battery', bat != null ? bat + '% (' + (h.battery_status || '?') + ')' : 'N/A', bat ?? 0, batTone);

        const svcs = Object.entries(h.services || {}).filter(([, v]) => v).map(([k]) => k.split('_')[0]);
        bodyHtml += '<div class="chips">'
          + '<span class="pill neutral">' + esc(h.os_env || 'linux') + '</span>'
          + '<span class="pill neutral">' + esc(n.latency_ms) + ' ms</span>'
          + svcs.map(s => '<span class="pill ok">' + esc(s) + '</span>').join('')
          + '</div>';
      }

      const card = document.createElement('article');
      card.className = 'node-card';
      card.innerHTML = '<div class="node-head">'
        + '<div><div class="node-title">' + esc(n.id) + ' <small style="color:var(--muted);font-weight:400">(' + esc(n.role) + ')</small></div>'
        + '<div class="node-meta">' + esc(n.host) + '</div></div>'
        + badge + '</div>' + bodyHtml;
      grid.appendChild(card);
    }

    const banner = document.getElementById('battery-banner');
    if (batWarnings.length) {
      document.getElementById('battery-banner-text').textContent = batWarnings.join('; ')
        + '. Avoid leaving Li-Po batteries pinned at 100% 24/7 (use a smart plug webhook or rooted ACC).';
      banner.classList.remove('hidden');
    } else {
      banner.classList.add('hidden');
    }
  } catch (e) {
    document.getElementById('last-updated').textContent = 'Connection error: ' + e;
  }
}

async function loadWorkloads() {
  try {
    const r = await fetch('/api/workloads');
    const d = await r.json();
    document.getElementById('wl-distcc').textContent = d.distcc_hosts
      ? 'export DISTCC_HOSTS="' + d.distcc_hosts + '"'
      : '# No running distccd workers detected (click Start All above).';
    document.getElementById('wl-llama').textContent = d.llama_rpc
      ? '--rpc ' + d.llama_rpc
      : '# No running llama.cpp rpc-server detected on port 50052.';
    document.getElementById('wl-mpi').textContent = d.mpi_hostfile || '# No ready nodes available.';

    let svcHtml = '';
    if (d.home_assistant_urls && d.home_assistant_urls.length) {
      svcHtml += '<p><strong>✓ Home Assistant detected:</strong> '
        + d.home_assistant_urls.map(u => '<a href="' + esc(u) + '" target="_blank" rel="noopener" style="color:var(--accent)">' + esc(u) + '</a>').join(', ')
        + '</p>';
    } else {
      svcHtml += '<p><strong>Home Assistant:</strong> Not detected on port 8123. Best deployed on Tier 2 (Rooted Debian 13 chroot) or Tier 3 (Docker).</p>';
    }
    svcHtml += '<p><strong>Docker-ready nodes:</strong> ' + (d.docker_nodes.length ? esc(d.docker_nodes.join(', ')) : 'None yet (requires Tier 3 custom kernel + Droidspaces)') + '</p>';
    document.getElementById('wl-services').innerHTML = svcHtml;
  } catch (e) {
    document.getElementById('wl-distcc').textContent = 'Error loading workloads: ' + e;
  }
}

function setPreset(cmd) {
  document.getElementById('run-cmd').value = cmd;
}

async function authPost(url, payload) {
  const token = getToken();
  if (!token) {
    return { error: 'Controls are locked. Paste your auth_token in the top bar and click Unlock.' };
  }
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify(payload),
  });
  return await r.json();
}

async function runSingleCmd() {
  const cmd = document.getElementById('run-cmd').value.trim();
  const target = document.getElementById('run-target').value;
  if (!cmd) return;
  const out = document.getElementById('run-out');
  out.textContent = 'Running across cluster...';
  const data = await authPost('/api/exec', { command: cmd, target });
  if (data.error) { out.textContent = 'Error: ' + data.error; return; }
  out.textContent = (data.results || []).map(res => {
    const head = '=== [' + res.node_id + '] ' + (res.ok ? 'OK' : 'FAIL rc=' + res.returncode) + ' (' + res.duration_sec + 's) ===';
    return [head, res.stdout, res.stderr ? '[stderr]\n' + res.stderr : '', res.error ? '[error] ' + res.error : '']
      .filter(Boolean).join('\n');
  }).join('\n\n');
}

function toggleMapMode() {
  const mode = document.getElementById('map-mode').value;
  document.getElementById('map-commands-box').style.display = mode === 'commands' ? 'block' : 'none';
  document.getElementById('map-script-box').style.display = mode === 'script' ? 'block' : 'none';
}

async function runParallelMap() {
  const mode = document.getElementById('map-mode').value;
  const out = document.getElementById('map-out');
  out.textContent = 'Dispatching parallel batch across all ready phones...';
  let payload;
  if (mode === 'commands') {
    const commands = document.getElementById('map-commands').value.split('\n').map(s => s.trim()).filter(Boolean);
    payload = { mode: 'commands', commands };
  } else {
    const script_content = document.getElementById('map-script').value;
    const interpreter = document.getElementById('map-interp').value;
    const args_lines = document.getElementById('map-args').value.split('\n').map(s => s.trim()).filter(Boolean);
    payload = { mode: 'script', script_content, interpreter, args_lines };
  }
  const data = await authPost('/api/map', payload);
  if (data.error) { out.textContent = 'Error: ' + data.error; return; }
  const dist = Object.entries(data.distribution || {}).map(([k, v]) => k + ':' + v).join(', ');
  let txt = 'Done in ' + data.wall_sec + 's | OK=' + data.ok_count + ' FAIL=' + data.fail_count + ' | Distribution: ' + dist + '\n\n';
  for (const r of (data.results || [])) {
    txt += '[' + (r.ok ? 'OK' : 'FAIL') + '] ' + r.node_id + ' (' + r.duration_sec + 's) ' + r.label + '\n  '
      + (r.stdout || r.stderr || r.error || '').trim().replace(/\n/g, '\n  ') + '\n';
  }
  out.textContent = txt;
  refreshStatus();
}

async function workloadAction(action) {
  const cidr = document.getElementById('distcc-cidr').value.trim() || '192.168.1.0/24';
  const out = document.getElementById('wl-action-out');
  out.style.display = 'block';
  out.textContent = 'Running ' + action + ' on all ready phones...';
  const data = await authPost('/api/workloads/action', { action, cidr });
  out.textContent = JSON.stringify(data, null, 2);
  setTimeout(loadWorkloads, 800);
}

async function scanLan() {
  const box = document.getElementById('discover-list');
  box.innerHTML = 'Scanning Wi-Fi (2 seconds)...';
  try {
    const r = await fetch('/api/discover');
    const d = await r.json();
    if (!d.discovered || !d.discovered.length) {
      box.innerHTML = '<p class="hint">No phones answered UDP discovery on port 8766. Make sure worker daemons are running on the same Wi-Fi.</p>';
      return;
    }
    box.innerHTML = d.discovered.map(item => {
      const btn = item.already_configured
        ? '<span class="pill ok">✓ Already in Cluster</span>'
        : '<button class="small primary" onclick="addDiscoveredNode(\'' + esc(item.host) + '\',' + Number(item.worker_port) + ',' + Number(item.ssh_port) + ',\'' + esc(item.ssh_user) + '\')">+ Add to Cluster</button>';
      return '<div class="check-item" style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">'
        + '<div><strong>' + esc(item.host) + '</strong> (' + esc(item.os_env) + ', ' + esc(item.cpu_cores) + ' cores, ' + esc(item.mem_total_mb) + ' MB RAM)</div>'
        + btn + '</div>';
    }).join('');
  } catch (e) {
    box.textContent = 'Discovery failed: ' + e;
  }
}

async function addDiscoveredNode(host, worker_port, ssh_port, ssh_user) {
  const data = await authPost('/api/nodes/add', { host, worker_port, ssh_port, ssh_user });
  if (data.error) { alert('Could not add node: ' + data.error); return; }
  alert('Added ' + data.node.id + ' (' + data.node.host + ') to cluster.json!');
  scanLan();
  refreshStatus();
}

async function runDoctorUi() {
  const box = document.getElementById('doctor-list');
  box.innerHTML = 'Running diagnostics...';
  try {
    const r = await fetch('/api/doctor');
    const d = await r.json();
    const icons = { ok: '✓ OK', warn: '⚠ WARN', fail: '✕ FAIL' };
    const cls = { ok: 'ok', warn: 'warn', fail: 'bad' };
    box.innerHTML = (d.checks || []).map(c =>
      '<div class="check-item">'
      + '<span class="pill ' + (cls[c.status] || 'neutral') + '">' + (icons[c.status] || c.status) + '</span> '
      + '<strong>' + esc(c.name) + '</strong>: ' + esc(c.detail)
      + (c.fix_hint ? '<div class="hint">Fix: ' + esc(c.fix_hint) + '</div>' : '')
      + '</div>'
    ).join('');
  } catch (e) {
    box.textContent = 'Doctor failed: ' + e;
  }
}

function copyEl(id) {
  const txt = document.getElementById(id).textContent;
  if (navigator.clipboard) navigator.clipboard.writeText(txt);
}

function refreshAll() {
  refreshStatus();
  if (document.getElementById('panel-workloads').classList.contains('active')) loadWorkloads();
}

initPreferences();
updateAuthBadge();
refreshStatus();
refreshTimer = setInterval(() => { if (autoRefresh) refreshStatus(); }, 5000);
</script>
</body>
</html>
"""


class DashboardHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        addr: tuple[str, int],
        controller: MasterController,
        config_path: Path | None = None,
    ) -> None:
        self.controller = controller
        self.config_path = config_path
        super().__init__(addr, DashboardRequestHandler)


class DashboardRequestHandler(BaseHTTPRequestHandler):
    server: DashboardHTTPServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        LOG.info("dashboard %s - %s", self.address_string(), format % args)

    def _send(self, status: int, content_type: str, raw: bytes) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        self._send(status, "application/json", json.dumps(data).encode("utf-8"))

    def _read_json(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_DASHBOARD_BODY:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid Content-Length"})
                return None
            raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError("JSON body must be an object")
            return body
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid JSON: {exc}"})
            return None

    def _require_auth(self) -> bool:
        if not verify_token(self.headers, self.server.controller.config.auth_token):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized (invalid or missing auth_token)"})
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in {"/", "/index.html"}:
            self._send(HTTPStatus.OK, "text/html; charset=utf-8", DASHBOARD_HTML.encode("utf-8"))
        elif path == "/api/status":
            self._send_json(HTTPStatus.OK, self.server.controller.cluster_summary())
        elif path == "/api/doctor":
            report = run_doctor(config_path=self.server.config_path, check_remote=True)
            self._send_json(HTTPStatus.OK, report)
        elif path == "/api/workloads":
            ctrl = self.server.controller
            snaps = ctrl.poll_health()
            ha_urls: list[str] = []
            docker_nodes: list[str] = []
            for s in snaps:
                if not s.online:
                    continue
                if s.health.get("services", {}).get("homeassistant_8123"):
                    ha_urls.append(f"http://{s.node.host}:8123")
                if s.health.get("tools", {}).get("docker"):
                    docker_nodes.append(s.node.id)
            self._send_json(
                HTTPStatus.OK,
                {
                    "distcc_hosts": ctrl.build_distcc_hosts(),
                    "llama_rpc": ctrl.build_llama_rpc_arg(),
                    "mpi_hostfile": ctrl.build_mpi_hostfile(),
                    "home_assistant_urls": ha_urls,
                    "docker_nodes": docker_nodes,
                },
            )
        elif path == "/api/discover":
            existing_hosts = {n.host for n in self.server.controller.config.nodes}
            found = discover_lan_nodes(timeout_sec=2.0)
            for item in found:
                item["already_configured"] = item["host"] in existing_hosts
            self._send_json(HTTPStatus.OK, {"discovered": found})
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path not in {"/api/exec", "/api/map", "/api/nodes/add", "/api/workloads/action"}:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._require_auth():
            return
        body = self._read_json()
        if body is None:
            return

        ctrl = self.server.controller

        if path == "/api/exec":
            command = str(body.get("command", "")).strip()
            target = str(body.get("target", "best")).strip() or "best"
            if not command:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty command"})
                return
            spec = JobSpec(
                index=0,
                job_id=f"web-{int(time.time())}",
                command=command,
                timeout_sec=float(body.get("timeout_sec", ctrl.config.default_job_timeout_sec)),
            )
            outcomes = ctrl.run_single(spec, target=target)
            self._send_json(HTTPStatus.OK, {"results": [o.to_dict() for o in outcomes]})

        elif path == "/api/map":
            mode = str(body.get("mode", "commands"))
            timeout = float(body.get("timeout_sec", ctrl.config.default_job_timeout_sec))
            jobs: list[JobSpec] = []
            if mode == "script":
                script_content = str(body.get("script_content", ""))
                interpreter = str(body.get("interpreter", "python3"))
                args_lines = body.get("args_lines") or []
                if not script_content.strip() or not isinstance(args_lines, list) or not args_lines:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "provide script_content and non-empty args_lines"})
                    return
                for idx, line in enumerate(args_lines):
                    jobs.append(
                        JobSpec(
                            index=idx,
                            job_id=f"webmap-{idx:04d}",
                            script_content=script_content,
                            script_name="web_job.py" if "python" in interpreter else "web_job.sh",
                            interpreter=interpreter,
                            args=shlex.split(str(line)),
                            timeout_sec=timeout,
                            env={"PHONECLUSTER_TASK_INDEX": str(idx)},
                        )
                    )
            else:
                commands = body.get("commands") or []
                if not isinstance(commands, list) or not commands:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "provide non-empty commands list"})
                    return
                for idx, cmd in enumerate(commands):
                    cmd_s = str(cmd).strip()
                    if cmd_s:
                        jobs.append(
                            JobSpec(
                                index=idx,
                                job_id=f"webmap-{idx:04d}",
                                command=cmd_s,
                                timeout_sec=timeout,
                                env={"PHONECLUSTER_TASK_INDEX": str(idx)},
                            )
                        )
            t0 = time.monotonic()
            outcomes = ctrl.map_jobs(jobs, retries=1)
            wall = round(time.monotonic() - t0, 2)
            dist: dict[str, int] = {}
            for o in outcomes:
                dist[o.node_id] = dist.get(o.node_id, 0) + 1
            ok_count = sum(1 for o in outcomes if o.ok)
            self._send_json(
                HTTPStatus.OK,
                {
                    "wall_sec": wall,
                    "ok_count": ok_count,
                    "fail_count": len(outcomes) - ok_count,
                    "distribution": dist,
                    "results": [o.to_dict() for o in outcomes],
                },
            )

        elif path == "/api/workloads/action":
            action = str(body.get("action", "")).strip()
            cidr = str(body.get("cidr", "192.168.1.0/24")).strip()
            allowed_actions = {
                "distcc-start": f"bash ~/phonecluster/scripts/05_workload_helpers.sh distcc-start {shlex.quote(cidr)}",
                "distcc-stop": "bash ~/phonecluster/scripts/05_workload_helpers.sh distcc-stop",
                "llama-rpc-start": "bash ~/phonecluster/scripts/05_workload_helpers.sh llama-rpc-start",
                "llama-rpc-stop": "bash ~/phonecluster/scripts/05_workload_helpers.sh llama-rpc-stop",
            }
            cmd = allowed_actions.get(action)
            if not cmd:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"unsupported action '{action}'"})
                return
            spec = JobSpec(index=0, job_id=f"wl-{action}", command=cmd, timeout_sec=30.0)
            outcomes = ctrl.run_single(spec, target="all")
            self._send_json(HTTPStatus.OK, {"action": action, "results": [o.to_dict() for o in outcomes]})

        elif path == "/api/nodes/add":
            host = str(body.get("host", "")).strip()
            if not host:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing host"})
                return
            existing_ids = {n.id for n in ctrl.config.nodes}
            idx = len(ctrl.config.nodes)
            while f"node{idx}" in existing_ids:
                idx += 1
            node_id = str(body.get("id") or f"node{idx}").strip()
            if node_id in existing_ids:
                self._send_json(HTTPStatus.CONFLICT, {"error": f"node id '{node_id}' already exists"})
                return
            new_node = NodeConfig(
                id=node_id,
                host=host,
                role="worker",
                worker_port=int(body.get("worker_port", DEFAULT_WORKER_PORT)),
                ssh_port=int(body.get("ssh_port", DEFAULT_SSH_PORT)),
                ssh_user=str(body.get("ssh_user", "")),
                max_concurrency=int(body.get("max_concurrency", 2)),
                weight=float(body.get("weight", 1.0)),
                tags=["worker"],
                notes="Added via Web Control Center",
            )
            ctrl.config.nodes.append(new_node)
            if self.server.config_path is not None:
                save_config(ctrl.config, self.server.config_path)
            self._send_json(HTTPStatus.OK, {"node": {"id": new_node.id, "host": new_node.host}})


def serve_dashboard(
    bind_host: str,
    port: int,
    controller: MasterController,
    config_path: Path | None = None,
) -> None:
    """Start the Master Phone's accessible Web Control Center."""
    server = DashboardHTTPServer((bind_host, port), controller, config_path=config_path)
    lan_ip = detect_local_ip()
    actual_port = server.server_address[1]
    LOG.info(
        "PhoneCluster Web Control Center listening on http://%s:%d (LAN: http://%s:%d)",
        bind_host,
        actual_port,
        lan_ip,
        actual_port,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
