"""Accessible, offline-first, btop-inspired Web Control Center + Interactive Web Terminal."""

from __future__ import annotations

import json
import logging
import shlex
import threading
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .auth import AuthRateLimiter, verify_token
from .config import (
    DEFAULT_SSH_PORT,
    DEFAULT_WORKER_PORT,
    NodeConfig,
    SafetyConfig,
    save_config,
)
from .discovery import detect_local_ip, discover_lan_nodes
from .doctor import run_doctor
from .master import JobSpec, MasterController
from .pairing import PairingManager

LOG = logging.getLogger("phonecluster.dashboard")

MAX_DASHBOARD_BODY = 2 * 1024 * 1024

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en" data-theme="dark" data-scale="normal">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>PhoneCluster — Shared btop &amp; Control Center</title>
<style>
  :root {
    --font-size: 16px;
    --bg: #090d14;
    --bg-grad: radial-gradient(circle at 12% 0%, rgba(88, 166, 255, 0.12), transparent 36%),
               radial-gradient(circle at 88% 8%, rgba(163, 113, 247, 0.11), transparent 34%);
    --surface: #111824;
    --surface-2: #182232;
    --surface-3: #0c121c;
    --border: #263348;
    --border-hi: #3a4f70;
    --fg: #eaf1fb;
    --muted: #93a4bc;
    --accent: #58a6ff;
    --accent-2: #a371f7;
    --accent-fg: #08101b;
    --ok: #3fb950;
    --ok-bg: rgba(63, 185, 80, 0.16);
    --warn: #e3b341;
    --warn-bg: rgba(227, 179, 65, 0.18);
    --bad: #f85149;
    --bad-bg: rgba(248, 81, 73, 0.18);
    --focus: #ffd33d;
    --term-bg: #070b11;
    --term-fg: #dce6f5;
    --term-prompt: #3fb950;
    --shadow: 0 8px 28px rgba(0, 0, 0, 0.28);
  }
  [data-theme="light"] {
    --bg: #eef2f7;
    --bg-grad: radial-gradient(circle at 10% 0%, rgba(37, 99, 235, 0.08), transparent 40%),
               radial-gradient(circle at 90% 10%, rgba(124, 58, 237, 0.07), transparent 38%);
    --surface: #ffffff;
    --surface-2: #f3f6fb;
    --surface-3: #e8eef6;
    --border: #cbd5e1;
    --border-hi: #94a3b8;
    --fg: #0f172a;
    --muted: #475569;
    --accent: #1d4ed8;
    --accent-2: #7c3aed;
    --accent-fg: #ffffff;
    --ok: #15803d;
    --ok-bg: #dcfce7;
    --warn: #a16207;
    --warn-bg: #fef3c7;
    --bad: #b91c1c;
    --bad-bg: #fee2e2;
    --focus: #1d4ed8;
    --term-bg: #0f172a;
    --term-fg: #e2e8f0;
    --term-prompt: #4ade80;
    --shadow: 0 6px 20px rgba(15, 23, 42, 0.08);
  }
  [data-theme="contrast"] {
    --bg: #000000;
    --bg-grad: none;
    --surface: #0a0a0a;
    --surface-2: #171717;
    --surface-3: #000000;
    --border: #ffffff;
    --border-hi: #ffea00;
    --fg: #ffffff;
    --muted: #e5e5e5;
    --accent: #ffea00;
    --accent-2: #00ffff;
    --accent-fg: #000000;
    --ok: #00ff66;
    --ok-bg: #003314;
    --warn: #ffea00;
    --warn-bg: #332e00;
    --bad: #ff4d4d;
    --bad-bg: #3b0000;
    --focus: #00ffff;
    --term-bg: #000000;
    --term-fg: #ffffff;
    --term-prompt: #00ff66;
    --shadow: none;
  }
  [data-scale="large"] { --font-size: 18px; }
  [data-scale="xl"] { --font-size: 20px; }

  * { box-sizing: border-box; }
  html { font-size: var(--font-size); }
  body {
    margin: 0;
    min-height: 100vh;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    background-image: var(--bg-grad);
    background-attachment: fixed;
    color: var(--fg);
    line-height: 1.48;
  }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-variant-numeric: tabular-nums; }
  .skip-link {
    position: absolute; left: -9999px; top: 8px;
    background: var(--accent); color: var(--accent-fg);
    padding: 8px 14px; border-radius: 6px; font-weight: 700; z-index: 1000;
  }
  .skip-link:focus { left: 12px; }
  :focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }

  .wrap { max-width: 1280px; margin: 0 auto; padding: 16px; }

  header.topbar {
    display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between;
    background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
    padding: 14px 18px; margin-bottom: 12px; box-shadow: var(--shadow);
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .logo-badge {
    width: 40px; height: 40px; border-radius: 10px; display: grid; place-items: center;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    color: var(--accent-fg); font-weight: 800; font-size: 1.05rem; flex-shrink: 0;
  }
  .brand h1 { margin: 0; font-size: 1.28rem; line-height: 1.2; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .brand .sub { color: var(--muted); font-size: 0.83rem; margin-top: 2px; }
  .live-dot {
    width: 9px; height: 9px; border-radius: 50%; background: var(--ok); display: inline-block;
    box-shadow: 0 0 0 3px var(--ok-bg); animation: pulse 2s infinite;
  }
  .live-dot.paused { background: var(--warn); box-shadow: 0 0 0 3px var(--warn-bg); animation: none; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.45; } }

  .controls { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }

  button, input, select, textarea {
    font: inherit; color: var(--fg); background: var(--surface-2);
    border: 1px solid var(--border); border-radius: 8px; padding: 7px 11px;
  }
  button { cursor: pointer; font-weight: 600; transition: transform .1s, border-color .15s, opacity .15s; }
  button:hover { border-color: var(--border-hi); }
  button:active { transform: translateY(1px); }
  button:disabled { opacity: 0.48; cursor: not-allowed; transform: none; }
  button.primary { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
  button.danger { background: var(--bad-bg); color: var(--bad); border-color: var(--bad); }
  button.ghost { background: transparent; }
  button.small { padding: 5px 9px; font-size: 0.83rem; }

  .toast {
    position: fixed; bottom: 18px; right: 18px; max-width: 440px; z-index: 999;
    background: var(--surface); border: 2px solid var(--accent); border-radius: 12px;
    padding: 12px 16px; box-shadow: 0 12px 32px rgba(0,0,0,0.48);
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
  }
  .toast.ok { border-color: var(--ok); }
  .toast.warn { border-color: var(--warn); }
  .toast.bad { border-color: var(--bad); }
  .toast.hidden { display: none; }

  .auth-bar {
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 9px 14px; margin-bottom: 12px; display: flex; flex-wrap: wrap; gap: 10px;
    align-items: center; justify-content: space-between;
  }

  nav.tabs {
    display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px;
    border-bottom: 1px solid var(--border); padding-bottom: 10px;
  }
  nav.tabs button[role="tab"] {
    background: var(--surface); border: 1px solid var(--border); color: var(--fg);
    padding: 8px 14px; border-radius: 10px; font-size: 0.92rem;
  }
  nav.tabs button[role="tab"][aria-selected="true"] {
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    color: var(--accent-fg); border-color: transparent;
  }

  .panel { display: none; }
  .panel.active { display: block; }

  .banner {
    border-radius: 10px; padding: 11px 15px; margin-bottom: 14px;
    border: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; gap: 12px;
  }
  .banner.warn { background: var(--warn-bg); border-color: var(--warn); }
  .banner.hidden { display: none; }

  /* Hero KPI + Sparklines */
  .kpi-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 12px; margin-bottom: 16px;
  }
  .kpi-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
    padding: 14px 16px; box-shadow: var(--shadow); display: flex; flex-direction: column; justify-content: space-between;
  }
  .kpi-top { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
  .stat-label { color: var(--muted); font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 700; }
  .stat-val { font-size: 1.55rem; font-weight: 800; line-height: 1.15; margin-top: 4px; }
  .stat-sub { color: var(--muted); font-size: 0.8rem; margin-top: 2px; }
  .spark-wrap { margin-top: 8px; height: 34px; width: 100%; }
  .spark-wrap svg { width: 100%; height: 100%; display: block; overflow: visible; }

  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 14px; padding: 16px; margin-bottom: 14px; box-shadow: var(--shadow);
  }
  .card h2, .card h3 { margin: 0 0 10px; font-size: 1.05rem; }

  /* Multi-Device btop Cards */
  .nodes-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 14px; margin-bottom: 16px;
  }
  .node-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 16px;
    display: flex; flex-direction: column; justify-content: space-between; box-shadow: var(--shadow);
    transition: border-color .15s;
  }
  .node-card:hover { border-color: var(--border-hi); }
  .node-card.hot { border-color: var(--warn); }
  .node-card.offline { border-color: var(--bad); opacity: 0.88; }
  .node-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 10px; }
  .node-title { font-weight: 800; font-size: 1.08rem; display: flex; align-items: center; gap: 6px; }
  .node-meta { color: var(--muted); font-size: 0.82rem; margin-top: 2px; }

  .cpu-btop-box {
    background: var(--surface-3); border: 1px solid var(--border); border-radius: 10px;
    padding: 10px; margin-bottom: 10px;
  }
  .cpu-btop-top { display: flex; justify-content: space-between; align-items: center; font-size: 0.84rem; margin-bottom: 6px; }
  .core-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(22px, 1fr)); gap: 4px;
    align-items: end; height: 28px; margin-top: 6px;
  }
  .core-col {
    background: var(--surface-2); border-radius: 3px; height: 100%; display: flex; align-items: flex-end; overflow: hidden;
  }
  .core-col > span { width: 100%; border-radius: 3px; background: var(--ok); display: block; min-height: 2px; }
  .core-col > span.warn { background: var(--warn); }
  .core-col > span.bad { background: var(--bad); }

  .metric-row { margin: 7px 0; font-size: 0.85rem; }
  .metric-head { display: flex; justify-content: space-between; margin-bottom: 3px; }
  .bar { height: 8px; background: var(--surface-3); border-radius: 999px; overflow: hidden; border: 1px solid var(--border); }
  .bar > span { display: block; height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent-2)); border-radius: 999px; }
  .bar.ok > span { background: linear-gradient(90deg, #2ea043, var(--ok)); }
  .bar.warn > span { background: linear-gradient(90deg, #d29922, var(--warn)); }
  .bar.bad > span { background: linear-gradient(90deg, #da3633, var(--bad)); }

  .mini-procs {
    margin-top: 10px; background: var(--surface-3); border: 1px solid var(--border); border-radius: 9px;
    padding: 8px 10px; font-size: 0.79rem;
  }
  .mini-procs-head { color: var(--muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 4px; display: flex; justify-content: space-between; }
  .proc-line { display: flex; justify-content: space-between; gap: 8px; padding: 2px 0; border-top: 1px dashed rgba(128,128,128,0.18); }
  .proc-line:first-of-type { border-top: none; }
  .node-actions { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--border); }

  .pill {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 9px; border-radius: 999px; font-size: 0.77rem; font-weight: 700; white-space: nowrap;
  }
  .pill.ok { background: var(--ok-bg); color: var(--ok); border: 1px solid var(--ok); }
  .pill.warn { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn); }
  .pill.bad { background: var(--bad-bg); color: var(--bad); border: 1px solid var(--bad); }
  .pill.accent { background: rgba(88, 166, 255, 0.16); color: var(--accent); border: 1px solid var(--accent); }
  .pill.purple { background: rgba(163, 113, 247, 0.16); color: var(--accent-2); border: 1px solid var(--accent-2); }
  .pill.neutral { background: var(--surface-2); color: var(--muted); border: 1px solid var(--border); }

  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
  .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
  .col-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 14px; }
  .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; margin-bottom: 10px; }
  .field label { display: block; font-size: 0.8rem; color: var(--muted); margin-bottom: 3px; }
  .field input, .field select { width: 100%; }
  textarea { width: 100%; min-height: 115px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.86rem; }
  pre.code {
    background: var(--term-bg); color: var(--term-fg); border: 1px solid var(--border); border-radius: 10px;
    padding: 12px; overflow: auto; max-height: 360px; margin: 8px 0 0;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.84rem; white-space: pre-wrap;
  }

  /* Interactive Web Terminal Console */
  .term-window {
    background: var(--term-bg); color: var(--term-fg); border: 1px solid var(--border-hi);
    border-radius: 14px; overflow: hidden; box-shadow: var(--shadow);
  }
  .term-titlebar {
    background: var(--surface-2); border-bottom: 1px solid var(--border);
    padding: 10px 14px; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: space-between;
  }
  .term-dots { display: flex; gap: 6px; align-items: center; }
  .dot { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
  .dot.r { background: #ff5f56; } .dot.y { background: #ffbd2e; } .dot.g { background: #27c93f; }
  .term-screen {
    padding: 14px 16px; height: 420px; overflow-y: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.87rem; line-height: 1.5; white-space: pre-wrap; word-break: break-word;
  }
  .term-entry { margin-bottom: 12px; }
  .term-cmd-line { color: var(--term-prompt); font-weight: 700; }
  .term-meta { color: var(--muted); font-size: 0.78rem; margin-left: 8px; font-weight: 400; }
  .term-err { color: #ff7b72; }
  .term-input-bar {
    display: flex; gap: 8px; align-items: center; padding: 10px 14px;
    border-top: 1px solid var(--border); background: #0c121b;
  }
  .term-prompt-label { color: var(--term-prompt); font-weight: 700; white-space: nowrap; font-size: 0.88rem; }
  .term-input-bar input {
    flex: 1; background: transparent; border: none; color: #f0f6fc; padding: 6px 4px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9rem;
  }
  .term-input-bar input:focus { outline: none; }

  .check-item {
    border: 1px solid var(--border); border-radius: 9px; padding: 10px 12px; margin-bottom: 8px;
    background: var(--surface-2);
  }
  table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
  th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 700; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }
  .hint { color: var(--muted); font-size: 0.84rem; margin-top: 4px; }
  .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0,0,0,0); }

  @media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation: none !important; }
  }
</style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
<div id="toast" class="toast hidden" role="status" aria-live="polite">
  <span id="toast-msg"></span>
  <button class="small ghost" onclick="hideToast()" aria-label="Dismiss notification">✕</button>
</div>

<div class="wrap">
  <header class="topbar">
    <div class="brand">
      <div class="logo-badge" aria-hidden="true">PC</div>
      <div>
        <h1>
          <span id="live-dot" class="live-dot" aria-hidden="true"></span>
          <span id="cluster-title">PhoneCluster</span>
        </h1>
        <div class="sub" id="last-updated" aria-live="polite">Connecting to cluster...</div>
      </div>
    </div>
    <div class="controls" aria-label="Display and refresh controls">
      <label class="sr-only" for="theme-select">Color theme</label>
      <select id="theme-select" aria-label="Color theme">
        <option value="dark">Theme: Midnight</option>
        <option value="light">Theme: Daylight</option>
        <option value="contrast">Theme: High Contrast</option>
      </select>
      <label class="sr-only" for="scale-select">Text size</label>
      <select id="scale-select" aria-label="Text size">
        <option value="normal">Text: Normal</option>
        <option value="large">Text: Large</option>
        <option value="xl">Text: XL</option>
      </select>
      <label class="sr-only" for="poll-select">Refresh rate</label>
      <select id="poll-select" aria-label="Refresh rate">
        <option value="2000">Live: 2s</option>
        <option value="3000" selected>Live: 3s</option>
        <option value="5000">Live: 5s</option>
        <option value="10000">Live: 10s</option>
        <option value="0">Paused</option>
      </select>
      <button class="small primary" onclick="refreshAll()">Refresh</button>
    </div>
  </header>

  <section class="auth-bar" aria-label="Cluster authentication">
    <div class="row" style="margin:0; flex:1; min-width:260px;">
      <span id="auth-pill" class="pill neutral">Read-Only Mode</span>
      <label class="sr-only" for="auth-token">Cluster auth token</label>
      <input id="auth-token" type="password" placeholder="Paste token (run `pc token` on Master) to unlock Terminal &amp; Controls" style="flex:1; min-width:220px" />
      <label style="font-size:0.84rem; display:inline-flex; align-items:center; gap:4px;">
        <input id="remember-token" type="checkbox" style="width:auto; padding:0;" /> Remember
      </label>
      <button class="small primary" onclick="verifyAndSaveToken()">Unlock</button>
      <button class="small ghost" onclick="clearToken()">Lock</button>
    </div>
    <div class="hint" style="margin:0;">Tip: Run <code class="mono">pc top</code> in SSH for the matching terminal btop dashboard.</div>
  </section>

  <div id="battery-banner" class="banner warn hidden" role="status" aria-live="polite">
    <div><strong>24/7 Battery Safety Alert:</strong> <span id="battery-banner-text"></span></div>
  </div>

  <nav class="tabs" role="tablist" aria-label="Control Center Sections">
    <button role="tab" id="tab-overview" aria-selected="true" aria-controls="panel-overview" onclick="selectTab('overview')">1. Live btop &amp; Tasks</button>
    <button role="tab" id="tab-terminal" aria-selected="false" aria-controls="panel-terminal" onclick="selectTab('terminal')">2. Terminal Control</button>
    <button role="tab" id="tab-jobs" aria-selected="false" aria-controls="panel-jobs" onclick="selectTab('jobs')">3. Parallel Batch</button>
    <button role="tab" id="tab-workloads" aria-selected="false" aria-controls="panel-workloads" onclick="selectTab('workloads')">4. Workloads (AI / Compiler / HA)</button>
    <button role="tab" id="tab-setup" aria-selected="false" aria-controls="panel-setup" onclick="selectTab('setup')">5. Phones, Safety &amp; Doctor</button>
  </nav>

  <main id="main-content">
    <!-- TAB 1: SHARED MULTI-DEVICE BTOP & RUNNING TASKS -->
    <section id="panel-overview" class="panel active" role="tabpanel" aria-labelledby="tab-overview">
      <div class="kpi-grid" aria-label="Unified one-computer telemetry">
        <div class="kpi-card">
          <div class="kpi-top"><span class="stat-label">Cluster CPU</span><span id="k-cores" class="pill neutral">-</span></div>
          <div class="stat-val mono" id="k-cpu">-</div>
          <div class="spark-wrap" id="spark-cpu" aria-hidden="true"></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-top"><span class="stat-label">Cluster Memory</span><span id="k-ram-pct" class="pill neutral">-</span></div>
          <div class="stat-val mono" id="k-ram">-</div>
          <div class="spark-wrap" id="spark-ram" aria-hidden="true"></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-top"><span class="stat-label">Peak Thermal</span><span id="k-temp-pill" class="pill ok">Safe</span></div>
          <div class="stat-val mono" id="k-temp">-</div>
          <div class="spark-wrap" id="spark-temp" aria-hidden="true"></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-top"><span class="stat-label">Running Tasks</span><span id="k-net" class="pill neutral mono">↓0 ↑0 KB/s</span></div>
          <div class="stat-val mono" id="k-tasks">0</div>
          <div class="stat-sub" id="k-tasks-sub">Idle across cluster</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-top"><span class="stat-label">Fleet Status</span><span id="k-ping" class="pill neutral mono">- ms</span></div>
          <div class="stat-val mono" id="k-nodes">-</div>
          <div class="stat-sub" id="k-nodes-sub">Ready / Total phones</div>
        </div>
      </div>

      <div id="nodes-grid" class="nodes-grid" aria-live="polite"></div>

      <div class="card">
        <div class="row" style="justify-content:space-between; margin-bottom:10px;">
          <h2 style="margin:0;">Shared Running Tasks &amp; Top Processes</h2>
          <div class="row" style="margin:0;">
            <button id="btn-board-tasks" class="small primary" onclick="setBoardView('tasks')">Running &amp; Recent Tasks</button>
            <button id="btn-board-procs" class="small" onclick="setBoardView('procs')">Shared Processes (All Phones)</button>
          </div>
        </div>
        <div id="tasks-board-wrap" class="hint">Loading cluster tasks...</div>
      </div>
    </section>

    <!-- TAB 2: INTERACTIVE MULTI-NODE WEB TERMINAL -->
    <section id="panel-terminal" class="panel" role="tabpanel" aria-labelledby="tab-terminal">
      <div class="term-window">
        <div class="term-titlebar">
          <div class="row" style="margin:0;">
            <div class="term-dots" aria-hidden="true"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span></div>
            <label for="term-target" class="sr-only">Terminal target phone</label>
            <select id="term-target" onchange="onTermTargetChange()" aria-label="Terminal target phone">
              <option value="best">Smart: Best Coolest Phone</option>
              <option value="all">ALL READY PHONES (Broadcast)</option>
            </select>
            <span id="term-cwd-pill" class="pill neutral mono">~</span>
          </div>
          <div class="row" style="margin:0;">
            <button id="btn-term-cancel" class="small danger" onclick="cancelActiveTermJob()" disabled>Cancel (Ctrl+C)</button>
            <button class="small" onclick="clearTerminal()">Clear</button>
            <button class="small" onclick="downloadTermLog()">Save Log</button>
          </div>
        </div>
        <div id="term-screen" class="term-screen" aria-live="polite" onclick="document.getElementById('term-input').focus()">
          <div class="term-entry">
            <span class="term-cmd-line">PhoneCluster Interactive Web Terminal</span>
            <div class="hint" style="color:#8b9bb4;">Pick any phone (or ALL PHONES) above, unlock with your token, and type Linux commands below. Supports persistent `cd`, ↑/↓ history, and Ctrl+L clear.</div>
          </div>
        </div>
        <div class="term-input-bar">
          <span id="term-prompt" class="term-prompt-label mono">best:~ $</span>
          <label class="sr-only" for="term-input">Terminal command input</label>
          <input id="term-input" type="text" autocomplete="off" spellcheck="false" placeholder="Type a command (e.g. ls -la, uname -a, cd ~/phonecluster)..." />
          <button id="btn-term-run" class="small primary" onclick="submitTerminalCommand()">Run</button>
        </div>
      </div>
      <div class="chips" style="margin-top:10px;" aria-label="Quick terminal commands">
        <span class="hint" style="margin:0 4px 0 0;">Quick commands:</span>
        <button class="small" onclick="runTermPreset('uname -a && nproc')">System Info</button>
        <button class="small" onclick="runTermPreset('ls -la')">ls -la</button>
        <button class="small" onclick="runTermPreset('df -h ~')">Disk Space</button>
        <button class="small" onclick="runTermPreset('uptime && head -n 5 /proc/meminfo')">Load &amp; RAM</button>
        <button class="small" onclick="runTermPreset('ps -eo pid,pcpu,pmem,comm --sort=-pcpu 2>/dev/null | head -n 12 || ps | head -n 12')">Top Processes</button>
      </div>
    </section>

    <!-- TAB 3: PARALLEL BATCH RUNNER -->
    <section id="panel-jobs" class="panel" role="tabpanel" aria-labelledby="tab-jobs">
      <div class="card">
        <h2>Parallel Batch Runner (Distribute Work Across All Ready Phones)</h2>
        <div class="row">
          <label for="map-mode">Mode:</label>
          <select id="map-mode" onchange="toggleMapMode()">
            <option value="commands">Shell Command List (1 per line)</option>
            <option value="script">Ship &amp; Run Script + Arguments</option>
          </select>
          <label class="sr-only" for="map-template">Load sample template</label>
          <select id="map-template" onchange="applyMapTemplate(this.value)" aria-label="Load sample template">
            <option value="">Templates...</option>
            <option value="primes">Prime Benchmark (Python)</option>
            <option value="audit">Hardware Audit (Shell)</option>
            <option value="squares">Quick Square Test (Python)</option>
          </select>
        </div>

        <div id="map-commands-box">
          <div class="row" style="justify-content:space-between; margin-bottom:4px;">
            <label for="map-commands" class="hint" style="margin:0;">Commands (one per line · Ctrl+Enter to run):</label>
            <label class="small" style="cursor:pointer; border:1px solid var(--border); border-radius:6px; padding:3px 8px;">
              Load .txt <input type="file" accept=".txt,.sh" style="display:none" onchange="loadFileInto(this, 'map-commands')" />
            </label>
          </div>
          <textarea id="map-commands">echo "Job 1 on $PHONECLUSTER_NODE_ID"
echo "Job 2 on $PHONECLUSTER_NODE_ID"
echo "Job 3 on $PHONECLUSTER_NODE_ID"
echo "Job 4 on $PHONECLUSTER_NODE_ID"</textarea>
        </div>

        <div id="map-script-box" style="display:none">
          <div class="row" style="justify-content:space-between;">
            <div>
              <label for="map-interp">Interpreter:</label>
              <select id="map-interp">
                <option value="python3">python3</option>
                <option value="bash">bash</option>
                <option value="sh">sh</option>
              </select>
            </div>
            <label class="small" style="cursor:pointer; border:1px solid var(--border); border-radius:6px; padding:4px 8px;">
              Upload Script <input type="file" accept=".py,.sh,.bash" style="display:none" onchange="loadFileInto(this, 'map-script')" />
            </label>
          </div>
          <label for="map-script" class="hint">Script source (automatically shipped to every ready phone):</label>
          <textarea id="map-script">import os, sys
n = int(sys.argv[1])
print(f"node={os.environ.get('PHONECLUSTER_NODE_ID')} square({n})={n*n}")</textarea>
          <label for="map-args" class="hint">Arguments list (one parallel job per line):</label>
          <textarea id="map-args" style="min-height:80px">10
20
30
40</textarea>
        </div>

        <div class="row" style="margin-top:10px;">
          <button id="btn-run-map" class="primary" onclick="runParallelMap()">Run Batch Across Cluster</button>
          <button class="small" onclick="copyEl('map-out')">Copy Output</button>
          <button id="btn-dl-map" class="small" onclick="downloadLastMapJson()" disabled>Download JSON</button>
        </div>
        <div id="map-summary-chips" class="chips"></div>
        <pre id="map-out" class="code" aria-live="polite">Batch results will appear here.</pre>
      </div>
    </section>

    <!-- TAB 4: WORKLOADS -->
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

    <!-- TAB 5: PHONES, SAFETY & DOCTOR -->
    <section id="panel-setup" class="panel" role="tabpanel" aria-labelledby="tab-setup">
      <div class="col-grid">
        <div class="card">
          <h2>1. Secure One-Tap Phone Pairing (Recommended)</h2>
          <p class="hint">Cluster is completely silent to strangers on Wi-Fi until you open a temporary 2-minute pairing window.</p>
          <div class="chips" style="margin-bottom:12px;">
            <span class="pill ok">✓ 2048-bit DH Encrypted</span>
            <span class="pill ok">✓ Unique Per-Phone Token</span>
            <span class="pill neutral">5-Attempt Lockout</span>
            <span class="pill neutral">Auto-Closes</span>
          </div>
          <div class="row">
            <label for="pair-slots" class="sr-only">How many phones to pair</label>
            <select id="pair-slots" aria-label="How many phones to pair">
              <option value="1" selected>Pair 1 Phone (Single-Use)</option>
              <option value="2">Pair up to 2 Phones</option>
              <option value="3">Pair up to 3 Phones</option>
            </select>
            <button id="btn-pair-open" class="primary" onclick="openPairingWindow()">Open Pairing Window (2 min)</button>
            <button id="btn-pair-close" class="small danger" onclick="closePairingWindow()" style="display:none">Close Window Now</button>
          </div>
          <div id="pair-active-box" class="check-item" style="display:none; border-color:var(--ok);">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
              <div>
                <div class="stat-label">Type this 6-Digit Code on the New Phone (<code class="mono">pc join</code>)</div>
                <div id="pair-pin" class="mono" style="font-size:2rem; font-weight:800; letter-spacing:0.12em; color:var(--ok); margin:4px 0;">--- ---</div>
                <div class="hint">Master Fingerprint: <strong id="pair-fp" class="mono">-</strong> · Attempts left: <strong id="pair-att">5</strong> · Slots left: <strong id="pair-rem">1</strong></div>
              </div>
              <span id="pair-timer" class="pill warn mono" style="font-size:0.95rem;">120s</span>
            </div>
          </div>

          <h3 style="margin-top:16px;">One-Line Termux Phone Installer</h3>
          <div class="row" style="margin-bottom:4px;">
            <span class="hint" style="margin:0;">Run in Termux on your new phone (auto-finds Master when pairing is open):</span>
            <button class="small" onclick="copyEl('install-snippet')">Copy</button>
          </div>
          <pre id="install-snippet" class="code">curl -fsSL https://raw.githubusercontent.com/andreasNosalSK/phonecluster/main/install.sh | bash</pre>

          <h3 style="margin-top:16px;">Add Phone Manually (Tailscale / Static IP)</h3>
          <div class="form-grid">
            <div class="field"><label for="add-host">IP or Tailscale IP</label><input id="add-host" placeholder="192.168.1.204" /></div>
            <div class="field"><label for="add-user">SSH User</label><input id="add-user" placeholder="u0_a250" /></div>
            <div class="field"><label for="add-ssh-port">SSH Port</label><input id="add-ssh-port" type="number" value="8022" /></div>
            <div class="field"><label for="add-conc">Max Parallel Jobs</label><input id="add-conc" type="number" min="1" max="8" value="2" /></div>
          </div>
          <div class="row">
            <button class="small primary" onclick="addManualNode()">+ Add Phone Manually</button>
            <button class="small" onclick="scanLan()">Scan Opt-In Workers</button>
          </div>
          <div id="discover-list" aria-live="polite" class="hint"></div>
        </div>

        <div class="card">
          <h2>2. Thermal &amp; 24/7 Battery Safety</h2>
          <p class="hint">Adjust automatic overheat throttling and unrooted smart-plug / Home Assistant webhook alerts.</p>
          <div class="form-grid">
            <div class="field"><label for="set-max-temp">Pause Jobs At (°C)</label><input id="set-max-temp" type="number" step="0.5" value="40.0" /></div>
            <div class="field"><label for="set-res-temp">Resume Jobs At (°C)</label><input id="set-res-temp" type="number" step="0.5" value="37.0" /></div>
            <div class="field"><label for="set-bat-low">Charge On Below (%)</label><input id="set-bat-low" type="number" min="10" max="80" value="45" /></div>
            <div class="field"><label for="set-bat-high">Cut Charge Above (%)</label><input id="set-bat-high" type="number" min="40" max="95" value="60" /></div>
          </div>
          <div class="field" style="margin-bottom:10px;">
            <label for="set-webhook">Battery Webhook URL (Home Assistant / ntfy.sh / smart plug)</label>
            <input id="set-webhook" type="url" placeholder="http://192.168.1.201:8123/api/webhook/phonecluster_battery" />
          </div>
          <div class="row">
            <button class="small primary" onclick="saveSafetySettings()">Save Safety Settings</button>
            <button class="small" onclick="testSafetyWebhook()">Send Test Webhook</button>
          </div>

          <h2 style="margin-top:18px;">3. Cluster Doctor (Health Audit)</h2>
          <div class="row">
            <button class="primary" onclick="runDoctorUi()">Run Doctor Now</button>
          </div>
          <div id="doctor-list" aria-live="polite" class="hint">Click "Run Doctor Now" to inspect SSH, Termux:API, thermal, and battery safety.</div>
        </div>
      </div>
    </section>
  </main>
</div>

<script>
let pollMs = 3000;
let refreshTimer = null;
let lastLive = null;
let lastMapData = null;
let toastTimer = null;
let boardView = 'tasks';

// Interactive Web Terminal state
const termCwds = {};
const termHistory = [];
let termHistIdx = -1;
let termTranscript = [];
let activeTermJob = null;

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function fmtUptime(sec) {
  if (sec == null) return '-';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return d + 'd ' + h + 'h';
  if (h > 0) return h + 'h ' + m + 'm';
  return m + 'm';
}

function renderSparklineSvg(values, maxVal, strokeColor, fillColor) {
  const w = 200, h = 34;
  const pts = (values && values.length) ? values.slice(-40) : [0, 0];
  const safeMax = Math.max(1, maxVal || 100);
  const step = pts.length > 1 ? w / (pts.length - 1) : w;
  const coords = pts.map((v, i) => {
    const x = (i * step).toFixed(1);
    const ratio = Math.max(0, Math.min(1, (Number(v) || 0) / safeMax));
    const y = (h - 2 - ratio * (h - 5)).toFixed(1);
    return [x, y];
  });
  const lineD = coords.map((p, i) => (i === 0 ? 'M' : 'L') + p[0] + ',' + p[1]).join(' ');
  const areaD = lineD + ' L' + coords[coords.length - 1][0] + ',' + h + ' L' + coords[0][0] + ',' + h + ' Z';
  return '<svg viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">'
    + '<path d="' + areaD + '" fill="' + fillColor + '" />'
    + '<path d="' + lineD + '" fill="none" stroke="' + strokeColor + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />'
    + '</svg>';
}

function showToast(msg, tone) {
  const el = document.getElementById('toast');
  document.getElementById('toast-msg').textContent = msg;
  el.className = 'toast ' + (tone || 'ok');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(hideToast, 4500);
}
function hideToast() {
  document.getElementById('toast').classList.add('hidden');
}

function getToken() {
  return sessionStorage.getItem('pc_token') || localStorage.getItem('pc_token') || '';
}
function updateAuthBadge() {
  const pill = document.getElementById('auth-pill');
  const inp = document.getElementById('auth-token');
  const rem = document.getElementById('remember-token');
  rem.checked = Boolean(localStorage.getItem('pc_token'));
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
async function verifyAndSaveToken() {
  const raw = document.getElementById('auth-token').value.trim();
  const candidate = (!raw || raw.startsWith('••')) ? getToken() : raw;
  if (!candidate) {
    showToast('Paste your auth_token first (run `pc token` on the Master phone).', 'warn');
    return;
  }
  try {
    const r = await fetch('/api/auth/verify', { headers: { 'Authorization': 'Bearer ' + candidate } });
    if (!r.ok) {
      showToast('Invalid auth_token — check config/cluster.json or run `pc token`.', 'bad');
      return;
    }
    if (document.getElementById('remember-token').checked) {
      localStorage.setItem('pc_token', candidate);
      sessionStorage.removeItem('pc_token');
    } else {
      sessionStorage.setItem('pc_token', candidate);
      localStorage.removeItem('pc_token');
    }
    updateAuthBadge();
    loadSafetySettings();
    refreshLive();
    showToast('Token verified — Terminal & Cluster controls unlocked!', 'ok');
  } catch (e) {
    showToast('Could not reach Master to verify token: ' + e, 'bad');
  }
}
function clearToken() {
  sessionStorage.removeItem('pc_token');
  localStorage.removeItem('pc_token');
  updateAuthBadge();
  showToast('Controls locked (Read-Only Mode).', 'neutral');
}

function scheduleRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  const dot = document.getElementById('live-dot');
  if (pollMs > 0) {
    dot.classList.remove('paused');
    refreshTimer = setInterval(refreshLive, pollMs);
  } else {
    dot.classList.add('paused');
  }
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
  document.getElementById('poll-select').addEventListener('change', e => {
    pollMs = Number(e.target.value);
    scheduleRefresh();
  });

  // Terminal keyboard shortcuts (Enter, Up/Down history, Ctrl+L clear)
  const termInp = document.getElementById('term-input');
  termInp.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      submitTerminalCommand();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (termHistory.length && termHistIdx < termHistory.length - 1) {
        termHistIdx++;
        termInp.value = termHistory[termHistory.length - 1 - termHistIdx];
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (termHistIdx > 0) {
        termHistIdx--;
        termInp.value = termHistory[termHistory.length - 1 - termHistIdx];
      } else {
        termHistIdx = -1;
        termInp.value = '';
      }
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l') {
      e.preventDefault();
      clearTerminal();
    }
  });

  for (const id of ['map-commands', 'map-script', 'map-args']) {
    document.getElementById(id).addEventListener('keydown', e => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runParallelMap();
    });
  }
}

function selectTab(name) {
  const tabs = ['overview', 'terminal', 'jobs', 'workloads', 'setup'];
  for (const t of tabs) {
    const btn = document.getElementById('tab-' + t);
    const panel = document.getElementById('panel-' + t);
    const active = t === name;
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
    panel.classList.toggle('active', active);
  }
  if (name === 'terminal') document.getElementById('term-input').focus();
  if (name === 'workloads') loadWorkloads();
  if (name === 'setup' && getToken()) { loadSafetySettings(); pollPairingStatus(); }
}

document.querySelector('nav.tabs').addEventListener('keydown', e => {
  const btns = Array.from(document.querySelectorAll('nav.tabs button[role="tab"]'));
  const idx = btns.indexOf(document.activeElement);
  if (idx === -1) return;
  if (e.key === 'ArrowRight') { btns[(idx + 1) % btns.length].focus(); btns[(idx + 1) % btns.length].click(); }
  if (e.key === 'ArrowLeft') { btns[(idx - 1 + btns.length) % btns.length].focus(); btns[(idx - 1 + btns.length) % btns.length].click(); }
});

function metricBar(label, valueText, pct, tone) {
  const clamped = Math.max(0, Math.min(100, pct || 0));
  return '<div class="metric-row">'
    + '<div class="metric-head"><span>' + esc(label) + '</span><span class="mono">' + esc(valueText) + '</span></div>'
    + '<div class="bar ' + esc(tone || '') + '"><span style="width:' + clamped + '%"></span></div>'
    + '</div>';
}

function setBoardView(mode) {
  boardView = mode;
  document.getElementById('btn-board-tasks').className = 'small' + (mode === 'tasks' ? ' primary' : '');
  document.getElementById('btn-board-procs').className = 'small' + (mode === 'procs' ? ' primary' : '');
  if (lastLive) renderTasksBoard(lastLive);
}

function renderTasksBoard(live) {
  const wrap = document.getElementById('tasks-board-wrap');
  if (boardView === 'procs') {
    const procs = [];
    for (const n of (live.summary.nodes || [])) {
      if (!n.online) continue;
      for (const p of ((n.health || {}).top_processes || [])) {
        procs.push({ node_id: n.id, ...p });
      }
    }
    procs.sort((a, b) => (b.cpu_pct - a.cpu_pct) || (b.mem_pct - a.mem_pct));
    if (!procs.length) {
      wrap.innerHTML = '<p class="hint">No process snapshots available from workers.</p>';
      return;
    }
    wrap.innerHTML = '<div style="overflow-x:auto;"><table><thead><tr><th>Phone</th><th>PID</th><th>CPU %</th><th>RAM %</th><th>Process</th></tr></thead><tbody>'
      + procs.slice(0, 18).map(p =>
        '<tr><td><b>' + esc(p.node_id) + '</b></td><td class="mono">' + esc(p.pid) + '</td>'
        + '<td class="mono">' + esc(p.cpu_pct) + '%</td><td class="mono">' + esc(p.mem_pct) + '%</td>'
        + '<td class="mono">' + esc(p.name) + '</td></tr>'
      ).join('')
      + '</tbody></table></div>';
    return;
  }

  const rows = [];
  for (const node of (live.jobs || [])) {
    for (const j of (node.active || [])) {
      rows.push({
        node_id: node.node_id, job_id: j.job_id, state: 'RUNNING',
        command: j.command, duration: j.running_sec + 's', active: true
      });
    }
    for (const j of (node.recent || []).slice(0, 6)) {
      const st = j.cancelled ? 'CANCELLED' : (j.timed_out ? 'TIMEOUT' : (j.returncode === 0 ? 'OK' : 'FAIL(' + j.returncode + ')'));
      rows.push({
        node_id: node.node_id, job_id: j.job_id, state: st,
        command: j.command, duration: j.duration_sec + 's', active: false
      });
    }
  }
  if (!rows.length) {
    wrap.innerHTML = '<p class="hint">No active or recent cluster tasks yet. Try running a command in Terminal Control or Parallel Batch!</p>';
    return;
  }
  wrap.innerHTML = '<div style="overflow-x:auto;"><table><thead><tr><th>Phone</th><th>Job ID</th><th>Status</th><th>Duration</th><th>Command</th><th>Action</th></tr></thead><tbody>'
    + rows.map(r => {
      const tone = r.state === 'OK' ? 'ok' : (r.state === 'RUNNING' ? 'warn' : 'bad');
      const btn = r.active
        ? '<button class="small danger" onclick="cancelJob(\'' + esc(r.node_id) + '\',\'' + esc(r.job_id) + '\')">Cancel</button>'
        : '<button class="small" onclick="openNodeTerminal(\'' + esc(r.node_id) + '\', \'' + esc(r.command).replace(/'/g, '&#39;') + '\')">Re-run</button>';
      return '<tr><td><b>' + esc(r.node_id) + '</b></td><td class="mono">' + esc(r.job_id) + '</td>'
        + '<td><span class="pill ' + tone + '">' + esc(r.state) + '</span></td>'
        + '<td class="mono">' + esc(r.duration) + '</td><td class="mono">' + esc(r.command) + '</td><td>' + btn + '</td></tr>';
    }).join('')
    + '</tbody></table></div>';
}

async function apiFetch(url) {
  const token = getToken();
  const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
  return await fetch(url, { headers });
}

async function refreshLive() {
  try {
    const r = await apiFetch('/api/live');
    if (r.status === 401) {
      document.getElementById('last-updated').textContent = 'Dashboard locked — paste auth_token above and click Unlock.';
      return;
    }
    const live = await r.json();
    lastLive = live;
    const d = live.summary;
    const hist = live.history || { cluster: [], nodes: {} };
    const safety = d.safety || {};
    const maxTemp = safety.max_temp_c ?? 40;
    const resTemp = safety.resume_temp_c ?? 37;
    const batHigh = safety.battery_high_pct ?? 60;

    document.getElementById('cluster-title').textContent = d.cluster_name + ' — Shared btop';
    document.getElementById('last-updated').textContent = 'Synced ' + new Date().toLocaleTimeString() + ' · ' + d.nodes_online + '/' + d.nodes_total + ' phones connected';

    // Hero KPIs + Sparklines
    const cHist = hist.cluster || [];
    document.getElementById('k-cpu').textContent = (d.cluster_cpu_pct ?? 0).toFixed(1) + '%';
    document.getElementById('k-cores').textContent = d.total_cores + ' cores';
    document.getElementById('spark-cpu').innerHTML = renderSparklineSvg(
      cHist.map(p => p.cpu_pct), 100, '#58a6ff', 'rgba(88,166,255,0.18)'
    );

    const usedGb = ((d.mem_total_mb - d.mem_available_mb) / 1024).toFixed(2);
    const totGb = (d.mem_total_mb / 1024).toFixed(2);
    document.getElementById('k-ram').textContent = usedGb + ' / ' + totGb + ' GB';
    document.getElementById('k-ram-pct').textContent = (d.cluster_ram_pct ?? 0).toFixed(0) + '%';
    document.getElementById('spark-ram').innerHTML = renderSparklineSvg(
      cHist.map(p => p.ram_pct), 100, '#a371f7', 'rgba(163,113,247,0.18)'
    );

    const peakT = d.max_temp_c;
    document.getElementById('k-temp').textContent = peakT !== null ? peakT.toFixed(1) + ' °C' : 'N/A';
    const tp = document.getElementById('k-temp-pill');
    if (peakT === null) { tp.textContent = 'N/A'; tp.className = 'pill neutral'; }
    else if (peakT >= maxTemp) { tp.textContent = '⚠ HOT'; tp.className = 'pill bad'; }
    else if (peakT >= resTemp) { tp.textContent = 'Warm'; tp.className = 'pill warn'; }
    else { tp.textContent = '✓ Cool'; tp.className = 'pill ok'; }
    document.getElementById('spark-temp').innerHTML = renderSparklineSvg(
      cHist.map(p => p.max_temp_c ?? 0), 55, peakT >= maxTemp ? '#f85149' : '#3fb950',
      peakT >= maxTemp ? 'rgba(248,81,73,0.18)' : 'rgba(63,185,80,0.16)'
    );

    document.getElementById('k-tasks').textContent = String(d.total_active_jobs || 0);
    document.getElementById('k-tasks-sub').textContent = d.total_active_jobs ? 'Active across cluster' : 'Idle · ready for work';
    document.getElementById('k-net').textContent = '↓' + (d.total_net_rx_kbps ?? 0) + ' ↑' + (d.total_net_tx_kbps ?? 0) + ' KB/s';

    document.getElementById('k-nodes').textContent = d.nodes_ready + ' / ' + d.nodes_total;
    document.getElementById('k-ping').textContent = (d.avg_latency_ms ?? 0) + ' ms';
    document.getElementById('k-nodes-sub').textContent = d.nodes_online + ' online · ' + d.nodes_ready + ' ready';

    // Update Terminal Target Dropdown dynamically
    const termSel = document.getElementById('term-target');
    const prevTerm = termSel.value;
    termSel.innerHTML = '<option value="best">Smart: Best Coolest Phone</option><option value="all">ALL READY PHONES (Broadcast)</option>';
    for (const n of d.nodes) {
      const opt = document.createElement('option');
      opt.value = n.id;
      opt.textContent = n.id + ' (' + n.role + ' · ' + n.host + ')';
      termSel.appendChild(opt);
    }
    if (Array.from(termSel.options).some(o => o.value === prevTerm)) termSel.value = prevTerm;

    // Render Shared Multi-Device btop Cards
    const batWarnings = [];
    const grid = document.getElementById('nodes-grid');
    grid.innerHTML = '';

    for (const n of d.nodes) {
      const h = n.health || {};
      const nHist = (hist.nodes && hist.nodes[n.id]) ? hist.nodes[n.id] : [];
      let badge = '<span class="pill bad">✕ OFFLINE</span>';
      let cardCls = 'node-card offline';
      if (n.online && n.ready_for_jobs) {
        badge = '<span class="pill ok">✓ READY (' + (h.active_jobs || 0) + '/' + (h.max_concurrency || n.max_concurrency || 2) + ')</span>';
        cardCls = 'node-card';
      } else if (n.online) {
        badge = '<span class="pill warn">⚠ ' + esc((h.not_ready_reasons || ['PAUSED']).join(', ')) + '</span>';
        cardCls = 'node-card hot';
      }

      if (n.online && h.battery_pct != null && h.battery_pct >= batHigh && (h.battery_status === 'CHARGING' || h.battery_status === 'FULL')) {
        batWarnings.push(n.id + ' is at ' + h.battery_pct + '% (' + h.battery_status + ')');
      }

      let bodyHtml = '';
      if (!n.online) {
        bodyHtml = '<p class="hint">Unreachable: ' + esc(n.error || 'connection refused') + '</p>';
      } else {
        const cores = h.cpu_cores || 1;
        const cpuPct = h.cpu_pct != null ? Number(h.cpu_pct) : Math.min(100, ((h.load_1m || 0) / cores) * 100);
        const perCore = h.per_core_pct || [];
        const coreCols = perCore.length
          ? '<div class="core-grid" title="Per-core CPU utilization">'
            + perCore.slice(0, 16).map(p => {
                const c = p >= 85 ? 'bad' : (p >= 60 ? 'warn' : '');
                return '<div class="core-col"><span class="' + c + '" style="height:' + Math.max(6, Math.round(p)) + '%"></span></div>';
              }).join('')
            + '</div>'
          : '';

        bodyHtml += '<div class="cpu-btop-box">'
          + '<div class="cpu-btop-top"><span><strong>CPU</strong> ' + cores + ' cores · load ' + esc(h.load_1m ?? 0) + '</span>'
          + '<span class="mono"><strong>' + cpuPct.toFixed(1) + '%</strong></span></div>'
          + '<div class="spark-wrap" style="height:28px;margin-top:0">'
          + renderSparklineSvg(nHist.map(p => p.cpu_pct), 100, '#58a6ff', 'rgba(88,166,255,0.18)')
          + '</div>' + coreCols + '</div>';

        const ramUsedMb = Math.max(0, (h.mem_total_mb || 0) - (h.mem_available_mb || 0));
        const ramUsedPct = h.mem_total_mb ? (ramUsedMb / h.mem_total_mb) * 100 : 0;
        const temp = h.temp_c;
        const tempTone = temp == null ? '' : (temp >= maxTemp ? 'bad' : (temp >= resTemp ? 'warn' : 'ok'));
        const bat = h.battery_pct;
        const batTone = bat == null ? '' : (bat >= batHigh && h.battery_status === 'CHARGING' ? 'warn' : (bat < 20 ? 'bad' : 'ok'));

        bodyHtml += metricBar('Memory', ramUsedMb + ' / ' + (h.mem_total_mb || 0) + ' MB (' + ramUsedPct.toFixed(0) + '%)', ramUsedPct, ramUsedPct > 85 ? 'bad' : '');
        bodyHtml += metricBar('Temperature', temp != null ? temp.toFixed(1) + ' °C' : 'N/A', temp != null ? (temp / 50) * 100 : 0, tempTone);
        bodyHtml += metricBar('Battery', bat != null ? bat + '% · ' + (h.battery_status || '?') : 'N/A', bat ?? 0, batTone);

        // Inline running tasks badge
        const activeJobs = h.active_job_list || [];
        if (activeJobs.length) {
          bodyHtml += '<div class="chips">' + activeJobs.map(j =>
            '<span class="pill accent mono">▶ ' + esc(j.command.slice(0, 26)) + ' (' + esc(j.running_sec) + 's)</span>'
          ).join('') + '</div>';
        }

        // Top processes mini-panel
        const procs = h.top_processes || [];
        if (procs.length) {
          bodyHtml += '<div class="mini-procs"><div class="mini-procs-head"><span>Top Processes</span><span>CPU / MEM</span></div>'
            + procs.slice(0, 4).map(p =>
                '<div class="proc-line mono"><span>' + esc(p.name) + ' <small style="color:var(--muted)">#' + esc(p.pid) + '</small></span>'
                + '<span>' + esc(p.cpu_pct) + '% / ' + esc(p.mem_pct) + '%</span></div>'
              ).join('')
            + '</div>';
        }

        const svcs = Object.entries(h.services || {}).filter(([, v]) => v).map(([k]) => k.split('_')[0]);
        const netChip = (h.net_rx_kbps != null && h.net_tx_kbps != null)
          ? '<span class="pill neutral mono">↓' + esc(h.net_rx_kbps) + ' ↑' + esc(h.net_tx_kbps) + ' KB/s</span>' : '';
        bodyHtml += '<div class="chips">'
          + '<span class="pill neutral">' + esc(h.os_env || 'linux') + '</span>'
          + '<span class="pill neutral mono">up ' + esc(fmtUptime(h.uptime_sec)) + '</span>'
          + '<span class="pill neutral mono">' + esc(n.latency_ms) + ' ms</span>'
          + netChip
          + svcs.map(s => '<span class="pill ok">' + esc(s) + '</span>').join('')
          + '</div>';
      }

      const rolePill = n.role === 'master'
        ? '<span class="pill purple">MASTER</span>'
        : '<span class="pill neutral">WORKER</span>';
      let actionsHtml = '<div class="node-actions">'
        + '<button class="small primary" onclick="openNodeTerminal(\'' + esc(n.id) + '\')">Terminal</button>';
      if (n.role !== 'master') {
        actionsHtml += '<button class="small danger" onclick="removeNode(\'' + esc(n.id) + '\')">Remove</button>';
      }
      actionsHtml += '</div>';

      const card = document.createElement('article');
      card.className = cardCls;
      card.innerHTML = '<div><div class="node-head">'
        + '<div><div class="node-title">' + esc(n.id) + ' ' + rolePill + '</div>'
        + '<div class="node-meta mono">' + esc(n.host) + '</div></div>'
        + badge + '</div>' + bodyHtml + '</div>' + actionsHtml;
      grid.appendChild(card);
    }

    const banner = document.getElementById('battery-banner');
    if (batWarnings.length) {
      document.getElementById('battery-banner-text').textContent = batWarnings.join('; ')
        + '. Avoid leaving Li-Po batteries pinned at 100% 24/7 (configure a smart-plug webhook in Tab 5 or use rooted ACC).';
      banner.classList.remove('hidden');
    } else {
      banner.classList.add('hidden');
    }

    renderTasksBoard(live);
  } catch (e) {
    document.getElementById('last-updated').textContent = 'Connection error: ' + e;
  }
}

/* ---------------- Interactive Multi-Node Web Terminal ---------------- */
function onTermTargetChange() {
  const target = document.getElementById('term-target').value;
  const cwd = termCwds[target] || '~';
  document.getElementById('term-cwd-pill').textContent = cwd;
  document.getElementById('term-prompt').textContent = target + ':' + cwd.split('/').slice(-1)[0] + ' $';
}

function openNodeTerminal(nodeId, prefillCmd) {
  selectTab('terminal');
  const sel = document.getElementById('term-target');
  if (Array.from(sel.options).some(o => o.value === nodeId)) sel.value = nodeId;
  onTermTargetChange();
  const inp = document.getElementById('term-input');
  if (prefillCmd) inp.value = prefillCmd;
  inp.focus();
}

function runTermPreset(cmd) {
  document.getElementById('term-input').value = cmd;
  submitTerminalCommand();
}

function clearTerminal() {
  document.getElementById('term-screen').innerHTML = '';
  termTranscript = [];
}

function downloadTermLog() {
  const blob = new Blob([termTranscript.join('\n\n')], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'phonecluster-terminal-' + Date.now() + '.log';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function submitTerminalCommand() {
  const inp = document.getElementById('term-input');
  const cmd = inp.value.trim();
  if (!cmd) return;
  if (cmd === 'clear') { inp.value = ''; clearTerminal(); return; }

  const target = document.getElementById('term-target').value;
  const cwd = termCwds[target] || '';
  termHistory.push(cmd);
  termHistIdx = -1;
  inp.value = '';

  const screen = document.getElementById('term-screen');
  const entry = document.createElement('div');
  entry.className = 'term-entry';
  const promptText = target + ':' + (cwd ? cwd.split('/').slice(-1)[0] : '~') + ' $ ' + cmd;
  entry.innerHTML = '<div class="term-cmd-line">' + esc(promptText) + '<span class="term-meta">running...</span></div>';
  screen.appendChild(entry);
  screen.scrollTop = screen.scrollHeight;

  const jobId = 'wterm-' + Date.now().toString(36);
  activeTermJob = { node_id: target, job_id: jobId };
  document.getElementById('btn-term-run').disabled = true;
  document.getElementById('btn-term-cancel').disabled = (target === 'all' || target === 'best');

  try {
    const data = await authPost('/api/terminal/exec', { command: cmd, target, cwd, job_id: jobId });
    if (data.error) {
      entry.innerHTML = '<div class="term-cmd-line">' + esc(promptText) + '</div><div class="term-err">Error: ' + esc(data.error) + '</div>';
      showToast(data.error, 'bad');
      return;
    }
    let html = '<div class="term-cmd-line">' + esc(promptText) + '</div>';
    let plainOut = '$ ' + promptText + '\n';
    for (const r of (data.results || [])) {
      if (target !== 'all' && r.cwd) {
        termCwds[target] = r.cwd;
        onTermTargetChange();
      }
      const meta = '[' + r.node_id + ' · ' + (r.ok ? 'OK' : 'rc=' + r.returncode) + ' · ' + r.duration_sec + 's]';
      html += '<div class="term-meta" style="margin-left:0;">' + esc(meta) + '</div>';
      if (r.stdout) { html += '<div>' + esc(r.stdout) + '</div>'; plainOut += meta + '\n' + r.stdout + '\n'; }
      if (r.stderr) { html += '<div class="term-err">' + esc(r.stderr) + '</div>'; plainOut += '[stderr]\n' + r.stderr + '\n'; }
      if (r.error) { html += '<div class="term-err">Error: ' + esc(r.error) + '</div>'; plainOut += '[error] ' + r.error + '\n'; }
    }
    entry.innerHTML = html;
    termTranscript.push(plainOut.trim());
    screen.scrollTop = screen.scrollHeight;
    refreshLive();
  } finally {
    activeTermJob = null;
    document.getElementById('btn-term-run').disabled = false;
    document.getElementById('btn-term-cancel').disabled = true;
  }
}

async function cancelActiveTermJob() {
  if (!activeTermJob) return;
  await cancelJob(activeTermJob.node_id, activeTermJob.job_id);
}

async function cancelJob(nodeId, jobId) {
  const data = await authPost('/api/jobs/cancel', { node_id: nodeId, job_id: jobId });
  if (data.error) { showToast('Cancel failed: ' + data.error, 'bad'); return; }
  showToast('Cancelled job ' + jobId + ' on ' + nodeId, 'warn');
  refreshLive();
}

/* ---------------- Parallel Batch, Workloads, Setup & Doctor ---------------- */
function applyMapTemplate(name) {
  if (!name) return;
  if (name === 'primes') {
    document.getElementById('map-mode').value = 'script';
    toggleMapMode();
    document.getElementById('map-interp').value = 'python3';
    document.getElementById('map-script').value =
      "import math, os, sys, time\n"
      + "limit = int(sys.argv[1])\n"
      + "t0 = time.monotonic()\n"
      + "s = bytearray(b'\\x01') * (limit + 1)\n"
      + "s[0:2] = b'\\x00\\x00'\n"
      + "for p in range(2, int(math.isqrt(limit)) + 1):\n"
      + "    if s[p]: s[p*p:limit+1:p] = b'\\x00' * ((limit - p*p)//p + 1)\n"
      + "print(f\"node={os.environ.get('PHONECLUSTER_NODE_ID')} limit={limit} primes={sum(s)} time={time.monotonic()-t0:.3f}s\")";
    document.getElementById('map-args').value = "100000\n200000\n300000\n400000\n500000\n600000";
  } else if (name === 'audit') {
    document.getElementById('map-mode').value = 'commands';
    toggleMapMode();
    document.getElementById('map-commands').value =
      'echo "$PHONECLUSTER_NODE_ID: $(uname -m) $(nproc) cores"\n'
      + 'echo "$PHONECLUSTER_NODE_ID: $(uptime)"\n'
      + 'echo "$PHONECLUSTER_NODE_ID: $(df -h ~ | tail -n 1)"';
  } else if (name === 'squares') {
    document.getElementById('map-mode').value = 'script';
    toggleMapMode();
    document.getElementById('map-interp').value = 'python3';
    document.getElementById('map-script').value =
      "import os, sys\nn = int(sys.argv[1])\nprint(f\"node={os.environ.get('PHONECLUSTER_NODE_ID')} square({n})={n*n}\")";
    document.getElementById('map-args').value = "10\n20\n30\n40\n50\n60";
  }
  showToast('Loaded template: ' + name, 'ok');
}

function loadFileInto(input, targetId) {
  const file = input.files && input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    document.getElementById(targetId).value = String(reader.result || '');
    if (targetId === 'map-script' && file.name.endsWith('.sh')) {
      document.getElementById('map-interp').value = 'bash';
    }
    showToast('Loaded ' + file.name, 'ok');
  };
  reader.readAsText(file);
  input.value = '';
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

function toggleMapMode() {
  const mode = document.getElementById('map-mode').value;
  document.getElementById('map-commands-box').style.display = mode === 'commands' ? 'block' : 'none';
  document.getElementById('map-script-box').style.display = mode === 'script' ? 'block' : 'none';
}

async function runParallelMap() {
  const mode = document.getElementById('map-mode').value;
  const btn = document.getElementById('btn-run-map');
  const out = document.getElementById('map-out');
  const chips = document.getElementById('map-summary-chips');
  btn.disabled = true;
  chips.innerHTML = '';
  out.textContent = 'Dispatching parallel batch across all ready phones...';
  try {
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
    if (data.error) { out.textContent = 'Error: ' + data.error; showToast(data.error, 'bad'); return; }
    lastMapData = data;
    document.getElementById('btn-dl-map').disabled = false;
    chips.innerHTML = '<span class="pill neutral mono">' + esc(data.wall_sec) + 's</span>'
      + '<span class="pill ok">✓ OK: ' + esc(data.ok_count) + '</span>'
      + (data.fail_count ? '<span class="pill bad">✕ FAIL: ' + esc(data.fail_count) + '</span>' : '')
      + Object.entries(data.distribution || {}).map(([k, v]) => '<span class="pill neutral">' + esc(k) + ': ' + esc(v) + '</span>').join('');
    let txt = '';
    for (const r of (data.results || [])) {
      txt += '[' + (r.ok ? 'OK' : 'FAIL') + '] ' + r.node_id + ' (' + r.duration_sec + 's) ' + r.label + '\n  '
        + (r.stdout || r.stderr || r.error || '').trim().replace(/\n/g, '\n  ') + '\n';
    }
    out.textContent = txt || 'Done.';
    showToast('Batch complete: ' + data.ok_count + ' succeeded, ' + data.fail_count + ' failed', data.fail_count ? 'warn' : 'ok');
    refreshLive();
  } finally {
    btn.disabled = false;
  }
}

function downloadLastMapJson() {
  if (!lastMapData) return;
  const blob = new Blob([JSON.stringify(lastMapData, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'phonecluster-batch-' + Date.now() + '.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function loadWorkloads() {
  try {
    const r = await apiFetch('/api/workloads');
    if (r.status === 401) return;
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

async function workloadAction(action) {
  const cidr = document.getElementById('distcc-cidr').value.trim() || '192.168.1.0/24';
  const out = document.getElementById('wl-action-out');
  out.style.display = 'block';
  out.textContent = 'Running ' + action + ' on all ready phones...';
  const data = await authPost('/api/workloads/action', { action, cidr });
  out.textContent = JSON.stringify(data, null, 2);
  showToast(data.error ? data.error : 'Workload command finished: ' + action, data.error ? 'bad' : 'ok');
  setTimeout(loadWorkloads, 800);
}

let pairPollTimer = null;
let knownPairedCount = 0;

function renderPairingState(st) {
  const box = document.getElementById('pair-active-box');
  const btnClose = document.getElementById('btn-pair-close');
  if (!st || !st.active) {
    box.style.display = 'none';
    btnClose.style.display = 'none';
    if (pairPollTimer) { clearInterval(pairPollTimer); pairPollTimer = null; }
    return;
  }
  box.style.display = 'block';
  btnClose.style.display = 'inline-block';
  document.getElementById('pair-pin').textContent = st.pin;
  document.getElementById('pair-fp').textContent = st.fingerprint;
  document.getElementById('pair-att').textContent = st.attempts_left + '/5';
  document.getElementById('pair-rem').textContent = String(st.remaining_slots);
  document.getElementById('pair-timer').textContent = st.expires_in_sec + 's left';

  const recents = st.recent_paired || [];
  if (recents.length > knownPairedCount) {
    const latest = recents[recents.length - 1];
    knownPairedCount = recents.length;
    showToast('✓ Securely paired ' + latest.id + ' (' + latest.host + ') with its own unique token!', 'ok');
    refreshLive();
  }
}

async function openPairingWindow() {
  const max_devices = Number(document.getElementById('pair-slots').value || 1);
  const data = await authPost('/api/pair/open', { ttl_sec: 120, max_devices });
  if (data.error) { showToast('Could not open pairing: ' + data.error, 'bad'); return; }
  knownPairedCount = (data.recent_paired || []).length;
  renderPairingState(data);
  showToast('Pairing window open for 2 minutes! Run `pc join` on your new phone.', 'ok');
  if (pairPollTimer) clearInterval(pairPollTimer);
  pairPollTimer = setInterval(pollPairingStatus, 1500);
}

async function closePairingWindow() {
  const data = await authPost('/api/pair/close', {});
  if (data.error) { showToast(data.error, 'bad'); return; }
  renderPairingState(data);
  showToast('Pairing window closed — cluster is silent on Wi-Fi.', 'neutral');
}

async function pollPairingStatus() {
  if (!getToken()) return;
  try {
    const r = await apiFetch('/api/pair/status');
    if (!r.ok) return;
    const st = await r.json();
    const recents = st.recent_paired || [];
    if (recents.length > knownPairedCount) {
      const latest = recents[recents.length - 1];
      knownPairedCount = recents.length;
      showToast('✓ Securely paired ' + latest.id + ' (' + latest.host + ') with its own unique token!', 'ok');
      refreshLive();
    }
    renderPairingState(st);
  } catch (e) {}
}

async function scanLan() {
  const box = document.getElementById('discover-list');
  box.innerHTML = 'Scanning Wi-Fi (2 seconds)...';
  try {
    const r = await apiFetch('/api/discover');
    const d = await r.json();
    if (!d.discovered || !d.discovered.length) {
      box.innerHTML = '<p class="hint">No phones answered UDP discovery on port 8766. Make sure workers are running on the same Wi-Fi, or use Manual Add below.</p>';
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
  if (data.error) { showToast('Could not add node: ' + data.error, 'bad'); return; }
  showToast('Added ' + data.node.id + ' (' + data.node.host + ') to cluster.json!', 'ok');
  scanLan();
  refreshLive();
}

async function addManualNode() {
  const host = document.getElementById('add-host').value.trim();
  const ssh_user = document.getElementById('add-user').value.trim();
  const ssh_port = Number(document.getElementById('add-ssh-port').value || 8022);
  const max_concurrency = Number(document.getElementById('add-conc').value || 2);
  if (!host) { showToast('Enter an IP address first.', 'warn'); return; }
  const data = await authPost('/api/nodes/add', { host, ssh_user, ssh_port, max_concurrency });
  if (data.error) { showToast('Could not add phone: ' + data.error, 'bad'); return; }
  document.getElementById('add-host').value = '';
  showToast('Added ' + data.node.id + ' (' + data.node.host + ')!', 'ok');
  refreshLive();
}

async function removeNode(nodeId) {
  if (!confirm('Remove ' + nodeId + ' from cluster.json?')) return;
  const data = await authPost('/api/nodes/remove', { id: nodeId });
  if (data.error) { showToast('Remove failed: ' + data.error, 'bad'); return; }
  showToast('Removed ' + nodeId + ' from cluster.', 'warn');
  refreshLive();
}

async function loadSafetySettings() {
  const token = getToken();
  if (!token) return;
  try {
    const r = await fetch('/api/settings', { headers: { 'Authorization': 'Bearer ' + token } });
    if (!r.ok) return;
    const s = await r.json();
    document.getElementById('set-max-temp').value = s.max_temp_c;
    document.getElementById('set-res-temp').value = s.resume_temp_c;
    document.getElementById('set-bat-low').value = s.battery_low_pct;
    document.getElementById('set-bat-high').value = s.battery_high_pct;
    document.getElementById('set-webhook').value = s.battery_webhook_url || '';
  } catch (e) {}
}

async function saveSafetySettings() {
  const payload = {
    max_temp_c: Number(document.getElementById('set-max-temp').value),
    resume_temp_c: Number(document.getElementById('set-res-temp').value),
    battery_low_pct: Number(document.getElementById('set-bat-low').value),
    battery_high_pct: Number(document.getElementById('set-bat-high').value),
    battery_webhook_url: document.getElementById('set-webhook').value.trim(),
  };
  const data = await authPost('/api/settings', payload);
  if (data.error) { showToast('Save failed: ' + data.error, 'bad'); return; }
  showToast('Safety settings saved! Run `pc sync` to push to worker phones.', 'ok');
  refreshLive();
}

async function testSafetyWebhook() {
  const url = document.getElementById('set-webhook').value.trim();
  const data = await authPost('/api/settings/test-webhook', { battery_webhook_url: url });
  if (data.error) { showToast('Webhook test failed: ' + data.error, 'bad'); return; }
  showToast('Test webhook delivered (HTTP ' + data.http_status + ')!', 'ok');
}

async function runDoctorUi() {
  const box = document.getElementById('doctor-list');
  box.innerHTML = 'Running diagnostics...';
  try {
    const r = await apiFetch('/api/doctor');
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
  if (navigator.clipboard) {
    navigator.clipboard.writeText(txt).then(() => showToast('Copied to clipboard!', 'ok'));
  }
}

function refreshAll() {
  refreshLive();
  if (document.getElementById('panel-workloads').classList.contains('active')) loadWorkloads();
}

initPreferences();
updateAuthBadge();
onTermTargetChange();
refreshLive();
scheduleRefresh();
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
        enable_pairing_beacon: bool = True,
        pairing_fail_delay_sec: float = 1.0,
    ) -> None:
        self.controller = controller
        self.config_path = config_path
        self.rate_limiter = AuthRateLimiter(max_failures=10, window_sec=60.0, block_sec=60.0)
        super().__init__(addr, DashboardRequestHandler)
        self.pairing_manager = PairingManager(
            config=controller.config,
            config_path=config_path,
            pair_port=self.server_address[1],
            listen_host=addr[0],
            fail_delay_sec=pairing_fail_delay_sec,
            enable_beacon=enable_pairing_beacon,
        )

    def server_close(self) -> None:
        try:
            self.pairing_manager.close_session()
        finally:
            super().server_close()


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
        client_ip = self.client_address[0]
        blocked, retry_after = self.server.rate_limiter.is_blocked(client_ip)
        if blocked:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": f"too many failed auth attempts; retry in {retry_after}s", "retry_after_sec": retry_after},
            )
            return False
        if not verify_token(self.headers, self.server.controller.config.auth_token):
            self.server.rate_limiter.record_failure(client_ip)
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized (invalid or missing auth_token)"})
            return False
        self.server.rate_limiter.record_success(client_ip)
        return True

    def _require_read_auth_if_locked(self) -> bool:
        if self.server.controller.config.dashboard_require_auth:
            return self._require_auth()
        return True

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in {"/", "/index.html"}:
            self._send(HTTPStatus.OK, "text/html; charset=utf-8", DASHBOARD_HTML.encode("utf-8"))
        elif path == "/api/pair/hello":
            status, data = self.server.pairing_manager.public_hello()
            self._send_json(status, data)
        elif path == "/api/pair/status":
            if self._require_auth():
                self._send_json(HTTPStatus.OK, self.server.pairing_manager.admin_status())
        elif path == "/api/auth/verify":
            if self._require_auth():
                self._send_json(HTTPStatus.OK, {"valid": True})
        elif path == "/api/settings":
            if not self._require_auth():
                return
            s = self.server.controller.config.safety
            self._send_json(
                HTTPStatus.OK,
                {
                    "max_temp_c": s.max_temp_c,
                    "resume_temp_c": s.resume_temp_c,
                    "min_free_ram_mb": s.min_free_ram_mb,
                    "battery_low_pct": s.battery_low_pct,
                    "battery_high_pct": s.battery_high_pct,
                    "battery_webhook_url": s.battery_webhook_url,
                },
            )
        elif path in {"/api/status", "/api/metrics", "/api/live", "/api/jobs", "/api/doctor", "/api/workloads", "/api/discover"}:
            if not self._require_read_auth_if_locked():
                return
            if path == "/api/status":
                self._send_json(HTTPStatus.OK, self.server.controller.cluster_summary())
            elif path == "/api/metrics":
                self._send_json(HTTPStatus.OK, self.server.controller.metrics_history.snapshot())
            elif path == "/api/live":
                summary = self.server.controller.cluster_summary()
                jobs = self.server.controller.get_all_jobs()
                history = self.server.controller.metrics_history.snapshot()
                self._send_json(HTTPStatus.OK, {"summary": summary, "jobs": jobs, "history": history})
            elif path == "/api/jobs":
                self._send_json(HTTPStatus.OK, {"nodes": self.server.controller.get_all_jobs()})
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
        if path == "/api/pair/complete":
            body = self._read_json()
            if body is None:
                return
            status, data = self.server.pairing_manager.complete_pairing(self.client_address[0], body)
            self._send_json(status, data)
            return

        valid_paths = {
            "/api/exec",
            "/api/terminal/exec",
            "/api/map",
            "/api/jobs/cancel",
            "/api/nodes/add",
            "/api/nodes/remove",
            "/api/workloads/action",
            "/api/settings",
            "/api/settings/test-webhook",
            "/api/pair/open",
            "/api/pair/close",
        }
        if path not in valid_paths:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._require_auth():
            return
        body = self._read_json()
        if body is None:
            return

        ctrl = self.server.controller

        if path == "/api/pair/open":
            ttl = int(body.get("ttl_sec", 120))
            slots = int(body.get("max_devices", 1))
            data = self.server.pairing_manager.open_session(ttl_sec=ttl, max_devices=slots)
            self._send_json(HTTPStatus.OK, data)
            return
        if path == "/api/pair/close":
            data = self.server.pairing_manager.close_session()
            self._send_json(HTTPStatus.OK, data)
            return

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

        elif path == "/api/terminal/exec":
            command = str(body.get("command", "")).strip()
            target = str(body.get("target", "best")).strip() or "best"
            cwd = str(body.get("cwd", "")).strip() or None
            job_id = str(body.get("job_id", "")).strip() or None
            if not command:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty command"})
                return
            try:
                results = ctrl.exec_terminal_command(
                    command=command,
                    target=target,
                    cwd=cwd,
                    timeout_sec=float(body.get("timeout_sec", ctrl.config.default_job_timeout_sec)),
                    job_id=job_id,
                )
            except KeyError as exc:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.OK, {"results": results})

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

        elif path == "/api/jobs/cancel":
            node_id = str(body.get("node_id", "")).strip()
            job_id = str(body.get("job_id", "")).strip()
            if not node_id or not job_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing node_id or job_id"})
                return
            try:
                res = ctrl.cancel_node_job(node_id, job_id)
            except KeyError as exc:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
                return
            status = HTTPStatus.OK if res.get("cancelled") else HTTPStatus.NOT_FOUND
            self._send_json(status, res)

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
                max_concurrency=max(1, int(body.get("max_concurrency", 2))),
                weight=max(0.1, float(body.get("weight", 1.0))),
                tags=["worker"],
                notes="Added via Web Control Center",
            )
            ctrl.config.nodes.append(new_node)
            if self.server.config_path is not None:
                save_config(ctrl.config, self.server.config_path)
            self._send_json(HTTPStatus.OK, {"node": {"id": new_node.id, "host": new_node.host}})

        elif path == "/api/nodes/remove":
            node_id = str(body.get("id", "")).strip()
            if not node_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing node id"})
                return
            target_node = next((n for n in ctrl.config.nodes if n.id == node_id), None)
            if target_node is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"node '{node_id}' not found"})
                return
            if target_node.role == "master":
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "cannot remove the master node"})
                return
            ctrl.config.nodes = [n for n in ctrl.config.nodes if n.id != node_id]
            if self.server.config_path is not None:
                save_config(ctrl.config, self.server.config_path)
            self._send_json(HTTPStatus.OK, {"removed": node_id})

        elif path == "/api/settings":
            try:
                updated = SafetyConfig.from_dict(
                    {
                        "max_temp_c": body.get("max_temp_c", ctrl.config.safety.max_temp_c),
                        "resume_temp_c": body.get("resume_temp_c", ctrl.config.safety.resume_temp_c),
                        "min_free_ram_mb": body.get("min_free_ram_mb", ctrl.config.safety.min_free_ram_mb),
                        "battery_low_pct": body.get("battery_low_pct", ctrl.config.safety.battery_low_pct),
                        "battery_high_pct": body.get("battery_high_pct", ctrl.config.safety.battery_high_pct),
                        "battery_poll_sec": ctrl.config.safety.battery_poll_sec,
                        "webhook_cooldown_sec": ctrl.config.safety.webhook_cooldown_sec,
                        "battery_webhook_url": body.get(
                            "battery_webhook_url", ctrl.config.safety.battery_webhook_url
                        ),
                    }
                )
            except (ValueError, TypeError) as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            ctrl.config.safety = updated
            if self.server.config_path is not None:
                save_config(ctrl.config, self.server.config_path)
            self._send_json(HTTPStatus.OK, {"saved": True})

        elif path == "/api/settings/test-webhook":
            url = str(body.get("battery_webhook_url") or ctrl.config.safety.battery_webhook_url).strip()
            if not url or not url.startswith(("http://", "https://")):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "enter a valid http:// or https:// webhook URL"})
                return
            test_payload = {
                "event": "test",
                "node_id": "master",
                "message": "PhoneCluster test battery/thermal webhook notification.",
                "timestamp": int(time.time()),
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(test_payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    self._send_json(HTTPStatus.OK, {"delivered": True, "http_status": resp.status})
            except urllib.error.HTTPError as exc:
                code = exc.code
                exc.close()
                self._send_json(HTTPStatus.BAD_GATEWAY, {"error": f"webhook returned HTTP {code}"})
            except (urllib.error.URLError, OSError, ValueError) as exc:
                self._send_json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})


def _start_background_sampler(
    controller: MasterController,
    stop_event: threading.Event,
    interval_sec: float = 4.0,
) -> threading.Thread:
    """Keep sparkline metrics warm even before a browser tab connects."""
    def _loop() -> None:
        while not stop_event.is_set():
            try:
                controller.cluster_summary(record_history=True)
            except Exception:
                pass
            stop_event.wait(interval_sec)

    t = threading.Thread(target=_loop, name="metrics-sampler", daemon=True)
    t.start()
    return t


def serve_dashboard(
    bind_host: str,
    port: int,
    controller: MasterController,
    config_path: Path | None = None,
) -> None:
    """Start the Master Phone's accessible btop Web Control Center."""
    server = DashboardHTTPServer((bind_host, port), controller, config_path=config_path)
    stop_event = threading.Event()
    _start_background_sampler(controller, stop_event, interval_sec=4.0)
    lan_ip = detect_local_ip()
    actual_port = server.server_address[1]
    print(f"PhoneCluster Web Control Center -> http://{lan_ip}:{actual_port}")
    print("Unlock controls with your token (run `pc token` to view it). Press Ctrl+C to stop.")
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
        stop_event.set()
        server.server_close()
