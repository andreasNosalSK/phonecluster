"""Accessible, offline-first, btop-inspired Web Control Center + Interactive Web Terminal."""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import math
import re
import shlex
import signal
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .auth import (
    AuthRateLimiter,
    build_webhook_opener,
    is_allowed_http_host,
    is_webhook_target_unsafe,
    parse_strict_content_length,
    safe_json_dumps,
    verify_token,
)
from .config import (
    DEFAULT_SSH_PORT,
    DEFAULT_WORKER_PORT,
    GatewayConfig,
    NetworkHardeningConfig,
    NodeConfig,
    SafetyConfig,
    format_host_port,
    is_loopback_or_unspecified_host,
    normalize_host,
    save_config,
    validate_allowed_master_entry,
    validate_domain_pattern,
    validate_host,
    validate_node_id,
    validate_pool_name,
    validate_ssh_user,
)
from .discovery import detect_local_ip, discover_lan_nodes
from .doctor import run_doctor
from .gateway import GatewayManager
from .master import JobSpec, MasterController
from .netguard import apply_security_profile, audit_cluster_network, infer_lan_subnet
from .pairing import PairingManager
from .routing import resolve_node_tier_and_pool

LOG = logging.getLogger("phonecluster.dashboard")

MAX_DASHBOARD_BODY = 2 * 1024 * 1024
WORKLOAD_HELPER_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "05_workload_helpers.sh"
_WEBHOOK_OPENER = build_webhook_opener()

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
  .pool-strip {
    display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; align-items: stretch;
  }
  .pool-chip {
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 9px 13px; text-align: left; display: flex; flex-direction: column; gap: 2px;
    min-width: 170px; box-shadow: var(--shadow); color: var(--fg);
  }
  .pool-chip:hover { border-color: var(--border-hi); }
  .pool-chip.active {
    border-color: var(--accent);
    background: linear-gradient(135deg, rgba(88, 166, 255, 0.16), rgba(163, 113, 247, 0.12));
  }
  .pool-chip-title { font-weight: 800; font-size: 0.88rem; display: flex; align-items: center; gap: 6px; }
  .pool-chip-sub { font-size: 0.77rem; color: var(--muted); }
  .tier-edit-box {
    margin-top: 10px; padding: 10px; border-radius: 10px;
    background: var(--surface-3); border: 1px solid var(--border);
  }
  .quick-strip {
    display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; align-items: center;
  }
  .quick-strip button {
    background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
    padding: 7px 12px; font-size: 0.85rem;
  }
  .quick-strip button:hover { border-color: var(--accent); }
  .pipe-flow {
    display: flex; flex-wrap: wrap; align-items: center; gap: 8px;
    padding: 10px 12px; margin-bottom: 12px; border-radius: 10px;
    background: var(--surface-3); border: 1px solid var(--border);
  }
  .pipe-flow-node {
    display: inline-flex; align-items: center; gap: 6px; padding: 5px 10px;
    border-radius: 8px; background: var(--surface-2); border: 1px solid var(--border);
    font-size: 0.82rem; font-weight: 700;
  }
  .pipe-flow-node.ok { border-color: var(--ok); background: var(--ok-bg); }
  .pipe-flow-node.bad { border-color: var(--bad); background: var(--bad-bg); }
  .pipe-flow-arrow { color: var(--muted); font-weight: 800; }
  .step-card {
    background: var(--surface-2); border: 1px solid var(--border); border-radius: 12px;
    padding: 12px 14px; margin-bottom: 10px;
  }
  .step-card-head {
    display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between;
    margin-bottom: 8px;
  }
  .step-num {
    width: 26px; height: 26px; border-radius: 50%; display: inline-grid; place-items: center;
    background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: var(--accent-fg);
    font-weight: 800; font-size: 0.82rem; flex-shrink: 0;
  }
  .var-chip {
    background: var(--surface-3); border: 1px solid var(--border); border-radius: 999px;
    padding: 3px 9px; font-size: 0.76rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    color: var(--accent); font-weight: 600; cursor: pointer;
  }
  .var-chip:hover { border-color: var(--accent); background: rgba(88, 166, 255, 0.14); }
  .pipe-res-card {
    background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px;
    padding: 10px 12px; margin-top: 8px;
  }
  .pipe-res-card.ok { border-left: 4px solid var(--ok); }
  .pipe-res-card.bad { border-left: 4px solid var(--bad); }
  .mesh-diagram {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px; margin-bottom: 14px;
  }
  .mesh-tier-box {
    background: var(--surface-2); border: 1px solid var(--border); border-radius: 12px;
    padding: 11px 13px;
  }
  .profile-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    gap: 10px; margin: 10px 0 12px;
  }
  .profile-btn {
    background: var(--surface-2); border: 1px solid var(--border); border-radius: 12px;
    padding: 12px 14px; text-align: left; display: flex; flex-direction: column; gap: 4px;
    color: var(--fg); font-weight: 400;
  }
  .profile-btn:hover { border-color: var(--accent); background: rgba(88, 166, 255, 0.08); }
  .profile-btn strong { font-size: 0.94rem; }
  .profile-btn span { font-size: 0.79rem; color: var(--muted); line-height: 1.38; }
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
    <button role="tab" id="tab-overview" aria-selected="true" aria-controls="panel-overview" onclick="selectTab('overview')">1. Live btop &amp; Pools</button>
    <button role="tab" id="tab-terminal" aria-selected="false" aria-controls="panel-terminal" onclick="selectTab('terminal')">2. Terminal Control</button>
    <button role="tab" id="tab-jobs" aria-selected="false" aria-controls="panel-jobs" onclick="selectTab('jobs')">3. Parallel Batch &amp; Pipelines</button>
    <button role="tab" id="tab-workloads" aria-selected="false" aria-controls="panel-workloads" onclick="selectTab('workloads')">4. Workloads &amp; Service Mesh</button>
    <button role="tab" id="tab-network" aria-selected="false" aria-controls="panel-network" onclick="selectTab('network')">5. Network &amp; Pi Guard</button>
    <button role="tab" id="tab-setup" aria-selected="false" aria-controls="panel-setup" onclick="selectTab('setup')">6. Phones, Safety &amp; Doctor</button>
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

      <div class="quick-strip" aria-label="Quick navigation shortcuts">
        <span class="hint" style="margin:0 4px 0 0;">Quick actions:</span>
        <button onclick="selectTab('terminal')">⚡ Auto-Route Terminal</button>
        <button onclick="selectTab('jobs')">🔗 Cross-Tier Pipeline Builder</button>
        <button onclick="selectTab('workloads')">🌐 Service Mesh &amp; .cluster DNS</button>
        <button onclick="selectTab('network')">🛡️ Network &amp; Pi Guard</button>
        <button onclick="selectTab('setup')">📱 Pair New Phone</button>
      </div>

      <div id="pool-strip" class="pool-strip" role="group" aria-label="Filter phones by Tier and Pool"></div>
      <div id="node-tier-editor" class="card" style="display:none" aria-live="polite"></div>

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
            <select id="term-target" onchange="onTermTargetChange()" aria-label="Terminal target phone or tier">
              <option value="auto">⚡ Auto-Route by Workload (Smart Tier)</option>
              <option value="tier:1">Tier 1 · Termux Compute &amp; AI</option>
              <option value="tier:2">Tier 2 · Debian 13 Services</option>
              <option value="tier:3">Tier 3 · Docker &amp; Containers</option>
              <option value="best">Best Coolest Phone (Any Tier)</option>
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
            <span class="term-cmd-line">PhoneCluster Unified Terminal (Auto-Routing Across Tiers)</span>
            <div class="hint" style="color:#8b9bb4;">In Auto-Route mode, commands are automatically routed to the right tier (Docker → Tier 3, Debian services/MQTT → Tier 2, compute/AI → Tier 1) with live <code class="mono">$PHONECLUSTER_*</code> cross-tier service env vars injected.</div>
          </div>
        </div>
        <div class="term-input-bar">
          <span id="term-prompt" class="term-prompt-label mono">auto:~ $</span>
          <label class="sr-only" for="term-input">Terminal command input</label>
          <input id="term-input" type="text" autocomplete="off" spellcheck="false" placeholder="Type any command (docker ps, mosquitto_pub, python3 ..., uname -a)..." />
          <button id="btn-term-run" class="small primary" onclick="submitTerminalCommand()">Run</button>
        </div>
      </div>
      <div class="chips" style="margin-top:10px;" aria-label="Quick terminal commands">
        <span class="hint" style="margin:0 4px 0 0;">Quick commands:</span>
        <button class="small" onclick="runTermPreset('uname -a && nproc')">System Info</button>
        <button class="small" onclick="runTermPreset('env | grep ^PHONECLUSTER_ | sort')">Cross-Tier Env</button>
        <button class="small" onclick="runTermPreset('docker ps 2>&1')">Docker Status (Tier 3)</button>
        <button class="small" onclick="runTermPreset('df -h ~')">Disk Space</button>
        <button class="small" onclick="runTermPreset('uptime && head -n 5 /proc/meminfo')">Load &amp; RAM</button>
        <button class="small" onclick="runTermPreset('ps -eo pid,pcpu,pmem,comm --sort=-pcpu 2>/dev/null | head -n 12 || ps | head -n 12')">Top Processes</button>
      </div>
    </section>

    <!-- TAB 3: PARALLEL BATCH & CROSS-TIER PIPELINES -->
    <section id="panel-jobs" class="panel" role="tabpanel" aria-labelledby="tab-jobs">
      <div class="card">
        <h2>Parallel Batch Runner (Smart Tier Auto-Routing)</h2>
        <div class="row">
          <label for="map-mode">Mode:</label>
          <select id="map-mode" onchange="toggleMapMode()">
            <option value="commands">Shell Command List (1 per line)</option>
            <option value="script">Ship &amp; Run Script + Arguments</option>
          </select>
          <label for="map-target">Target Tier/Pool:</label>
          <select id="map-target" aria-label="Batch target tier or pool">
            <option value="auto">⚡ Auto-Route Each Job</option>
            <option value="tier:1">Tier 1 · Termux Compute</option>
            <option value="tier:2">Tier 2 · Debian 13 Services</option>
            <option value="tier:3">Tier 3 · Docker / Containers</option>
            <option value="all">All Ready Phones (Any Tier)</option>
          </select>
          <label class="sr-only" for="map-template">Load sample template</label>
          <select id="map-template" onchange="applyMapTemplate(this.value)" aria-label="Load sample template">
            <option value="">Templates...</option>
            <option value="mixed">Mixed Multi-Tier Auto-Route</option>
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

      <div class="card">
        <div class="row" style="justify-content:space-between; margin-bottom:6px;">
          <h2 style="margin:0;">Visual Cross-Tier Pipeline Builder (No JSON Needed!)</h2>
          <div class="row" style="margin:0;">
            <label class="small" style="cursor:pointer; border:1px solid var(--border); border-radius:8px; padding:5px 9px;">
              Import .json <input type="file" accept=".json" style="display:none" onchange="importPipeJsonFile(this)" />
            </label>
            <button class="small" onclick="downloadPipeJson()">Export .json</button>
            <button class="small ghost" id="btn-toggle-pipe-json" onclick="togglePipeJsonDrawer()">Advanced JSON</button>
          </div>
        </div>
        <p class="hint" style="margin-top:0;">Build a multi-step workflow across <strong>Tier 1 (Termux)</strong> → <strong>Tier 2 (Debian Services)</strong> → <strong>Tier 3 (Docker)</strong>. Each step automatically gets the previous step's output (<code class="mono">$PHONECLUSTER_PREV_STDOUT</code>) and every live cluster service URL.</p>

        <div class="row">
          <label for="pipe-template">Starter Templates:</label>
          <select id="pipe-template" onchange="applyPipeTemplate(this.value)" aria-label="Cross-tier pipeline template">
            <option value="">Load a starter workflow...</option>
            <option value="tiers">Tier 1 Compute → Tier 2 Debian Services → Tier 3 Docker</option>
            <option value="mqtt">Tier 1 AI / Metric → Tier 2 Mosquitto MQTT Publish</option>
            <option value="mesh">Inspect Live Cross-Tier Service Mesh</option>
            <option value="health">Quick Check Across All Ready Phones</option>
          </select>
          <button class="small" onclick="addPipeStep()">+ Add Step</button>
          <button id="btn-run-pipe" class="primary" onclick="runCrossTierPipeline()">▶ Run Cross-Tier Pipeline</button>
        </div>

        <div id="pipe-flow" class="pipe-flow" aria-label="Visual pipeline flow preview"></div>
        <div id="pipe-steps-list"></div>

        <div id="pipe-json-drawer" style="display:none; margin-top:10px; padding-top:10px; border-top:1px dashed var(--border);">
          <div class="row" style="justify-content:space-between; margin-bottom:4px;">
            <label for="pipe-json" class="hint" style="margin:0;">Advanced Raw JSON (auto-synced with Visual Builder above):</label>
            <button class="small primary" onclick="applyPipeJsonFromDrawer()">Apply JSON to Visual Steps</button>
          </div>
          <textarea id="pipe-json" style="min-height:140px"></textarea>
        </div>

        <div id="pipe-summary-chips" class="chips"></div>
        <div id="pipe-results-cards" aria-live="polite"></div>
        <pre id="pipe-out" class="code" style="display:none"></pre>
      </div>
    </section>

    <!-- TAB 4: WORKLOADS & CROSS-TIER SERVICE MESH -->
    <section id="panel-workloads" class="panel" role="tabpanel" aria-labelledby="tab-workloads">
      <div class="card">
        <div class="row" style="justify-content:space-between; margin-bottom:8px;">
          <h2 style="margin:0;">Live Cross-Tier Service Mesh &amp; Auto-Discovery</h2>
          <button class="small primary" onclick="loadWorkloads()">Rescan Services</button>
        </div>
        <p class="hint" style="margin-top:0;">Every tier sees every other tier's live services automatically — zero hardcoded IPs. Click <strong>Test</strong> to verify live reachability from your Master, or register extra custom apps below.</p>

        <div id="mesh-tier-diagram" class="mesh-diagram" aria-label="Cross-tier architecture overview"></div>
        <div id="mesh-services-table" class="hint" style="margin-bottom:12px;">Scanning cluster services...</div>

        <div class="tier-edit-box" style="margin-bottom:14px;">
          <strong style="font-size:0.9rem;">+ Register Custom Service in Mesh (optional)</strong>
          <p class="hint" style="margin:2px 0 8px;">Add any extra app (e.g. <code class="mono">portainer</code>, <code class="mono">jellyfin</code>, <code class="mono">ollama</code>) — it is immediately injected as <code class="mono">$PHONECLUSTER_SVC_&lt;NAME&gt;</code> into every job and added to <code class="mono">.cluster</code> DNS hosts.</p>
          <div class="form-grid" style="margin-bottom:6px;">
            <div class="field"><label for="custom-svc-name">Service Name</label><input id="custom-svc-name" placeholder="portainer" /></div>
            <div class="field"><label for="custom-svc-url">Endpoint URL</label><input id="custom-svc-url" placeholder="http://192.168.1.206:9000" /></div>
          </div>
          <button class="small primary" onclick="addCustomService()">+ Add to Service Mesh</button>
        </div>

        <div class="col-grid">
          <div>
            <div class="row" style="justify-content:space-between; margin-bottom:4px;">
              <strong>Auto-Injected Cross-Tier Env Vars</strong>
              <button class="small" onclick="copyEl('mesh-env-code')">Copy .env</button>
            </div>
            <pre id="mesh-env-code" class="code">Loading...</pre>
          </div>
          <div>
            <div class="row" style="justify-content:space-between; margin-bottom:4px;">
              <strong>Friendly .cluster DNS Rewrites (AdGuard / /etc/hosts)</strong>
              <button class="small" onclick="copyEl('mesh-hosts-code')">Copy Hosts</button>
            </div>
            <pre id="mesh-hosts-code" class="code">Loading...</pre>
          </div>
        </div>
      </div>

      <div class="col-grid">
        <div class="card">
          <h2>Compiler PC (distcc)</h2>
          <p class="hint">Spread C/C++ builds across all healthy ARM64 cores.</p>
          <div class="row">
            <input id="distcc-cidr" type="text" value="192.168.1.0/24" aria-label="Allowed LAN subnet" style="width:165px" oninput="this.dataset.edited='user'" />
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
          <h2>Home Assistant, Ubuntu Touch &amp; Snap Docker</h2>
          <div id="wl-services" class="hint">Checking cluster services...</div>
          <div class="row" style="margin-top:8px;">
            <button class="small primary" onclick="workloadAction('docker-status')">Check Docker Containers</button>
            <button class="small" onclick="workloadAction('docker-swarm-init')">Init 2-Phone Docker Swarm</button>
          </div>
          <pre id="wl-action-out" class="code" style="display:none"></pre>
        </div>
      </div>
    </section>

    <!-- TAB 6: PHONES, SAFETY & DOCTOR -->
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
            <div class="field">
              <label for="add-tier">Tier / Role</label>
              <select id="add-tier">
                <option value="0" selected>Auto-Detect</option>
                <option value="1">Tier 1 · Termux Compute</option>
                <option value="2">Tier 2 · Debian 13 Services</option>
                <option value="3">Tier 3 · Docker (Ubuntu Touch / Linux)</option>
              </select>
            </div>
            <div class="field"><label for="add-pool">Pool Name</label><input id="add-pool" value="auto" placeholder="auto / compute / services / docker" /></div>
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

    <!-- TAB 5: NETWORK & PI GUARD (MASTER/WORKER HARDENING, ADGUARD HOME, WATCHGUARD PROXY) -->
    <section id="panel-network" class="panel" role="tabpanel" aria-labelledby="tab-network">
      <div class="card">
        <div class="row" style="justify-content:space-between; margin-bottom:6px;">
          <h2 style="margin:0;">Master &amp; Raspberry Pi Network Command Center</h2>
          <button class="small primary" onclick="loadNetworkCenter()">Refresh Audit</button>
        </div>
        <div id="net-hero-chips" class="chips" style="margin-bottom:10px;">
          <span class="pill neutral">Scanning Master controller &amp; cluster security posture...</span>
        </div>
        <p class="hint" style="margin:0 0 8px;">Pick a <strong>1-Click Security Profile</strong> below (can be switched back to Standard Home LAN anytime — no Docker required!):</p>
        <div class="profile-grid">
          <button type="button" class="profile-btn" onclick="applySecurityProfile('standard')">
            <strong>🟢 Standard Home LAN (Default)</strong>
            <span>Network Guard OFF, direct LAN peers, zero friction on a trusted home Wi-Fi.</span>
          </button>
          <button type="button" class="profile-btn" onclick="applySecurityProfile('airgap_workers')">
            <strong>🛡️ Air-Gapped Old Phones (Recommended)</strong>
            <span>Network Guard Allowlist ON, SSRF Private-IP Guard ON, Per-Phone Rate Quota ON. Ideal when router blocks worker WAN.</span>
          </button>
          <button type="button" class="profile-btn" onclick="applySecurityProfile('lockdown')">
            <strong>🔒 Maximum Lockdown (Strict)</strong>
            <span>Air-Gap Proxy (block_all), Dashboard Read-Auth Lock ON, Worker Master-IP Allowlist ON, 60 req/min cap.</span>
          </button>
        </div>
      </div>

      <div class="card">
        <div class="row" style="justify-content:space-between; margin-bottom:8px;">
          <h2 style="margin:0;">1. Per-Phone Attack Surface, Quarantine &amp; WAN Isolation</h2>
          <button class="small primary" onclick="checkWanIsolation()">Verify Router WAN Block on Workers</button>
        </div>
        <p class="hint" style="margin-top:0;">Inspect token isolation, Master-IP allowlist enforcement, unexpected open TCP ports (<code class="mono">/proc/net/tcp</code>), and instantly <strong>Quarantine</strong> any suspicious worker phone with 1 click.</p>
        <div id="net-nodes-table" class="hint">Loading cluster network posture...</div>
        <div id="gw-isolation-box" class="hint" style="margin-top:10px;"></div>
      </div>

      <div class="card">
        <div class="row" style="justify-content:space-between; margin-bottom:6px;">
          <h2 style="margin:0;">2. Optional Master Network Guard (Allowlist Proxy &amp; Traffic Log)</h2>
          <div class="row" style="margin:0;">
            <span id="gw-status-pill" class="pill neutral">OFF (Direct LAN)</span>
            <button class="small" onclick="loadGatewayStatus()">Refresh Log</button>
          </div>
        </div>
        <p class="hint" style="margin-top:0;"><strong>Optional (OFF by default):</strong> Block direct internet (WAN) on your router for old unrooted worker phones, then route approved package/API traffic through your updated Master phone or Raspberry Pi Zero 2 W.</p>
        <div class="chips" id="gw-stats-chips" style="margin-bottom:12px;"></div>

        <div class="form-grid">
          <div class="field">
            <label for="gw-enabled">Network Guard State</label>
            <select id="gw-enabled">
              <option value="false">OFF — Disabled (Default)</option>
              <option value="true">ON — Filter &amp; Monitor Worker WAN</option>
            </select>
          </div>
          <div class="field">
            <label for="gw-mode">Firewall Policy Mode</label>
            <select id="gw-mode">
              <option value="allowlist">Allowlist Only (Recommended · Default-Deny)</option>
              <option value="monitor">Monitor &amp; Log All (Discover domains first)</option>
              <option value="block_all">Strict Air-Gap (Block ALL WAN traffic)</option>
            </select>
          </div>
          <div class="field">
            <label for="gw-port">Proxy Port on Master</label>
            <input id="gw-port" type="number" min="1024" max="65535" value="8888" />
          </div>
          <div class="field">
            <label for="gw-rpm">Max Req/Min per Phone (0=off)</label>
            <input id="gw-rpm" type="number" min="0" max="10000" value="120" />
          </div>
        </div>

        <div class="row" style="margin-bottom:8px;">
          <label style="font-size:0.84rem; display:inline-flex; align-items:center; gap:5px;">
            <input id="gw-ssrf" type="checkbox" checked style="width:auto; padding:0;" /> Block private/LAN IPs via proxy (SSRF Guard)
          </label>
          <label style="font-size:0.84rem; display:inline-flex; align-items:center; gap:5px;">
            <input id="gw-inject" type="checkbox" checked style="width:auto; padding:0;" /> Auto-inject <code class="mono">HTTP_PROXY/NO_PROXY</code> into worker jobs
          </label>
        </div>

        <div class="row" style="margin-bottom:8px;">
          <span class="hint" style="margin:0;">1-Click Domain Presets:</span>
          <div id="gw-preset-chips" class="chips" style="margin:0;"></div>
        </div>

        <div class="col-grid" style="margin-bottom:10px;">
          <div>
            <label for="gw-allowed" class="hint">Allowed Domains (one per line · supports <code class="mono">*.domain.com</code>):</label>
            <textarea id="gw-allowed" style="min-height:95px;"></textarea>
          </div>
          <div>
            <label for="gw-blocked" class="hint">Always-Blocked Domains (one per line · overrides Monitor mode):</label>
            <textarea id="gw-blocked" style="min-height:95px;" placeholder="ads.example.com&#10;*.telemetry.vendor.com"></textarea>
          </div>
        </div>

        <div class="row">
          <button class="primary" onclick="saveGatewaySettings()">Save &amp; Apply Network Guard</button>
          <button class="small danger" onclick="clearGatewayLogs()">Clear Audit Log</button>
        </div>

        <h3 style="margin:12px 0 6px;">Live Worker Traffic Audit Log</h3>
        <div id="gw-events-table" class="hint">Network Guard is currently OFF.</div>
      </div>

      <div class="col-grid">
        <div class="card">
          <h2>3. Native AdGuard Home (No Docker!) &amp; Raspberry Pi Hub</h2>
          <p class="hint" style="margin-top:0;"><strong>No Docker required:</strong> AdGuard Home is a single ~12 MB native Go binary (~30–60 MB RAM) — runs effortlessly on a <strong>Raspberry Pi Zero 2 W</strong> or <strong>Tier 2 Debian 13</strong> phone.</p>
          <div id="net-adguard-status" class="check-item" style="margin-bottom:10px;">Checking AdGuard Home status...</div>
          <div class="row" style="justify-content:space-between; margin-bottom:4px;">
            <strong>1-Line Pi Zero 2 W + Native AdGuard Installer</strong>
            <button class="small" onclick="copyEl('net-ag-install')">Copy</button>
          </div>
          <pre id="net-ag-install" class="code">Loading...</pre>

          <div class="row" style="justify-content:space-between; margin:10px 0 4px;">
            <strong>AdGuard .cluster DNS Rewrites (YAML)</strong>
            <button class="small" onclick="copyEl('net-ag-rewrites')">Copy YAML</button>
          </div>
          <pre id="net-ag-rewrites" class="code" style="max-height:170px;">Loading...</pre>

          <div class="row" style="justify-content:space-between; margin:10px 0 4px;">
            <strong>Old-Phone Telemetry / Ad Block Rules</strong>
            <button class="small" onclick="copyEl('net-ag-blocks')">Copy Rules</button>
          </div>
          <pre id="net-ag-blocks" class="code" style="max-height:170px;">Loading...</pre>
        </div>

        <div class="card">
          <h2>4. Master &amp; Worker Hardening + Firewall Rules</h2>
          <div class="form-grid" style="margin-bottom:8px;">
            <div class="field"><label for="hard-subnet">Home LAN Subnet (CIDR)</label><input id="hard-subnet" placeholder="192.168.1.0/24" /></div>
            <div class="field"><label for="hard-ag-url">Custom AdGuard URL (optional)</label><input id="hard-ag-url" placeholder="http://192.168.1.200:3000" /></div>
          </div>
          <div class="row" style="margin-bottom:8px;">
            <label style="font-size:0.84rem; display:inline-flex; align-items:center; gap:5px;">
              <input id="hard-req-auth" type="checkbox" style="width:auto; padding:0;" /> Lock read-only Dashboard stats behind token (<code class="mono">dashboard_require_auth</code>)
            </label>
          </div>
          <div class="row" style="margin-bottom:8px;">
            <label style="font-size:0.84rem; display:inline-flex; align-items:center; gap:5px;">
              <input id="hard-src-ip" type="checkbox" style="width:auto; padding:0;" /> Workers accept HTTP <code class="mono">:8765</code> ONLY from Master IP (pushed live to online workers automatically)
            </label>
          </div>
          <div class="row" style="margin-bottom:10px;">
            <label style="font-size:0.84rem; display:inline-flex; align-items:center; gap:5px;">
              <input id="hard-signed-only" type="checkbox" style="width:auto; padding:0;" /> Strict replay-proof HMAC-SHA256 only on workers (disable legacy raw <code class="mono">Bearer</code> fallback)
            </label>
          </div>
          <div class="row">
            <button class="primary small" onclick="saveHardeningSettings()">Save &amp; Push Hardening</button>
            <button class="small" onclick="pushLivePolicyToWorkers()">📡 Push Live Policy to All Workers</button>
          </div>

          <h3 style="margin:12px 0 6px;">Hardening Checklist</h3>
          <div id="net-checks-list" class="hint" style="margin-bottom:12px;">Loading checklist...</div>

          <div class="row" style="justify-content:space-between; margin-bottom:4px;">
            <div class="row" style="margin:0;">
              <button id="btn-fw-router" class="small primary" onclick="setFwTab('router')">Router Checklist</button>
              <button id="btn-fw-nft" class="small" onclick="setFwTab('nft')">Pi / Debian nftables</button>
              <button id="btn-fw-ufw" class="small" onclick="setFwTab('ufw')">UFW</button>
            </div>
            <button class="small" onclick="copyEl('net-fw-code')">Copy Rules</button>
          </div>
          <pre id="net-fw-code" class="code" style="max-height:240px;">Loading...</pre>
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
let activePoolFilter = 'all';

function tierPillHtml(tier, pool) {
  const t = Number(tier || 1);
  const p = String(pool || 'compute').toUpperCase();
  const cls = t === 3 ? 'warn' : (t === 2 ? 'purple' : 'accent');
  return '<span class="pill ' + cls + '">T' + t + ' · ' + esc(p) + '</span>';
}

function setPoolFilter(filterKey) {
  activePoolFilter = filterKey || 'all';
  if (lastLive) {
    renderPoolStrip(lastLive.summary);
    renderNodesGrid(lastLive);
  }
}

function renderPoolStrip(summary) {
  const strip = document.getElementById('pool-strip');
  if (!strip) return;
  const pools = summary.pools || [];
  let html = '<button class="pool-chip' + (activePoolFilter === 'all' ? ' active' : '') + '" onclick="setPoolFilter(\'all\')">'
    + '<span class="pool-chip-title">All Phones <span class="pill ok">' + esc(summary.nodes_ready) + '/' + esc(summary.nodes_total) + '</span></span>'
    + '<span class="pool-chip-sub mono">' + esc(summary.total_cores) + ' cores · ' + ((summary.mem_total_mb || 0) / 1024).toFixed(1) + ' GB RAM</span>'
    + '</button>';
  for (const p of pools) {
    const key = 'pool:' + p.pool;
    const isAct = activePoolFilter === key;
    html += '<button class="pool-chip' + (isAct ? ' active' : '') + '" onclick="setPoolFilter(' + jsArg(key) + ')">'
      + '<span class="pool-chip-title">' + tierPillHtml(p.tier, p.pool)
      + ' <span class="mono">' + esc(p.nodes_ready) + '/' + esc(p.nodes_total) + '</span></span>'
      + '<span class="pool-chip-sub mono">' + esc(p.total_cores) + 'c · ' + ((p.mem_total_mb || 0) / 1024).toFixed(1) + ' GB · ' + esc((p.node_ids || []).join(', ')) + '</span>'
      + '</button>';
  }
  strip.innerHTML = html;
}

function openNodeTierEditor(nodeId) {
  if (!lastLive) return;
  const n = (lastLive.summary.nodes || []).find(x => x.id === nodeId);
  if (!n) return;
  const ed = document.getElementById('node-tier-editor');
  const cfgTier = Number(n.configured_tier || 0);
  const cfgPool = String(n.configured_pool || 'auto');
  ed.style.display = 'block';
  ed.innerHTML = '<div class="row" style="justify-content:space-between; margin-bottom:8px;">'
    + '<h3 style="margin:0;">Configure Tier &amp; Pool for <span class="mono">' + esc(n.id) + '</span> (' + esc(n.host) + ')</h3>'
    + '<button class="small ghost" onclick="closeNodeTierEditor()">✕ Close</button></div>'
    + '<div class="form-grid">'
    + '<div class="field"><label for="ed-tier">Tier Role</label><select id="ed-tier">'
    + '<option value="0"' + (cfgTier === 0 ? ' selected' : '') + '>Auto-Detect (from OS/Docker)</option>'
    + '<option value="1"' + (cfgTier === 1 ? ' selected' : '') + '>Tier 1 · Termux Compute &amp; AI</option>'
    + '<option value="2"' + (cfgTier === 2 ? ' selected' : '') + '>Tier 2 · Debian 13 Services</option>'
    + '<option value="3"' + (cfgTier === 3 ? ' selected' : '') + '>Tier 3 · Docker (Ubuntu Touch / Linux)</option>'
    + '</select></div>'
    + '<div class="field"><label for="ed-pool">Workload Pool</label>'
    + '<input id="ed-pool" value="' + esc(cfgPool) + '" placeholder="auto / compute / services / docker" /></div>'
    + '<div class="field"><label for="ed-conc">Max Parallel Jobs</label>'
    + '<input id="ed-conc" type="number" min="1" max="16" value="' + esc(n.max_concurrency || 2) + '" /></div>'
    + '</div>'
    + '<div class="row" style="margin:0;">'
    + '<button class="small primary" onclick="saveNodeTier(' + jsArg(n.id) + ')">Save Tier &amp; Pool</button>'
    + '<span class="hint" style="margin:0;">Effective now: ' + tierPillHtml(n.tier, n.pool) + '</span>'
    + '</div>';
}

function closeNodeTierEditor() {
  const ed = document.getElementById('node-tier-editor');
  if (ed) ed.style.display = 'none';
}

async function saveNodeTier(nodeId) {
  const tier = Number(document.getElementById('ed-tier').value || 0);
  const pool = document.getElementById('ed-pool').value.trim() || 'auto';
  const max_concurrency = Number(document.getElementById('ed-conc').value || 2);
  const data = await authPost('/api/nodes/update', { id: nodeId, tier, pool, max_concurrency });
  if (data.error) { showToast('Update failed: ' + data.error, 'bad'); return; }
  closeNodeTierEditor();
  const pushed = data.pushed ? (' · live-synced ' + data.pushed.ok_count + '/' + data.pushed.total) : '';
  showToast('Updated ' + nodeId + ' -> Tier ' + (tier || 'auto') + ' / pool ' + pool + pushed, 'ok');
  refreshLive();
}

// Interactive Web Terminal state
const termCwds = {};
const termHistory = [];
let termHistIdx = -1;
let termTranscript = [];
let activeTermJob = null;

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function jsArg(s) {
  return esc(JSON.stringify(String(s ?? '')).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029'));
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
    refreshAll();
    showToast('Token verified — Terminal & Cluster controls unlocked!', 'ok');
  } catch (e) {
    showToast('Could not reach Master to verify token: ' + e, 'bad');
  }
}
function clearToken(silent) {
  sessionStorage.removeItem('pc_token');
  localStorage.removeItem('pc_token');
  if (pairPollTimer) { clearInterval(pairPollTimer); pairPollTimer = null; }
  const pairBox = document.getElementById('pair-active-box');
  if (pairBox) pairBox.style.display = 'none';
  const btnClose = document.getElementById('btn-pair-close');
  if (btnClose) btnClose.style.display = 'none';
  const pinEl = document.getElementById('pair-pin');
  if (pinEl) pinEl.textContent = '------';
  const wbEl = document.getElementById('set-webhook');
  if (wbEl) wbEl.value = '';
  updateAuthBadge();
  if (!silent) {
    refreshAll();
    showToast('Controls locked (Read-Only Mode).', 'neutral');
  }
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
  const tabs = ['overview', 'terminal', 'jobs', 'workloads', 'network', 'setup'];
  for (const t of tabs) {
    const btn = document.getElementById('tab-' + t);
    const panel = document.getElementById('panel-' + t);
    const active = t === name;
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
    panel.classList.toggle('active', active);
  }
  if (name === 'terminal') document.getElementById('term-input').focus();
  if (name === 'jobs') renderPipeBuilder();
  if (name === 'workloads') loadWorkloads();
  if (name === 'network') loadNetworkCenter();
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
  const numPct = Number(pct);
  const clamped = Math.max(0, Math.min(100, Number.isFinite(numPct) ? numPct : 0));
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

let lastTaskCommands = [];

function rerunTask(idx) {
  const item = lastTaskCommands[idx];
  if (!item) return;
  openNodeTerminal(item.node_id, item.command);
}

function renderTasksBoard(live) {
  const wrap = document.getElementById('tasks-board-wrap');
  if (boardView === 'procs') {
    const procs = [];
    for (const n of (live.summary.nodes || [])) {
      if (!n.online) continue;
      const rawProcs = (n.health || {}).top_processes;
      const procList = Array.isArray(rawProcs) ? rawProcs : [];
      for (const p of procList) {
        if (p && typeof p === 'object') procs.push({ node_id: n.id, ...p });
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
  lastTaskCommands = rows.map(r => ({ node_id: r.node_id, command: r.command }));
  wrap.innerHTML = '<div style="overflow-x:auto;"><table><thead><tr><th>Phone</th><th>Job ID</th><th>Status</th><th>Duration</th><th>Command</th><th>Action</th></tr></thead><tbody>'
    + rows.map((r, idx) => {
      const tone = r.state === 'OK' ? 'ok' : (r.state === 'RUNNING' ? 'warn' : 'bad');
      const btn = r.active
        ? '<button class="small danger" onclick="cancelJob(' + jsArg(r.node_id) + ',' + jsArg(r.job_id) + ')">Cancel</button>'
        : '<button class="small" onclick="rerunTask(' + idx + ')">Re-run</button>';
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

let liveInFlight = false;

async function refreshLive() {
  if (liveInFlight) return;
  liveInFlight = true;
  try {
    const r = await apiFetch('/api/live');
    if (r.status === 401) {
      if (getToken()) {
        clearToken(true);
        const pill = document.getElementById('auth-pill');
        if (pill) { pill.textContent = '✕ Token Rejected'; pill.className = 'pill bad'; }
      }
      document.getElementById('last-updated').textContent = 'Dashboard locked — paste auth_token above and click Unlock.';
      const grid = document.getElementById('nodes-grid');
      if (grid) grid.innerHTML = '<div class="card"><p class="hint">Dashboard locked — paste auth_token above and click Unlock.</p></div>';
      const tasks = document.getElementById('tasks-board-wrap');
      if (tasks) tasks.innerHTML = '<p class="hint">Dashboard locked — paste auth_token above and click Unlock.</p>';
      return;
    }
    if (!r.ok) {
      document.getElementById('last-updated').textContent = 'Dashboard error (HTTP ' + r.status + ')';
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
    const clusterCpuNum = Number(d.cluster_cpu_pct ?? 0);
    document.getElementById('k-cpu').textContent = (Number.isFinite(clusterCpuNum) ? clusterCpuNum : 0).toFixed(1) + '%';
    document.getElementById('k-cores').textContent = d.total_cores + ' cores';
    document.getElementById('spark-cpu').innerHTML = renderSparklineSvg(
      cHist.map(p => p.cpu_pct), 100, '#58a6ff', 'rgba(88,166,255,0.18)'
    );

    const memTot = Number(d.mem_total_mb || 0);
    const memAvail = Number(d.mem_available_mb || 0);
    const usedGb = (Math.max(0, memTot - memAvail) / 1024).toFixed(2);
    const totGb = (Math.max(0, memTot) / 1024).toFixed(2);
    document.getElementById('k-ram').textContent = usedGb + ' / ' + totGb + ' GB';
    const clusterRamNum = Number(d.cluster_ram_pct ?? 0);
    document.getElementById('k-ram-pct').textContent = (Number.isFinite(clusterRamNum) ? clusterRamNum : 0).toFixed(0) + '%';
    document.getElementById('spark-ram').innerHTML = renderSparklineSvg(
      cHist.map(p => p.ram_pct), 100, '#a371f7', 'rgba(163,113,247,0.18)'
    );

    const peakT = d.max_temp_c;
    const hasPeakT = typeof peakT === 'number' && Number.isFinite(peakT);
    document.getElementById('k-temp').textContent = hasPeakT ? peakT.toFixed(1) + ' °C' : 'N/A';
    const tp = document.getElementById('k-temp-pill');
    if (!hasPeakT) { tp.textContent = 'N/A'; tp.className = 'pill neutral'; }
    else if (peakT >= maxTemp) { tp.textContent = '⚠ HOT'; tp.className = 'pill bad'; }
    else if (peakT >= resTemp) { tp.textContent = 'Warm'; tp.className = 'pill warn'; }
    else { tp.textContent = '✓ Cool'; tp.className = 'pill ok'; }
    document.getElementById('spark-temp').innerHTML = renderSparklineSvg(
      cHist.map(p => p.max_temp_c ?? 0), 55, (hasPeakT && peakT >= maxTemp) ? '#f85149' : '#3fb950',
      (hasPeakT && peakT >= maxTemp) ? 'rgba(248,81,73,0.18)' : 'rgba(63,185,80,0.16)'
    );

    document.getElementById('k-tasks').textContent = String(d.total_active_jobs || 0);
    document.getElementById('k-tasks-sub').textContent = d.total_active_jobs ? 'Active across cluster' : 'Idle · ready for work';
    document.getElementById('k-net').textContent = '↓' + (d.total_net_rx_kbps ?? 0) + ' ↑' + (d.total_net_tx_kbps ?? 0) + ' KB/s';

    document.getElementById('k-nodes').textContent = d.nodes_ready + ' / ' + d.nodes_total;
    document.getElementById('k-ping').textContent = (d.avg_latency_ms ?? 0) + ' ms';
    document.getElementById('k-nodes-sub').textContent = d.nodes_online + ' online · ' + d.nodes_ready + ' ready';

    // Update Terminal Target Dropdown dynamically only when options change and select is not open/focused
    const termSel = document.getElementById('term-target');
    const prevTerm = termSel.value;
    const dynPools = [];
    const seenPools = new Set(['compute', 'services', 'docker']);
    for (const p of (d.pools || [])) {
      if (p.pool && !seenPools.has(p.pool)) {
        seenPools.add(p.pool);
        dynPools.push(p.pool);
      }
    }
    const termSig = JSON.stringify([dynPools, (d.nodes || []).map(n => [n.id, n.role, n.tier || 1, n.pool || 'compute', n.host])]);
    if (termSel.dataset.sig !== termSig && document.activeElement !== termSel) {
      let termOpts = '<option value="auto">⚡ Auto-Route by Workload (Smart Tier)</option>'
        + '<option value="tier:1">Tier 1 · Termux Compute &amp; AI</option>'
        + '<option value="tier:2">Tier 2 · Debian 13 Services</option>'
        + '<option value="tier:3">Tier 3 · Docker &amp; Containers</option>'
        + '<option value="best">Best Coolest Phone (Any Tier)</option>'
        + '<option value="all">ALL READY PHONES (Broadcast)</option>';
      for (const pname of dynPools) {
        termOpts += '<option value="pool:' + esc(pname) + '">Pool: ' + esc(pname) + '</option>';
      }
      termSel.innerHTML = termOpts;
      for (const n of (d.nodes || [])) {
        const opt = document.createElement('option');
        opt.value = n.id;
        opt.textContent = n.id + ' (' + n.role + ' · T' + (n.tier || 1) + ':' + (n.pool || 'compute') + ' · ' + n.host + ')';
        termSel.appendChild(opt);
      }
      termSel.dataset.sig = termSig;
      if (Array.from(termSel.options).some(o => o.value === prevTerm)) {
        termSel.value = prevTerm;
      } else {
        onTermTargetChange();
      }
    }

    renderPoolStrip(d);
    renderNodesGrid(live);

    const batWarnings = [];
    for (const n of d.nodes) {
      const h = n.health || {};
      if (n.online && h.battery_pct != null && h.battery_pct >= batHigh && (h.battery_status === 'CHARGING' || h.battery_status === 'FULL')) {
        batWarnings.push(n.id + ' is at ' + h.battery_pct + '% (' + h.battery_status + ')');
      }
    }

    const banner = document.getElementById('battery-banner');
    if (batWarnings.length) {
      document.getElementById('battery-banner-text').textContent = batWarnings.join('; ')
        + '. Avoid leaving Li-Po batteries pinned at 100% 24/7 (configure a smart-plug webhook in Tab 6 or use rooted ACC).';
      banner.classList.remove('hidden');
    } else {
      banner.classList.add('hidden');
    }

    renderTasksBoard(live);
  } catch (e) {
    document.getElementById('last-updated').textContent = 'Connection error: ' + e;
  } finally {
    liveInFlight = false;
  }
}

function renderNodesGrid(live) {
    const d = live.summary;
    const hist = live.history || { cluster: [], nodes: {} };
    const safety = d.safety || {};
    const maxTemp = safety.max_temp_c ?? 40;
    const resTemp = safety.resume_temp_c ?? 37;
    const batHigh = safety.battery_high_pct ?? 60;

    // Render Shared Multi-Device btop Cards (respecting active Tier/Pool filter)
    const grid = document.getElementById('nodes-grid');
    grid.innerHTML = '';

    const visibleNodes = (d.nodes || []).filter(n => {
      if (activePoolFilter === 'all') return true;
      if (activePoolFilter.startsWith('pool:')) return ('pool:' + (n.pool || 'compute')) === activePoolFilter;
      return true;
    });

    if (!visibleNodes.length) {
      grid.innerHTML = '<div class="card"><p class="hint">No phones in this pool yet. Click "All Phones" above or assign a phone via Tier / Pool.</p></div>';
      return;
    }

    for (const n of visibleNodes) {
      const h = n.health || {};
      const nHist = (hist.nodes && hist.nodes[n.id]) ? hist.nodes[n.id] : [];
      let badge = '<span class="pill bad">✕ OFFLINE</span>';
      let cardCls = 'node-card offline';
      if (n.online && n.quarantined) {
        badge = '<span class="pill bad">🔒 QUARANTINED</span>';
        cardCls = 'node-card offline';
      } else if (n.online && n.ready_for_jobs) {
        const actNum = Number.isFinite(Number(h.active_jobs)) ? Number(h.active_jobs) : 0;
        const maxNum = Number.isFinite(Number(h.max_concurrency)) && Number(h.max_concurrency) > 0
          ? Number(h.max_concurrency) : (Number(n.max_concurrency) || 2);
        badge = '<span class="pill ok">✓ READY (' + esc(actNum) + '/' + esc(maxNum) + ')</span>';
        cardCls = 'node-card';
      } else if (n.online) {
        const reasons = (Array.isArray(h.not_ready_reasons) && h.not_ready_reasons.length) ? h.not_ready_reasons : ['PAUSED'];
        badge = '<span class="pill warn">⚠ ' + esc(reasons.join(', ')) + '</span>';
        cardCls = 'node-card hot';
      }

      let bodyHtml = '';
      if (!n.online) {
        bodyHtml = '<p class="hint">Unreachable: ' + esc(n.error || 'connection refused') + '</p>';
      } else {
        const rawCores = Number(h.cpu_cores);
        const cores = (Number.isFinite(rawCores) && rawCores > 0) ? Math.floor(rawCores) : 1;
        const rawCpu = h.cpu_pct != null ? Number(h.cpu_pct) : Math.min(100, ((Number(h.load_1m) || 0) / cores) * 100);
        const cpuPct = Number.isFinite(rawCpu) ? rawCpu : 0;
        const perCore = Array.isArray(h.per_core_pct) ? h.per_core_pct : [];
        const coreCols = perCore.length
          ? '<div class="core-grid" title="Per-core CPU utilization">'
            + perCore.slice(0, 16).map(p => {
                const pNum = Number.isFinite(Number(p)) ? Number(p) : 0;
                const c = pNum >= 85 ? 'bad' : (pNum >= 60 ? 'warn' : '');
                return '<div class="core-col"><span class="' + c + '" style="height:' + Math.max(6, Math.min(100, Math.round(pNum))) + '%"></span></div>';
              }).join('')
            + '</div>'
          : '';

        bodyHtml += '<div class="cpu-btop-box">'
          + '<div class="cpu-btop-top"><span><strong>CPU</strong> ' + esc(cores) + ' cores · load ' + esc(h.load_1m ?? 0) + '</span>'
          + '<span class="mono"><strong>' + cpuPct.toFixed(1) + '%</strong></span></div>'
          + '<div class="spark-wrap" style="height:28px;margin-top:0">'
          + renderSparklineSvg(nHist.map(p => p.cpu_pct), 100, '#58a6ff', 'rgba(88,166,255,0.18)')
          + '</div>' + coreCols + '</div>';

        const memTotNum = Number.isFinite(Number(h.mem_total_mb)) ? Math.max(0, Number(h.mem_total_mb)) : 0;
        const memAvailNum = Number.isFinite(Number(h.mem_available_mb)) ? Math.max(0, Number(h.mem_available_mb)) : 0;
        const ramUsedMb = Math.max(0, memTotNum - memAvailNum);
        const ramUsedPct = memTotNum ? Math.min(100, (ramUsedMb / memTotNum) * 100) : 0;
        const tempNum = Number(h.temp_c);
        const hasTemp = h.temp_c != null && Number.isFinite(tempNum);
        const tempTone = !hasTemp ? '' : (tempNum >= maxTemp ? 'bad' : (tempNum >= resTemp ? 'warn' : 'ok'));
        const bat = h.battery_pct;
        const batTone = bat == null ? '' : (bat >= batHigh && (h.battery_status === 'CHARGING' || h.battery_status === 'FULL') ? 'warn' : (bat < 20 ? 'bad' : 'ok'));

        bodyHtml += metricBar('Memory', ramUsedMb + ' / ' + memTotNum + ' MB (' + ramUsedPct.toFixed(0) + '%)', ramUsedPct, ramUsedPct > 85 ? 'bad' : '');
        bodyHtml += metricBar('Temperature', hasTemp ? tempNum.toFixed(1) + ' °C' : 'N/A', hasTemp ? (tempNum / 50) * 100 : 0, tempTone);
        bodyHtml += metricBar('Battery', bat != null ? bat + '% · ' + (h.battery_status || '?') : 'N/A', bat ?? 0, batTone);

        // Inline running tasks badge
        const activeJobs = Array.isArray(h.active_job_list) ? h.active_job_list.filter(j => j && typeof j === 'object') : [];
        if (activeJobs.length) {
          bodyHtml += '<div class="chips">' + activeJobs.map(j =>
            '<span class="pill accent mono">▶ ' + esc(String(j.command ?? '').slice(0, 26)) + ' (' + esc(j.running_sec) + 's)</span>'
          ).join('') + '</div>';
        }

        // Top processes mini-panel
        const procs = Array.isArray(h.top_processes) ? h.top_processes.filter(p => p && typeof p === 'object') : [];
        if (procs.length) {
          bodyHtml += '<div class="mini-procs"><div class="mini-procs-head"><span>Top Processes</span><span>CPU / MEM</span></div>'
            + procs.slice(0, 4).map(p =>
                '<div class="proc-line mono"><span>' + esc(p.name) + ' <small style="color:var(--muted)">#' + esc(p.pid) + '</small></span>'
                + '<span>' + esc(p.cpu_pct) + '% / ' + esc(p.mem_pct) + '%</span></div>'
              ).join('')
            + '</div>';
        }

        const svcsObj = (h.services && typeof h.services === 'object' && !Array.isArray(h.services)) ? h.services : {};
        const svcs = Object.entries(svcsObj).filter(([, v]) => v).map(([k]) => k.split('_')[0]);
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
        + '<button class="small primary" onclick="openNodeTerminal(' + jsArg(n.id) + ')">Terminal</button>'
        + '<button class="small" onclick="openNodeTierEditor(' + jsArg(n.id) + ')">Tier / Pool</button>';
      if (n.role !== 'master') {
        actionsHtml += '<button class="small danger" onclick="removeNode(' + jsArg(n.id) + ')">Remove</button>';
      }
      actionsHtml += '</div>';

      const card = document.createElement('article');
      card.className = cardCls;
      card.innerHTML = '<div><div class="node-head">'
        + '<div><div class="node-title">' + esc(n.id) + ' ' + rolePill + ' ' + tierPillHtml(n.tier, n.pool) + '</div>'
        + '<div class="node-meta mono">' + esc(n.host) + '</div></div>'
        + badge + '</div>' + bodyHtml + '</div>' + actionsHtml;
      grid.appendChild(card);
    }
}

/* ---------------- Interactive Multi-Node Web Terminal ---------------- */
function shortCwd(cwd) {
  if (!cwd) return '~';
  const s = String(cwd);
  if (s === '/') return '/';
  return s.replace(/\/+$/, '').split('/').slice(-1)[0] || '~';
}

function onTermTargetChange() {
  const target = document.getElementById('term-target').value;
  const cwd = termCwds[target] || '~';
  document.getElementById('term-cwd-pill').textContent = cwd;
  document.getElementById('term-prompt').textContent = target + ':' + shortCwd(cwd) + ' $';
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
  const blobUrl = URL.createObjectURL(blob);
  a.href = blobUrl;
  a.download = 'phonecluster-terminal-' + Date.now() + '.log';
  a.click();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}

async function submitTerminalCommand() {
  if (activeTermJob) return;
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
  const promptText = target + ':' + shortCwd(cwd) + ' $ ' + cmd;
  entry.innerHTML = '<div class="term-cmd-line">' + esc(promptText) + '<span class="term-meta">running...</span></div>';
  screen.appendChild(entry);
  screen.scrollTop = screen.scrollHeight;

  const jobId = 'wterm-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
  activeTermJob = { node_id: target, job_id: jobId };
  document.getElementById('btn-term-run').disabled = true;
  const isDynamicTarget = (target === 'auto' || target === 'all' || target === 'best' || target.startsWith('tier:') || target.startsWith('pool:'));
  document.getElementById('btn-term-cancel').disabled = isDynamicTarget;

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
      if (!isDynamicTarget && r.cwd) {
        termCwds[target] = r.cwd;
        onTermTargetChange();
      }
      const tierStr = r.node_tier ? (' · T' + r.node_tier + ':' + (r.node_pool || 'compute')) : '';
      const whyStr = r.routing_reason ? (' — ' + r.routing_reason) : '';
      const meta = '[' + r.node_id + tierStr + ' · ' + (r.ok ? 'OK' : 'rc=' + r.returncode) + ' · ' + r.duration_sec + 's' + whyStr + ']';
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
  if (name === 'mixed') {
    document.getElementById('map-mode').value = 'commands';
    document.getElementById('map-target').value = 'auto';
    toggleMapMode();
    document.getElementById('map-commands').value =
      'python3 -c "import os; print(\'compute on\', os.environ.get(\'PHONECLUSTER_NODE_ID\'), \'mqtt=\', os.environ.get(\'PHONECLUSTER_MQTT_HOST\', \'none\'))"\n'
      + 'echo "Parallel compute task on $PHONECLUSTER_NODE_ID (HA=${PHONECLUSTER_HOMEASSISTANT_URL:-none})"\n'
      + 'docker ps --format "{{.Names}}: {{.Status}}" 2>&1 || true';
  } else if (name === 'primes') {
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
  document.getElementById('map-template').value = '';
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
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    try {
      const parsed = JSON.parse(text);
      if (!r.ok && (!parsed || typeof parsed !== 'object' || !parsed.error)) {
        return Object.assign(typeof parsed === 'object' && parsed ? parsed : {}, {
          error: 'Request failed (HTTP ' + r.status + ')',
        });
      }
      return parsed;
    } catch (_e) {
      return { error: 'Unexpected server response (HTTP ' + r.status + ')' };
    }
  } catch (e) {
    return { error: 'Could not reach Master: ' + (e && e.message ? e.message : String(e)) };
  }
}

function toggleMapMode() {
  const mode = document.getElementById('map-mode').value;
  document.getElementById('map-commands-box').style.display = mode === 'commands' ? 'block' : 'none';
  document.getElementById('map-script-box').style.display = mode === 'script' ? 'block' : 'none';
}

async function runParallelMap() {
  const mode = document.getElementById('map-mode').value;
  const target = document.getElementById('map-target').value || 'auto';
  const btn = document.getElementById('btn-run-map');
  const out = document.getElementById('map-out');
  const chips = document.getElementById('map-summary-chips');
  btn.disabled = true;
  chips.innerHTML = '';
  out.textContent = 'Dispatching parallel batch (target: ' + target + ')...';
  try {
    let payload;
    if (mode === 'commands') {
      const commands = document.getElementById('map-commands').value.split('\n').map(s => s.trim()).filter(Boolean);
      payload = { mode: 'commands', target, commands };
    } else {
      const script_content = document.getElementById('map-script').value;
      const interpreter = document.getElementById('map-interp').value;
      const args_lines = document.getElementById('map-args').value.split('\n').map(s => s.trim()).filter(Boolean);
      payload = { mode: 'script', target, script_content, interpreter, args_lines };
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
      const tierStr = r.node_tier ? (' [T' + r.node_tier + ':' + (r.node_pool || 'compute') + ']') : '';
      txt += '[' + (r.ok ? 'OK' : 'FAIL') + '] ' + r.node_id + tierStr + ' (' + r.duration_sec + 's) ' + r.label + '\n  '
        + (r.stdout || r.stderr || r.error || '').trim().replace(/\n/g, '\n  ') + '\n';
    }
    out.textContent = txt || 'Done.';
    showToast('Batch complete: ' + data.ok_count + ' succeeded, ' + data.fail_count + ' failed', data.fail_count ? 'warn' : 'ok');
    refreshLive();
  } finally {
    btn.disabled = false;
  }
}

let pipeSteps = [
  {
    name: 'Compute on Tier 1',
    target: 'tier:1',
    command: 'python3 -c "import os, platform; print(os.environ.get(\'PHONECLUSTER_NODE_ID\'), platform.machine())"',
    continue_on_error: false
  },
  {
    name: 'Relay via Service Mesh',
    target: 'auto',
    command: 'echo "From $PHONECLUSTER_PREV_NODE (T$PHONECLUSTER_PREV_TIER): $PHONECLUSTER_PREV_STDOUT | MQTT=${PHONECLUSTER_MQTT_URL:-not-running}"',
    continue_on_error: false
  }
];
let lastPipeResults = [];

function pipeTargetLabel(t) {
  if (t === 'auto') return '⚡ Auto';
  if (t === 'tier:1') return 'T1 · Compute';
  if (t === 'tier:2') return 'T2 · Services';
  if (t === 'tier:3') return 'T3 · Docker';
  if (t === 'all') return 'All Ready';
  return t || 'auto';
}

function syncPipeJsonFromBuilder() {
  const el = document.getElementById('pipe-json');
  if (el) el.value = JSON.stringify(pipeSteps, null, 2);
}

function getAvailableMeshVars(stepIdx) {
  const vars = [];
  if (stepIdx > 0) {
    vars.push({ label: '+ Prev Output', val: '$PHONECLUSTER_PREV_STDOUT' });
    vars.push({ label: '+ Prev Node', val: '$PHONECLUSTER_PREV_NODE' });
  }
  if (stepIdx > 1) {
    vars.push({ label: '+ Step 1 Output', val: '$PHONECLUSTER_STEP_1_STDOUT' });
  }
  const seen = new Set();
  const svcs = (lastLive && lastLive.summary && lastLive.summary.services_registry) ? lastLive.summary.services_registry : [];
  const svcToVar = {
    mqtt: { label: '+ MQTT Host', val: '$PHONECLUSTER_MQTT_HOST' },
    homeassistant: { label: '+ Home Assistant URL', val: '$PHONECLUSTER_HOMEASSISTANT_URL' },
    adguard: { label: '+ AdGuard URL', val: '$PHONECLUSTER_ADGUARD_URL' },
    llama_api: { label: '+ Local AI URL', val: '$PHONECLUSTER_LLAMA_API_URL' },
    redis: { label: '+ Redis URL', val: '$PHONECLUSTER_REDIS_URL' },
    postgres: { label: '+ Postgres Host', val: '$PHONECLUSTER_POSTGRES_HOST' }
  };
  for (const s of svcs) {
    if (svcToVar[s.name] && !seen.has(s.name)) {
      seen.add(s.name);
      vars.push(svcToVar[s.name]);
    } else if (s.source === 'config' && !seen.has('cfg:' + s.name)) {
      seen.add('cfg:' + s.name);
      const k = String(s.name).toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_|_$/g, '');
      if (k) vars.push({ label: '+ ' + s.name, val: '$PHONECLUSTER_SVC_' + k });
    }
  }
  if (!seen.has('mqtt')) vars.push({ label: '+ MQTT URL', val: '${PHONECLUSTER_MQTT_URL:-none}' });
  vars.push({ label: '+ Node ID', val: '$PHONECLUSTER_NODE_ID' });
  return vars;
}

function renderPipeFlow() {
  const flow = document.getElementById('pipe-flow');
  if (!flow) return;
  if (!pipeSteps.length) {
    flow.innerHTML = '<span class="hint" style="margin:0;">No steps yet — click "+ Add Step" or choose a Starter Template.</span>';
    return;
  }
  flow.innerHTML = pipeSteps.map((st, idx) => {
    const res = lastPipeResults.find(r => r.step_index === idx + 1);
    const cls = res ? (res.ok ? ' ok' : ' bad') : '';
    const icon = res ? (res.ok ? '✓ ' : '✕ ') : '';
    const targetBadge = res && res.node_id && res.node_id !== 'none'
      ? (res.node_id + (res.node_tier ? ' · T' + res.node_tier : ''))
      : pipeTargetLabel(st.target);
    const arrow = idx < pipeSteps.length - 1 ? '<span class="pipe-flow-arrow" aria-hidden="true">→</span>' : '';
    return '<span class="pipe-flow-node' + cls + '">'
      + '<span>' + icon + (idx + 1) + '. ' + esc(st.name || ('Step ' + (idx + 1))) + '</span>'
      + '<span class="pill neutral">' + esc(targetBadge) + '</span>'
      + '</span>' + arrow;
  }).join('');
}

function renderPipeBuilder() {
  renderPipeFlow();
  syncPipeJsonFromBuilder();
  const list = document.getElementById('pipe-steps-list');
  if (!list) return;
  const nodes = (lastLive && lastLive.summary && lastLive.summary.nodes) ? lastLive.summary.nodes : [];
  const baseTargets = [
    ['auto', '⚡ Auto-Route by Workload (Smart Tier)'],
    ['tier:1', 'Tier 1 · Termux Compute & AI'],
    ['tier:2', 'Tier 2 · Debian 13 Services'],
    ['tier:3', 'Tier 3 · Docker & Containers'],
    ['all', 'ALL READY PHONES (Broadcast)']
  ];
  for (const n of nodes) {
    baseTargets.push([n.id, 'Phone: ' + n.id + ' (T' + (n.tier || 1) + ':' + (n.pool || 'compute') + ')']);
  }

  list.innerHTML = pipeSteps.map((st, idx) => {
    const optsHtml = baseTargets.map(([val, lbl]) =>
      '<option value="' + esc(val) + '"' + (st.target === val ? ' selected' : '') + '>' + esc(lbl) + '</option>'
    ).join('');
    const customOpt = baseTargets.some(([v]) => v === st.target)
      ? ''
      : '<option value="' + esc(st.target) + '" selected>' + esc(st.target) + '</option>';
    const varsHtml = getAvailableMeshVars(idx).map(v =>
      '<button type="button" class="var-chip" onclick="insertPipeVar(' + idx + ',' + jsArg(v.val) + ')">' + esc(v.label) + '</button>'
    ).join('');
    return '<div class="step-card">'
      + '<div class="step-card-head">'
      + '<div class="row" style="margin:0; flex:1; min-width:220px;">'
      + '<span class="step-num">' + (idx + 1) + '</span>'
      + '<input type="text" aria-label="Step ' + (idx + 1) + ' name" value="' + esc(st.name || '') + '" placeholder="Step name..." style="flex:1; min-width:150px;" oninput="updatePipeStep(' + idx + ',\'name\',this.value)" />'
      + '<select aria-label="Step ' + (idx + 1) + ' target" onchange="updatePipeStep(' + idx + ',\'target\',this.value)">' + optsHtml + customOpt + '</select>'
      + '</div>'
      + '<div class="row" style="margin:0;">'
      + '<button type="button" class="small" title="Move up" onclick="movePipeStep(' + idx + ',-1)"' + (idx === 0 ? ' disabled' : '') + '>↑</button>'
      + '<button type="button" class="small" title="Move down" onclick="movePipeStep(' + idx + ',1)"' + (idx === pipeSteps.length - 1 ? ' disabled' : '') + '>↓</button>'
      + '<button type="button" class="small" title="Duplicate step" onclick="dupPipeStep(' + idx + ')">Copy</button>'
      + '<button type="button" class="small danger" title="Remove step" onclick="removePipeStep(' + idx + ')"' + (pipeSteps.length <= 1 ? ' disabled' : '') + '>✕</button>'
      + '</div></div>'
      + '<textarea id="pipe-cmd-' + idx + '" aria-label="Step ' + (idx + 1) + ' command" style="min-height:58px;" placeholder="Enter shell command (plain text — no JSON escaping needed)..." oninput="updatePipeStep(' + idx + ',\'command\',this.value)">' + esc(st.command || '') + '</textarea>'
      + '<div class="row" style="justify-content:space-between; margin:6px 0 0;">'
      + '<div class="chips" style="margin:0;">' + varsHtml + '</div>'
      + '<label style="font-size:0.8rem; color:var(--muted); display:inline-flex; align-items:center; gap:5px;">'
      + '<input type="checkbox" style="width:auto; padding:0;" ' + (st.continue_on_error ? 'checked ' : '') + 'onchange="updatePipeStep(' + idx + ',\'continue_on_error\',this.checked)" /> Continue if this step fails</label>'
      + '</div></div>';
  }).join('');
}

function updatePipeStep(idx, field, val) {
  if (!pipeSteps[idx]) return;
  pipeSteps[idx][field] = val;
  syncPipeJsonFromBuilder();
  if (field === 'name' || field === 'target') renderPipeFlow();
}

function insertPipeVar(idx, varToken) {
  const ta = document.getElementById('pipe-cmd-' + idx);
  if (!ta || !pipeSteps[idx]) return;
  const start = ta.selectionStart ?? ta.value.length;
  const end = ta.selectionEnd ?? ta.value.length;
  const cur = ta.value;
  ta.value = cur.slice(0, start) + varToken + cur.slice(end);
  pipeSteps[idx].command = ta.value;
  syncPipeJsonFromBuilder();
  ta.focus();
  ta.setSelectionRange(start + varToken.length, start + varToken.length);
}

function addPipeStep() {
  const nextIdx = pipeSteps.length + 1;
  const defaultTarget = nextIdx === 2 ? 'tier:2' : (nextIdx === 3 ? 'tier:3' : 'auto');
  pipeSteps.push({
    name: 'Step ' + nextIdx,
    target: defaultTarget,
    command: 'echo "Step ' + nextIdx + ' on $PHONECLUSTER_NODE_ID got: $PHONECLUSTER_PREV_STDOUT"',
    continue_on_error: false
  });
  lastPipeResults = [];
  renderPipeBuilder();
}

function movePipeStep(idx, delta) {
  const targetIdx = idx + delta;
  if (targetIdx < 0 || targetIdx >= pipeSteps.length) return;
  const tmp = pipeSteps[idx];
  pipeSteps[idx] = pipeSteps[targetIdx];
  pipeSteps[targetIdx] = tmp;
  lastPipeResults = [];
  renderPipeBuilder();
}

function dupPipeStep(idx) {
  if (!pipeSteps[idx]) return;
  const copy = Object.assign({}, pipeSteps[idx], { name: (pipeSteps[idx].name || 'Step') + ' (copy)' });
  pipeSteps.splice(idx + 1, 0, copy);
  lastPipeResults = [];
  renderPipeBuilder();
}

function removePipeStep(idx) {
  if (pipeSteps.length <= 1) return;
  pipeSteps.splice(idx, 1);
  lastPipeResults = [];
  renderPipeBuilder();
}

function togglePipeJsonDrawer() {
  const box = document.getElementById('pipe-json-drawer');
  const open = box.style.display === 'none';
  box.style.display = open ? 'block' : 'none';
  document.getElementById('btn-toggle-pipe-json').textContent = open ? 'Hide Advanced JSON' : 'Advanced JSON';
  if (open) syncPipeJsonFromBuilder();
}

function applyPipeJsonFromDrawer() {
  try {
    const parsed = JSON.parse(document.getElementById('pipe-json').value);
    const arr = Array.isArray(parsed) ? parsed : (parsed && Array.isArray(parsed.steps) ? parsed.steps : null);
    if (!arr || !arr.length || !arr.every(s => s && typeof s === 'object' && !Array.isArray(s))) {
      throw new Error('JSON must be a non-empty array of step objects (or {"steps": [...]}).');
    }
    pipeSteps = arr.map((s, i) => Object.assign({}, s, {
      name: String(s.name || ('Step ' + (i + 1))),
      target: String(s.target || 'auto'),
      command: String(s.command || ''),
      continue_on_error: Boolean(s.continue_on_error)
    }));
    lastPipeResults = [];
    renderPipeBuilder();
    showToast('Applied ' + pipeSteps.length + ' step(s) to Visual Builder!', 'ok');
  } catch (e) {
    showToast('Invalid Pipeline JSON: ' + e.message, 'bad');
  }
}

function importPipeJsonFile(input) {
  const file = input.files && input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    document.getElementById('pipe-json').value = String(reader.result || '');
    applyPipeJsonFromDrawer();
  };
  reader.readAsText(file);
  input.value = '';
}

function downloadPipeJson() {
  const payload = { name: 'PhoneCluster Cross-Tier Pipeline', steps: pipeSteps };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  const blobUrl = URL.createObjectURL(blob);
  a.href = blobUrl;
  a.download = 'phonecluster-pipeline-' + Date.now() + '.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}

function applyPipeTemplate(name) {
  if (!name) return;
  const templates = {
    tiers: [
      {
        name: 'Compute on Tier 1 (Termux)',
        target: 'tier:1',
        command: 'python3 -c "import os, platform; print(\'result=42 from\', os.environ.get(\'PHONECLUSTER_NODE_ID\'), platform.machine())"',
        continue_on_error: false
      },
      {
        name: 'Relay via Tier 2 (Debian Services)',
        target: 'tier:2',
        command: 'echo "Tier 2 ($PHONECLUSTER_NODE_ID) received: $PHONECLUSTER_PREV_STDOUT | MQTT=${PHONECLUSTER_MQTT_URL:-none}"',
        continue_on_error: false
      },
      {
        name: 'Check Containers on Tier 3 (Docker)',
        target: 'tier:3',
        command: 'echo "Tier 3 ($PHONECLUSTER_NODE_ID) saw Step 1: $PHONECLUSTER_STEP_1_STDOUT" && docker ps --format "{{.Names}}: {{.Status}}" 2>&1 || true',
        continue_on_error: false
      }
    ],
    mqtt: [
      {
        name: 'Generate Metric on Tier 1',
        target: 'tier:1',
        command: 'python3 -c "import json, os; print(json.dumps({\'node\': os.environ.get(\'PHONECLUSTER_NODE_ID\'), \'status\': \'ok\'}))"',
        continue_on_error: false
      },
      {
        name: 'Publish via Tier 2 Mosquitto',
        target: 'tier:2',
        command: 'if command -v mosquitto_pub >/dev/null 2>&1 && [ -n "$PHONECLUSTER_MQTT_HOST" ]; then mosquitto_pub -h "$PHONECLUSTER_MQTT_HOST" -p "${PHONECLUSTER_MQTT_PORT:-1883}" -t phonecluster/events -m "$PHONECLUSTER_PREV_STDOUT" && echo "Published to $PHONECLUSTER_MQTT_URL"; else echo "Dry-run payload -> $PHONECLUSTER_PREV_STDOUT (start Mosquitto on Tier 2 to publish)"; fi',
        continue_on_error: false
      }
    ],
    mesh: [
      {
        name: 'Inspect Live Cross-Tier Mesh',
        target: 'auto',
        command: 'env | grep ^PHONECLUSTER_ | sort',
        continue_on_error: false
      }
    ],
    health: [
      {
        name: 'Check Uptime Across All Phones',
        target: 'all',
        command: 'echo "$PHONECLUSTER_NODE_ID ($(uname -m)): $(uptime)"',
        continue_on_error: false
      }
    ]
  };
  if (templates[name]) {
    pipeSteps = templates[name].map(s => Object.assign({}, s));
    lastPipeResults = [];
    renderPipeBuilder();
    showToast('Loaded workflow template: ' + name, 'ok');
  }
  document.getElementById('pipe-template').value = '';
}

async function runCrossTierPipeline() {
  const btn = document.getElementById('btn-run-pipe');
  const cardsBox = document.getElementById('pipe-results-cards');
  const out = document.getElementById('pipe-out');
  const chips = document.getElementById('pipe-summary-chips');
  if (!pipeSteps.length) {
    showToast('Add at least one step to the pipeline first.', 'warn');
    return;
  }
  btn.disabled = true;
  chips.innerHTML = '';
  cardsBox.innerHTML = '<p class="hint">Running ' + pipeSteps.length + ' cross-tier step(s)...</p>';
  try {
    const data = await authPost('/api/pipeline', { steps: pipeSteps });
    if (data.error) {
      cardsBox.innerHTML = '<div class="pipe-res-card bad"><strong>Error:</strong> ' + esc(data.error) + '</div>';
      showToast(data.error, 'bad');
      return;
    }
    lastPipeResults = data.results || [];
    renderPipeFlow();
    chips.innerHTML = '<span class="pill ' + (data.ok ? 'ok' : 'bad') + '">' + (data.ok ? '✓ PIPELINE OK' : '✕ FAILED') + '</span>'
      + '<span class="pill neutral mono">' + esc(data.duration_sec) + 's</span>'
      + '<span class="pill neutral">' + esc(data.steps_completed) + '/' + esc(data.steps_total) + ' steps</span>';

    cardsBox.innerHTML = lastPipeResults.map(r => {
      const tp = r.node_tier ? tierPillHtml(r.node_tier, r.node_pool) : '<span class="pill neutral">none</span>';
      const body = (r.stdout || r.stderr || r.error || '(no output)').trim();
      return '<div class="pipe-res-card ' + (r.ok ? 'ok' : 'bad') + '">'
        + '<div class="row" style="justify-content:space-between; margin-bottom:4px;">'
        + '<div><strong>Step ' + esc(r.step_index) + ': ' + esc(r.name) + '</strong> '
        + '<span class="pill ' + (r.ok ? 'ok' : 'bad') + '">' + (r.ok ? '✓ OK' : '✕ FAIL') + '</span> '
        + '<span class="pill neutral mono">' + esc(r.node_id) + '</span> ' + tp + '</div>'
        + '<span class="hint mono" style="margin:0;">' + esc(r.duration_sec) + 's</span></div>'
        + (r.routing_reason ? '<div class="hint" style="margin:0 0 6px;">Route: ' + esc(r.routing_reason) + '</div>' : '')
        + '<pre class="code" style="margin:0; max-height:180px;">' + esc(body) + '</pre>'
        + '</div>';
    }).join('');

    out.textContent = JSON.stringify(data, null, 2);
    showToast('Pipeline finished: ' + data.steps_completed + '/' + data.steps_total + ' steps', data.ok ? 'ok' : 'warn');
    refreshLive();
  } finally {
    btn.disabled = false;
  }
}

function downloadLastMapJson() {
  if (!lastMapData) return;
  const blob = new Blob([JSON.stringify(lastMapData, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  const blobUrl = URL.createObjectURL(blob);
  a.href = blobUrl;
  a.download = 'phonecluster-batch-' + Date.now() + '.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}

async function loadWorkloads() {
  try {
    const r = await apiFetch('/api/workloads');
    if (r.status === 401) {
      document.getElementById('wl-distcc').textContent = '# Dashboard locked — paste auth_token above and click Unlock.';
      return;
    }
    if (!r.ok) {
      document.getElementById('wl-distcc').textContent = '# Error loading workloads (HTTP ' + r.status + ')';
      return;
    }
    const d = await r.json();
    const cidrInput = document.getElementById('distcc-cidr');
    if (cidrInput && d.lan_subnet && cidrInput.dataset.edited !== 'user') {
      cidrInput.value = d.lan_subnet;
      cidrInput.dataset.edited = 'auto';
    }
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
        + d.home_assistant_urls.map(u => /^https?:\/\//i.test(String(u || ''))
            ? '<a href="' + esc(u) + '" target="_blank" rel="noopener noreferrer" style="color:var(--accent)">' + esc(u) + '</a>'
            : '<span class="mono">' + esc(u) + '</span>'
          ).join(', ')
        + '</p>';
    } else {
      svcHtml += '<p><strong>Home Assistant:</strong> Not detected on port 8123. Best deployed on Tier 2 (Rooted Debian 13 chroot) or Tier 3 (Docker).</p>';
    }
    svcHtml += '<p><strong>Docker-ready nodes:</strong> ' + (d.docker_nodes.length ? esc(d.docker_nodes.join(', ')) : 'None yet (install Snap Docker on Ubuntu Touch or Tier 3 Linux)') + '</p>';
    if (Array.isArray(d.docker_snap_nodes) && d.docker_snap_nodes.length) {
      svcHtml += '<p class="hint" style="margin-top:4px;">Snap Docker detected on <strong>' + esc(d.docker_snap_nodes.join(', ')) + '</strong> — keep bind-mount volumes under <code class="mono">~/phonecluster/docker-data</code> ($HOME).</p>';
    }
    if (Array.isArray(d.docker_socket_issues) && d.docker_socket_issues.length) {
      svcHtml += '<p class="hint" style="color:var(--warn); margin-top:4px;">⚠ Docker socket permission needed on <strong>' + esc(d.docker_socket_issues.join(', ')) + '</strong> — run <code class="mono">bash scripts/06_ubuntu_touch_node_setup.sh</code>.</p>';
    }
    document.getElementById('wl-services').innerHTML = svcHtml;

    // Cross-Tier Live Service Mesh Diagram + Table + .env + .cluster DNS hosts
    const mesh = d.services_info || {};
    const svcs = mesh.services || [];
    const pools = mesh.pools || [];
    const diagBox = document.getElementById('mesh-tier-diagram');
    if (diagBox) {
      const tiersMeta = [
        { t: 1, title: 'Tier 1 · Termux Compute', desc: 'Parallel scripts, Local LLMs, distcc' },
        { t: 2, title: 'Tier 2 · Debian 13 Services', desc: 'Mosquitto MQTT, AdGuard DNS, glibc apps' },
        { t: 3, title: 'Tier 3 · Docker & Containers', desc: 'Home Assistant, Docker stacks, K3s' }
      ];
      diagBox.innerHTML = tiersMeta.map(tm => {
        const matchedPools = pools.filter(p => Number(p.tier) === tm.t);
        const readyN = matchedPools.reduce((a, p) => a + (p.nodes_ready || 0), 0);
        const totalN = matchedPools.reduce((a, p) => a + (p.nodes_total || 0), 0);
        const tierSvcs = svcs.filter(s => Number(s.tier) === tm.t);
        const svcPills = tierSvcs.length
          ? tierSvcs.map(s => '<span class="pill ok">' + esc(s.name) + '</span>').join(' ')
          : '<span class="hint" style="margin:0;">No active services detected</span>';
        return '<div class="mesh-tier-box">'
          + '<div class="row" style="justify-content:space-between; margin-bottom:4px;">'
          + '<strong>' + esc(tm.title) + '</strong>'
          + '<span class="pill ' + (readyN ? 'ok' : 'neutral') + '">' + readyN + '/' + totalN + ' ready</span></div>'
          + '<div class="hint" style="margin:0 0 8px;">' + esc(tm.desc) + '</div>'
          + '<div class="chips" style="margin:0;">' + svcPills + '</div></div>';
      }).join('');
    }
    const meshBox = document.getElementById('mesh-services-table');
    if (meshBox) {
      if (!svcs.length) {
        meshBox.innerHTML = '<p class="hint">No cross-tier services detected yet (start Mosquitto, AdGuard Home, Home Assistant, llama.cpp, distcc, or Docker on any tier, or register a Custom Service below).</p>';
      } else {
        meshBox.innerHTML = '<div style="overflow-x:auto;"><table><thead><tr><th>Service</th><th>Phone</th><th>Tier / Pool</th><th>Endpoint</th><th>Status</th><th>Action</th></tr></thead><tbody>'
          + svcs.map((s, idx) => {
              const link = /^https?:\/\//i.test(String(s.url || ''))
                ? '<a href="' + esc(s.url) + '" target="_blank" rel="noopener noreferrer" style="color:var(--accent)">' + esc(s.url) + '</a>'
                : '<span class="mono">' + esc(s.url) + '</span>';
              const tp = s.tier ? tierPillHtml(s.tier, s.pool) : '<span class="pill neutral">custom</span>';
              let actions = '';
              if (s.host && Number(s.port) > 0) {
                actions += '<button class="small" id="probe-btn-' + idx + '" onclick="probeService(' + idx + ',' + jsArg(s.name) + ',' + jsArg(s.host) + ',' + Number(s.port) + ')">Test</button> ';
              }
              if (s.source === 'config') {
                actions += '<button class="small danger" onclick="removeCustomService(' + jsArg(s.name) + ')">Remove</button>';
              }
              const stCls = s.loopback_only ? 'warn' : (s.ready ? 'ok' : 'warn');
              const stLbl = s.loopback_only ? '⚠ Localhost-Only' : (s.ready ? '✓ Live' : 'Warm/Busy');
              return '<tr><td><strong>' + esc(s.name) + '</strong></td><td class="mono">' + esc(s.node_id) + '</td>'
                + '<td>' + tp + '</td><td>' + link + '</td>'
                + '<td><span id="probe-st-' + idx + '" class="pill ' + stCls + '">' + stLbl + '</span></td>'
                + '<td>' + (actions || '<span class="hint">-</span>') + '</td></tr>';
            }).join('')
          + '</tbody></table></div>';
      }
    }
    const envObj = mesh.env || {};
    const envEl = document.getElementById('mesh-env-code');
    if (envEl) {
      const shQuote = v => "'" + String(v ?? '').replace(/'/g, "'\\''") + "'";
      const lines = Object.entries(envObj).sort((a, b) => a[0].localeCompare(b[0])).map(([k, v]) => 'export ' + k + '=' + shQuote(v));
      envEl.textContent = lines.join('\n') || '# No cluster env variables yet.';
    }
    const hostsEl = document.getElementById('mesh-hosts-code');
    if (hostsEl) {
      hostsEl.textContent = mesh.dns_hosts || '# No hosts generated yet.';
    }
  } catch (e) {
    document.getElementById('wl-distcc').textContent = 'Error loading workloads: ' + e;
  }
}

async function probeService(idx, name, host, port) {
  const btn = document.getElementById('probe-btn-' + idx);
  const st = document.getElementById('probe-st-' + idx);
  if (btn) btn.disabled = true;
  try {
    const data = await authPost('/api/services/probe', { name, host, port });
    if (data.error) { showToast('Probe error: ' + data.error, 'bad'); return; }
    if (data.reachable) {
      if (st) { st.className = 'pill ok'; st.textContent = '✓ ' + data.latency_ms + ' ms'; }
      showToast('✓ ' + name + ' (' + host + ':' + port + ') reachable in ' + data.latency_ms + ' ms!', 'ok');
    } else {
      if (st) { st.className = 'pill bad'; st.textContent = '✕ Unreachable'; }
      showToast('✕ ' + name + ' unreachable: ' + (data.error || 'timeout'), 'bad');
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function addCustomService() {
  const name = document.getElementById('custom-svc-name').value.trim();
  const url = document.getElementById('custom-svc-url').value.trim();
  if (!name || !url) { showToast('Enter both a service name and endpoint URL.', 'warn'); return; }
  const data = await authPost('/api/services/custom', { name, url });
  if (data.error) { showToast('Could not save service: ' + data.error, 'bad'); return; }
  document.getElementById('custom-svc-name').value = '';
  document.getElementById('custom-svc-url').value = '';
  showToast('Registered "' + data.name + '" in Cross-Tier Service Mesh!', 'ok');
  loadWorkloads();
  refreshLive();
}

async function removeCustomService(name) {
  const data = await authPost('/api/services/custom/remove', { name });
  if (data.error) { showToast('Remove failed: ' + data.error, 'bad'); return; }
  showToast('Removed "' + name + '" from Service Mesh.', 'warn');
  loadWorkloads();
  refreshLive();
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
let lastPairedKey = null;

function _pairedEntryKey(recents) {
  if (!Array.isArray(recents) || !recents.length) return '';
  const latest = recents[recents.length - 1];
  if (!latest || typeof latest !== 'object') return '';
  return String(latest.id || '') + '|' + String(latest.host || '') + '|' + String(latest.paired_at || recents.length);
}

function _checkNewlyPaired(recents) {
  const key = _pairedEntryKey(recents);
  if (lastPairedKey === null) {
    lastPairedKey = key;
    return;
  }
  if (key && key !== lastPairedKey) {
    const latest = recents[recents.length - 1];
    lastPairedKey = key;
    showToast('✓ Securely paired ' + latest.id + ' (' + latest.host + ') with its own unique token!', 'ok');
    refreshLive();
  }
}

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

  if (!pairPollTimer) {
    pairPollTimer = setInterval(pollPairingStatus, 1500);
  }

  _checkNewlyPaired(st.recent_paired || []);
}

async function openPairingWindow() {
  const max_devices = Number(document.getElementById('pair-slots').value || 1);
  const data = await authPost('/api/pair/open', { ttl_sec: 120, max_devices });
  if (data.error) { showToast('Could not open pairing: ' + data.error, 'bad'); return; }
  lastPairedKey = _pairedEntryKey(data.recent_paired || []);
  renderPairingState(data);
  showToast('Pairing window open for 2 minutes! Run `pc join` on your new phone.', 'ok');
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
    _checkNewlyPaired(st.recent_paired || []);
    renderPairingState(st);
  } catch (e) {}
}

async function scanLan() {
  const box = document.getElementById('discover-list');
  box.innerHTML = 'Scanning Wi-Fi (2 seconds)...';
  try {
    const r = await apiFetch('/api/discover');
    if (r.status === 401) {
      box.innerHTML = '<p class="hint">Dashboard locked — paste auth_token above and click Unlock.</p>';
      return;
    }
    if (!r.ok) {
      box.innerHTML = '<p class="hint">Discovery failed (HTTP ' + r.status + ').</p>';
      return;
    }
    const d = await r.json();
    if (!d.discovered || !d.discovered.length) {
      box.innerHTML = '<p class="hint">No phones answered UDP discovery on port 8766. Make sure workers are running on the same Wi-Fi, or use Manual Add below.</p>';
      return;
    }
    box.innerHTML = d.discovered.map(item => {
      const btn = item.already_configured
        ? '<span class="pill ok">✓ Already in Cluster</span>'
        : '<button class="small primary" onclick="addDiscoveredNode(' + jsArg(item.host) + ',' + Number(item.worker_port) + ',' + Number(item.ssh_port) + ',' + jsArg(item.ssh_user) + ')">+ Add to Cluster</button>';
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
  const tier = Number(document.getElementById('add-tier').value || 0);
  const pool = document.getElementById('add-pool').value.trim() || 'auto';
  if (!host) { showToast('Enter an IP address first.', 'warn'); return; }
  const data = await authPost('/api/nodes/add', { host, ssh_user, ssh_port, max_concurrency, tier, pool });
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
  const rawMaxT = document.getElementById('set-max-temp').value.trim();
  const rawResT = document.getElementById('set-res-temp').value.trim();
  const rawLowB = document.getElementById('set-bat-low').value.trim();
  const rawHighB = document.getElementById('set-bat-high').value.trim();
  if (!rawMaxT || !rawResT || !rawLowB || !rawHighB) {
    showToast('Please fill in all temperature and battery threshold fields.', 'warn');
    return;
  }
  const payload = {
    max_temp_c: Number(rawMaxT),
    resume_temp_c: Number(rawResT),
    battery_low_pct: Number(rawLowB),
    battery_high_pct: Number(rawHighB),
    battery_webhook_url: document.getElementById('set-webhook').value.trim(),
  };
  const data = await authPost('/api/settings', payload);
  if (data.error) { showToast('Save failed: ' + data.error, 'bad'); return; }
  const pushed = data.pushed ? (' (live-synced to ' + data.pushed.ok_count + '/' + data.pushed.total + ' phone(s))') : '';
  showToast('Safety settings saved!' + pushed, 'ok');
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
    if (r.status === 401) {
      box.innerHTML = '<p class="hint">Dashboard locked — paste auth_token above and click Unlock.</p>';
      return;
    }
    if (!r.ok) {
      box.innerHTML = '<p class="hint">Doctor failed (HTTP ' + r.status + ').</p>';
      return;
    }
    const d = await r.json();
    const icons = { ok: '✓ OK', warn: '⚠ WARN', fail: '✕ FAIL' };
    const cls = { ok: 'ok', warn: 'warn', fail: 'bad' };
    box.innerHTML = (d.checks || []).map(c =>
      '<div class="check-item">'
      + '<span class="pill ' + (cls[c.status] || 'neutral') + '">' + (icons[c.status] || esc(c.status)) + '</span> '
      + '<strong>' + esc(c.name) + '</strong>: ' + esc(c.detail)
      + (c.fix_hint ? '<div class="hint">Fix: ' + esc(c.fix_hint) + '</div>' : '')
      + '</div>'
    ).join('');
  } catch (e) {
    box.textContent = 'Doctor failed: ' + e;
  }
}

let gwPresetsCache = {};
let lastNetAudit = null;
let activeFwTab = 'router';

function setFwTab(tab) {
  activeFwTab = tab;
  document.getElementById('btn-fw-router').className = 'small' + (tab === 'router' ? ' primary' : '');
  document.getElementById('btn-fw-nft').className = 'small' + (tab === 'nft' ? ' primary' : '');
  document.getElementById('btn-fw-ufw').className = 'small' + (tab === 'ufw' ? ' primary' : '');
  const codeEl = document.getElementById('net-fw-code');
  if (!codeEl || !lastNetAudit) return;
  const fg = lastNetAudit.firewall_guides || {};
  if (tab === 'nft') codeEl.textContent = fg.nftables || '';
  else if (tab === 'ufw') codeEl.textContent = fg.ufw || '';
  else codeEl.textContent = fg.router_checklist || '';
}

async function loadNetworkCenter() {
  await Promise.all([loadGatewayStatus(), loadNetworkAudit()]);
}

async function loadNetworkAudit() {
  try {
    const r = await apiFetch('/api/network/audit');
    if (r.status === 401) {
      const msg = '<p class="hint">Dashboard locked — paste auth_token above and click Unlock.</p>';
      const nb = document.getElementById('net-nodes-table');
      const cb = document.getElementById('net-checks-list');
      if (nb) nb.innerHTML = msg;
      if (cb) cb.innerHTML = msg;
      return;
    }
    if (!r.ok) return;
    const d = await r.json();
    lastNetAudit = d;
    const hi = d.host_info || {};
    const scoreTone = d.score >= 80 ? 'ok' : (d.score >= 55 ? 'accent' : 'warn');
    const boardIcon = hi.is_raspberry_pi ? '🥧 ' : (hi.is_termux ? '📱 ' : '🐧 ');
    document.getElementById('net-hero-chips').innerHTML =
      '<span class="pill ' + scoreTone + '">Hardening Score: ' + esc(d.score) + '/100 (' + esc(d.grade) + ')</span>'
      + '<span class="pill purple">' + boardIcon + esc(hi.friendly_name || 'Master') + '</span>'
      + '<span class="pill neutral mono">Master IP: ' + esc(hi.master_host || hi.lan_ip || '-') + '</span>'
      + '<span class="pill neutral mono">LAN: ' + esc(hi.lan_subnet || '-') + '</span>'
      + (d.adguard_url
          ? '<span class="pill ok">✓ AdGuard Home Live (' + esc(d.adguard_node) + ')</span>'
          : '<span class="pill neutral">AdGuard Home: Not Detected (No Docker Needed)</span>');

    // Per-phone attack surface & quarantine table
    const nodes = d.nodes || [];
    const nBox = document.getElementById('net-nodes-table');
    if (!nodes.length) {
      nBox.innerHTML = '<p class="hint">No phones configured yet.</p>';
    } else {
      nBox.innerHTML = '<div style="overflow-x:auto;"><table><thead><tr><th>Phone</th><th>Tier</th><th>Token Isolation</th><th>Master-IP Lock</th><th>Open Ports</th><th>Proxy Traffic</th><th>Action</th></tr></thead><tbody>'
        + nodes.map(n => {
            const tokPill = n.token_isolated ? '<span class="pill ok">✓ Unique</span>' : '<span class="pill warn">⚠ Shared</span>';
            const ipPill = n.role === 'master'
              ? '<span class="pill purple">MASTER</span>'
              : (n.source_ip_allowlist_active ? '<span class="pill ok">✓ Enforced</span>' : '<span class="pill neutral">Open LAN</span>');
            const portCell = !n.online
              ? '<span class="pill bad">Offline</span>'
              : (n.unexpected_ports && n.unexpected_ports.length
                  ? '<span class="pill warn">⚠ ' + esc(n.unexpected_ports.join(', ')) + '</span>'
                  : '<span class="pill ok">✓ Clean (' + (n.exposed_ports || []).length + ')</span>');
            const traf = n.role === 'master'
              ? '<span class="hint">Gateway</span>'
              : '<span class="mono">' + esc(n.proxy_allowed || 0) + ' ok / ' + esc(n.proxy_blocked || 0) + ' blk</span>';
            let act = '<span class="hint">-</span>';
            if (n.role !== 'master') {
              act = n.quarantined
                ? '<button class="small primary" onclick="toggleQuarantine(' + jsArg(n.id) + ', false)">✓ Unblock</button>'
                : '<button class="small danger" onclick="toggleQuarantine(' + jsArg(n.id) + ', true)">🔒 Quarantine</button>';
            }
            const nameBadge = n.quarantined
              ? '<strong>' + esc(n.id) + '</strong> <span class="pill bad">QUARANTINED</span>'
              : '<strong>' + esc(n.id) + '</strong>';
            return '<tr><td>' + nameBadge + '<div class="hint mono" style="margin:0;">' + esc(n.host) + '</div></td>'
              + '<td>' + tierPillHtml(n.tier, n.pool) + '</td><td>' + tokPill + '</td><td>' + ipPill + '</td>'
              + '<td>' + portCell + '</td><td>' + traf + '</td><td>' + act + '</td></tr>';
          }).join('')
        + '</tbody></table></div>';
    }

    // AdGuard & Pi hub
    const agBox = document.getElementById('net-adguard-status');
    if (d.adguard_url) {
      const agLink = /^https?:\/\//i.test(String(d.adguard_url || ''))
        ? '<a href="' + esc(d.adguard_url) + '" target="_blank" rel="noopener noreferrer" style="color:var(--accent)">' + esc(d.adguard_url) + '</a>'
        : '<span class="mono">' + esc(d.adguard_url) + '</span>';
      agBox.innerHTML = '<span class="pill ok">✓ Active</span> AdGuard Home reachable on <strong>' + esc(d.adguard_node) + '</strong>: ' + agLink;
    } else if (hi.is_termux) {
      agBox.innerHTML = '<span class="pill warn">Unrooted Termux Master</span> Port 53 requires root — run native AdGuard Home on a <strong>Raspberry Pi Zero 2 W</strong> Master or a <strong>Tier 2 Debian 13</strong> phone (no Docker needed!).';
    } else {
      agBox.innerHTML = '<span class="pill neutral">Not Installed</span> Your controller (' + esc(hi.friendly_name) + ') can run <strong>native AdGuard Home</strong> directly without Docker using the 1-line installer below!';
    }
    const sn = d.adguard_snippets || {};
    document.getElementById('net-ag-install').textContent = sn.native_install_cmd || '';
    document.getElementById('net-ag-rewrites').textContent = sn.rewrites_yaml || '';
    document.getElementById('net-ag-blocks').textContent = sn.worker_block_rules || '';

    // Hardening controls & checklist
    const hd = d.hardening || {};
    document.getElementById('hard-subnet').value = hd.lan_subnet || '';
    document.getElementById('hard-ag-url').value = hd.adguard_url || '';
    document.getElementById('hard-req-auth').checked = Boolean(hd.dashboard_require_auth);
    document.getElementById('hard-src-ip').checked = Boolean(hd.enforce_worker_source_ip);
    const signedEl = document.getElementById('hard-signed-only');
    if (signedEl) signedEl.checked = Boolean(hd.require_signed_requests);

    const cBox = document.getElementById('net-checks-list');
    const cIcons = { ok: '✓ OK', warn: '⚠ WARN', info: 'ℹ TIP' };
    const cCls = { ok: 'ok', warn: 'warn', info: 'neutral' };
    cBox.innerHTML = (d.checks || []).map(c =>
      '<div class="check-item"><span class="pill ' + (cCls[c.status] || 'neutral') + '">' + (cIcons[c.status] || esc(c.status)) + '</span> '
      + '<strong>' + esc(c.name) + '</strong>: ' + esc(c.detail)
      + (c.fix ? '<div class="hint">' + esc(c.fix) + '</div>' : '')
      + '</div>'
    ).join('');

    setFwTab(activeFwTab);
  } catch (e) {}
}

async function applySecurityProfile(profile) {
  const data = await authPost('/api/network/profile', { profile });
  if (data.error) { showToast('Profile error: ' + data.error, 'bad'); return; }
  const pushed = data.pushed ? (' · synced live to ' + data.pushed.ok_count + '/' + data.pushed.total + ' phone(s)') : '';
  showToast('Applied profile: ' + data.description + pushed, 'ok');
  loadNetworkCenter();
}

async function toggleQuarantine(nodeId, quarantine) {
  const data = await authPost('/api/gateway/quarantine', { node_id: nodeId, quarantine });
  if (data.error) { showToast('Quarantine failed: ' + data.error, 'bad'); return; }
  showToast(quarantine ? ('🔒 Quarantined ' + nodeId + ' (proxy, jobs & service mesh isolated!)') : ('✓ Unblocked ' + nodeId), quarantine ? 'warn' : 'ok');
  loadNetworkCenter();
  refreshLive();
}

async function saveHardeningSettings() {
  const payload = {
    dashboard_require_auth: document.getElementById('hard-req-auth').checked,
    enforce_worker_source_ip: document.getElementById('hard-src-ip').checked,
    require_signed_requests: Boolean(document.getElementById('hard-signed-only')?.checked),
    lan_subnet: document.getElementById('hard-subnet').value.trim(),
    adguard_url: document.getElementById('hard-ag-url').value.trim(),
  };
  const data = await authPost('/api/network/hardening', payload);
  if (data.error) { showToast('Save failed: ' + data.error, 'bad'); return; }
  const pushed = data.pushed ? (' Synced live to ' + data.pushed.ok_count + '/' + data.pushed.total + ' phone(s)!') : '';
  showToast('Network hardening saved!' + pushed, 'ok');
  loadNetworkCenter();
}

async function pushLivePolicyToWorkers() {
  const data = await authPost('/api/network/push-config', {});
  if (data.error) { showToast('Policy push failed: ' + data.error, 'bad'); return; }
  showToast('Pushed live policy (safety, concurrency & IP lock) to ' + data.ok_count + '/' + data.total + ' online phone(s)!', data.ok_count === data.total ? 'ok' : 'warn');
  loadNetworkCenter();
  refreshLive();
}

async function loadGatewayStatus() {
  try {
    const r = await apiFetch('/api/gateway/status');
    if (r.status === 401) {
      const tbl = document.getElementById('gw-events-table');
      if (tbl) tbl.innerHTML = '<p class="hint">Dashboard locked — paste auth_token above and click Unlock.</p>';
      return;
    }
    if (!r.ok) return;
    const d = await r.json();
    gwPresetsCache = d.presets || {};
    const pill = document.getElementById('gw-status-pill');
    if (d.enabled && d.running) {
      pill.className = 'pill ok';
      pill.textContent = '✓ ON · :' + d.port + ' (' + d.mode + ')';
    } else if (d.enabled) {
      pill.className = 'pill bad';
      pill.textContent = '✕ Error: ' + (d.last_error || 'stopped');
    } else {
      pill.className = 'pill neutral';
      pill.textContent = 'OFF (Direct LAN)';
    }

    document.getElementById('gw-enabled').value = d.enabled ? 'true' : 'false';
    document.getElementById('gw-mode').value = d.mode || 'allowlist';
    document.getElementById('gw-port').value = d.port || 8888;
    document.getElementById('gw-rpm').value = d.max_requests_per_min_per_node ?? 120;
    document.getElementById('gw-ssrf').checked = Boolean(d.block_private_ips);
    document.getElementById('gw-inject').checked = Boolean(d.inject_proxy_env);
    document.getElementById('gw-allowed').value = (d.allowed_domains || []).join('\n');
    document.getElementById('gw-blocked').value = (d.blocked_domains || []).join('\n');

    const pBox = document.getElementById('gw-preset-chips');
    if (pBox) {
      pBox.innerHTML = Object.entries(gwPresetsCache).map(([key, p]) =>
        '<button type="button" class="var-chip" onclick="addGatewayPreset(' + jsArg(key) + ')">+ ' + esc(p.label) + '</button>'
      ).join('');
    }

    const st = d.stats || {};
    const kb = ((st.bytes_total || 0) / 1024).toFixed(1);
    document.getElementById('gw-stats-chips').innerHTML =
      '<span class="pill ok">Allowed: ' + esc(st.total_allowed || 0) + '</span>'
      + '<span class="pill ' + ((st.total_blocked || 0) ? 'warn' : 'neutral') + '">Blocked: ' + esc(st.total_blocked || 0) + '</span>'
      + '<span class="pill ' + ((st.auth_failures || 0) ? 'bad' : 'neutral') + '">Auth Denied: ' + esc(st.auth_failures || 0) + '</span>'
      + '<span class="pill neutral mono">Relayed: ' + esc(kb) + ' KB</span>';

    const tbl = document.getElementById('gw-events-table');
    const evs = d.events || [];
    if (!evs.length) {
      tbl.innerHTML = d.enabled
        ? '<p class="hint">No worker proxy traffic logged yet. Any worker job making HTTP/HTTPS requests will appear here live.</p>'
        : '<p class="hint">Network Guard is currently OFF (default). Turn it ON above if you want Master to filter &amp; monitor worker internet traffic.</p>';
    } else {
      tbl.innerHTML = '<div style="overflow-x:auto;"><table><thead><tr><th>Time</th><th>Phone</th><th>Destination</th><th>Action</th><th>Reason</th><th>Data</th><th>Quick Fix</th></tr></thead><tbody>'
        + evs.slice(0, 40).map(ev => {
            const tm = new Date((ev.ts || 0) * 1000).toLocaleTimeString();
            const tone = ev.action === 'allow' ? 'ok' : (ev.action === 'auth_denied' ? 'bad' : 'warn');
            const totalB = ((ev.bytes_in || 0) + (ev.bytes_out || 0));
            const dataTxt = totalB > 1024 ? (totalB / 1024).toFixed(1) + ' KB' : totalB + ' B';
            const canAllow = ev.action === 'block' && ev.host && !String(ev.reason || '').includes('SSRF') && !String(ev.reason || '').includes('port');
            const fixBtn = canAllow
              ? '<button class="small" onclick="allowBlockedDomain(' + jsArg(ev.host) + ')">+ Allow</button>'
              : '<span class="hint">-</span>';
            return '<tr><td class="mono">' + esc(tm) + '</td><td><strong>' + esc(ev.node_id) + '</strong></td>'
              + '<td class="mono">' + esc(ev.host) + (ev.port ? ':' + esc(ev.port) : '') + '</td>'
              + '<td><span class="pill ' + tone + '">' + esc(ev.action.toUpperCase()) + '</span></td>'
              + '<td>' + esc(ev.reason) + '</td><td class="mono">' + esc(dataTxt) + '</td><td>' + fixBtn + '</td></tr>';
          }).join('')
        + '</tbody></table></div>';
    }
  } catch (e) {}
}

function addGatewayPreset(key) {
  const p = gwPresetsCache[key];
  if (!p) return;
  const el = document.getElementById('gw-allowed');
  const existing = el.value.split('\n').map(s => s.trim().toLowerCase()).filter(Boolean);
  const set = new Set(existing);
  for (const d of (p.domains || [])) set.add(d);
  el.value = Array.from(set).join('\n');
  showToast('Added ' + p.label + ' domains — click Save & Apply to activate.', 'ok');
}

async function saveGatewaySettings() {
  const payload = {
    enabled: document.getElementById('gw-enabled').value === 'true',
    mode: document.getElementById('gw-mode').value,
    port: Number(document.getElementById('gw-port').value || 8888),
    max_requests_per_min_per_node: Number(document.getElementById('gw-rpm').value || 0),
    block_private_ips: document.getElementById('gw-ssrf').checked,
    inject_proxy_env: document.getElementById('gw-inject').checked,
    allowed_domains: document.getElementById('gw-allowed').value.split('\n').map(s => s.trim()).filter(Boolean),
    blocked_domains: document.getElementById('gw-blocked').value.split('\n').map(s => s.trim()).filter(Boolean),
  };
  const data = await authPost('/api/gateway/settings', payload);
  if (data.error) { showToast('Network Guard error: ' + data.error, 'bad'); return; }
  showToast(payload.enabled ? 'Network Guard ON (port ' + data.port + ', mode: ' + data.mode + ')!' : 'Network Guard turned OFF.', payload.enabled ? 'ok' : 'neutral');
  loadNetworkCenter();
}

async function allowBlockedDomain(domain) {
  const data = await authPost('/api/gateway/allow-domain', { domain });
  if (data.error) { showToast('Allow failed: ' + data.error, 'bad'); return; }
  showToast('Added "' + domain + '" to Network Guard allowlist!', 'ok');
  loadGatewayStatus();
}

async function clearGatewayLogs() {
  const data = await authPost('/api/gateway/logs/clear', {});
  if (data.error) { showToast('Clear failed: ' + data.error, 'bad'); return; }
  showToast('Cleared Network Guard audit log.', 'neutral');
  loadGatewayStatus();
}

async function checkWanIsolation() {
  const box = document.getElementById('gw-isolation-box');
  box.innerHTML = 'Testing whether your router blocks direct WAN on worker phones...';
  const data = await authPost('/api/gateway/check-isolation', {});
  if (data.error) { box.textContent = 'Check failed: ' + data.error; showToast(data.error, 'bad'); return; }
  const rows = data.workers || [];
  if (!rows.length) {
    box.innerHTML = '<p class="hint">No worker phones configured yet.</p>';
    return;
  }
  box.innerHTML = rows.map(w => {
    const cls = w.wan_blocked === true ? 'ok' : (w.wan_blocked === false ? 'warn' : 'neutral');
    const tag = w.wan_blocked === true ? '✓ WAN BLOCKED' : (w.wan_blocked === false ? '⚠ DIRECT WAN OPEN' : 'OFFLINE / UNKNOWN');
    return '<div class="check-item"><span class="pill ' + cls + '">' + tag + '</span> '
      + '<strong>' + esc(w.node_id) + '</strong> (' + esc(w.host) + '): ' + esc(w.detail) + '</div>';
  }).join('');
}

function copyEl(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const txt = el.textContent || '';
  const fallbackCopy = () => {
    try {
      const ta = document.createElement('textarea');
      ta.value = txt;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand && document.execCommand('copy');
      document.body.removeChild(ta);
      if (ok) showToast('Copied to clipboard!', 'ok');
      else showToast('Copy blocked by browser — select text manually.', 'warn');
    } catch (e) {
      showToast('Copy failed — select text manually.', 'warn');
    }
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(txt).then(() => showToast('Copied to clipboard!', 'ok')).catch(fallbackCopy);
  } else {
    fallbackCopy();
  }
}

function refreshAll() {
  refreshLive();
  if (document.getElementById('panel-workloads').classList.contains('active')) loadWorkloads();
  if (document.getElementById('panel-network').classList.contains('active')) loadNetworkCenter();
  if (document.getElementById('panel-setup').classList.contains('active') && getToken()) {
    loadSafetySettings();
    pollPairingStatus();
  }
}

initPreferences();
updateAuthBadge();
onTermTargetChange();
renderPipeBuilder();
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
        self._conn_sem = threading.BoundedSemaphore(64)
        if ":" in str(addr[0]):
            self.address_family = socket.AF_INET6
        super().__init__(addr, DashboardRequestHandler)
        self.pairing_manager = PairingManager(
            config=controller.config,
            config_path=config_path,
            pair_port=self.server_address[1],
            listen_host=addr[0],
            fail_delay_sec=pairing_fail_delay_sec,
            enable_beacon=enable_pairing_beacon,
            config_lock=controller.config_lock,
        )
        self.gateway_manager = GatewayManager(controller.config)
        if controller.config.gateway.enabled:
            ok, msg = self.gateway_manager.start()
            if ok:
                controller.gateway_port_override = self.gateway_manager.bound_port
            else:
                controller.gateway_port_override = -1
                LOG.warning("Master Network Guard failed to start on boot: %s", msg)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._conn_sem.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._conn_sem.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_sem.release()

    def server_close(self) -> None:
        try:
            self.pairing_manager.close_session()
            self.gateway_manager.stop()
        finally:
            super().server_close()


class DashboardRequestHandler(BaseHTTPRequestHandler):
    server: DashboardHTTPServer
    timeout = 15.0

    def version_string(self) -> str:
        return "PhoneCluster"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        msg = re.sub(r"[\x00-\x1f\x7f]", "?", format % args)
        LOG.info("dashboard %s - %s", self.address_string(), msg)

    def _save_config_or_rollback(self, rollback_fn: Any) -> bool:
        """Persist `controller.config` atomically; roll back in-memory state and return HTTP 500 JSON on failure."""
        if self.server.config_path is None:
            return True
        try:
            save_config(self.server.controller.config, self.server.config_path)
            return True
        except Exception as exc:
            try:
                rollback_fn()
            except Exception as rb_exc:
                LOG.error("Rollback after failed config save also failed: %s", rb_exc)
            LOG.error("Failed to save cluster config: %s", exc)
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": f"Failed to persist cluster config: {exc}"},
            )
            return False

    def _send(self, status: int, content_type: str, raw: bytes) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if content_type.startswith("text/html"):
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            )
        if self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            pass

    def _check_same_origin(self) -> bool:
        """Block cross-site browser POSTs (CSRF defense) while keeping non-browser API clients working."""
        sec_fetch_site = self.headers.get("Sec-Fetch-Site", "").strip().lower()
        if sec_fetch_site == "cross-site":
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden: cross-site browser POST rejected"},
            )
            return False
        host_hdr = self.headers.get("Host", "").strip().lower()
        origin = self.headers.get("Origin", "").strip()
        if origin:
            try:
                parsed = urllib.parse.urlparse(origin)
                _ = parsed.port
            except ValueError:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "forbidden: malformed Origin header on browser POST"},
                )
                return False
            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not host_hdr
                or parsed.netloc.lower() != host_hdr
            ):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "forbidden: cross-origin browser POST rejected"},
                )
                return False
            return True
        referer = self.headers.get("Referer", "").strip()
        if referer:
            try:
                parsed_ref = urllib.parse.urlparse(referer)
                _ = parsed_ref.port
            except ValueError:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "forbidden: malformed Referer header on browser POST"},
                )
                return False
            if (
                parsed_ref.scheme.lower() not in {"http", "https"}
                or not host_hdr
                or parsed_ref.netloc.lower() != host_hdr
            ):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "forbidden: cross-origin Referer on browser POST rejected"},
                )
                return False
        return True

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        self._send(status, "application/json", safe_json_dumps(data).encode("utf-8"))

    def _read_json(self) -> dict[str, Any] | None:
        length, err_status, err_msg = parse_strict_content_length(self.headers, MAX_DASHBOARD_BODY)
        if length is None:
            self._send_json(err_status, {"error": err_msg})
            return None
        try:
            if length > 0:
                raw_bytes = self.rfile.read(length)
                if len(raw_bytes) != length:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "truncated request body"})
                    return None
                raw = raw_bytes.decode("utf-8")
            else:
                raw = "{}"

            def _reject_nonfinite(tok: str) -> Any:
                raise ValueError(f"non-finite JSON constant '{tok}' not allowed")

            body = json.loads(raw, parse_constant=_reject_nonfinite)
            if not isinstance(body, dict):
                raise ValueError("JSON body must be an object")
            return body
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, OSError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid JSON: {exc}"})
            return None

    @staticmethod
    def _parse_int_arg(raw_val: Any, default: int | None = None) -> int:
        if raw_val is None:
            if default is None:
                raise ValueError("missing integer value")
            return default
        if isinstance(raw_val, bool):
            raise ValueError("expected integer, got boolean")
        if isinstance(raw_val, float):
            if not math.isfinite(raw_val) or not raw_val.is_integer():
                raise ValueError("expected finite integer")
            return int(raw_val)
        return int(raw_val)

    def _require_auth(self) -> bool:
        client_ip = normalize_host(str(self.client_address[0]))
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

    def _check_host(self) -> bool:
        """Defend against browser DNS rebinding & duplicate-Host smuggling."""
        with self.server.controller.config_lock:
            configured_hosts = {n.host for n in self.server.controller.config.nodes if n.host}
        if not is_allowed_http_host(self.headers, extra_allowed_hosts=configured_hosts):
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden: invalid or untrusted Host header (DNS rebinding guard)"},
            )
            return False
        return True

    def do_HEAD(self) -> None:  # noqa: N802
        if not self._check_host():
            return
        path = self.path.split("?", 1)[0]
        if path in {"/", "/index.html"}:
            raw = DASHBOARD_HTML.encode("utf-8")
            self.send_response(int(HTTPStatus.OK))
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
        else:
            self.send_response(int(HTTPStatus.NOT_FOUND))
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if not self._check_host():
            return
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
        elif path in {
            "/api/status",
            "/api/metrics",
            "/api/live",
            "/api/jobs",
            "/api/doctor",
            "/api/workloads",
            "/api/services",
            "/api/gateway/status",
            "/api/network/audit",
            "/api/discover",
        }:
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
            elif path == "/api/services":
                self._send_json(HTTPStatus.OK, self.server.controller.get_services_info())
            elif path == "/api/gateway/status":
                self._send_json(HTTPStatus.OK, self.server.gateway_manager.status())
            elif path == "/api/network/audit":
                self._send_json(
                    HTTPStatus.OK,
                    audit_cluster_network(
                        self.server.controller,
                        gateway_manager=self.server.gateway_manager,
                    ),
                )
            elif path == "/api/doctor":
                report = run_doctor(config_path=self.server.config_path, check_remote=True)
                self._send_json(HTTPStatus.OK, report)
            elif path == "/api/workloads":
                ctrl = self.server.controller
                snaps = ctrl.poll_health()
                quarantined = ctrl._quarantined_ids()
                ha_urls: list[str] = []
                docker_nodes: list[str] = []
                docker_snap_nodes: list[str] = []
                docker_socket_issues: list[str] = []
                for s in snaps:
                    if not s.online or s.node.id in quarantined:
                        continue
                    raw_svcs = s.health.get("services") if isinstance(s.health, dict) else None
                    svcs_d = raw_svcs if isinstance(raw_svcs, dict) else {}
                    raw_tools = s.health.get("tools") if isinstance(s.health, dict) else None
                    tools_d = raw_tools if isinstance(raw_tools, dict) else {}
                    if svcs_d.get("homeassistant_8123"):
                        ha_urls.append(f"http://{format_host_port(s.node.host, 8123)}")
                    has_dk = bool(tools_d.get("docker")) or resolve_node_tier_and_pool(s.node, s.health)[0] == 3
                    if has_dk:
                        docker_nodes.append(s.node.id)
                        if isinstance(s.health, dict) and s.health.get("docker_snap"):
                            docker_snap_nodes.append(s.node.id)
                        if isinstance(s.health, dict) and tools_d.get("docker") and not s.health.get("docker_socket_accessible", True):
                            docker_socket_issues.append(s.node.id)
                with ctrl.config_lock:
                    master_node = next((n for n in ctrl.config.nodes if n.role == "master"), ctrl.config.nodes[0])
                    cfg_subnet = ctrl.config.network.lan_subnet
                seed_host = (
                    detect_local_ip()
                    if is_loopback_or_unspecified_host(master_node.host)
                    else master_node.host
                )
                lan_subnet = infer_lan_subnet(seed_host, cfg_subnet)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "distcc_hosts": ctrl.build_distcc_hosts(snapshots=snaps),
                        "llama_rpc": ctrl.build_llama_rpc_arg(snapshots=snaps),
                        "mpi_hostfile": ctrl.build_mpi_hostfile(snapshots=snaps),
                        "home_assistant_urls": ha_urls,
                        "docker_nodes": docker_nodes,
                        "docker_snap_nodes": docker_snap_nodes,
                        "docker_socket_issues": docker_socket_issues,
                        "lan_subnet": lan_subnet,
                        "services_info": ctrl.get_services_info(snapshots=snaps),
                    },
                )
            elif path == "/api/discover":
                with self.server.controller.config_lock:
                    existing_hosts = {n.host for n in self.server.controller.config.nodes}
                found = discover_lan_nodes(timeout_sec=2.0)
                for item in found:
                    item["already_configured"] = item["host"] in existing_hosts
                self._send_json(HTTPStatus.OK, {"discovered": found})
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._check_host():
            return
        path = self.path.split("?", 1)[0]
        if path == "/api/pair/complete":
            if not self._check_same_origin():
                return
            body = self._read_json()
            if body is None:
                return
            try:
                local_ip = str(self.connection.getsockname()[0])
            except OSError:
                local_ip = ""
            status, data = self.server.pairing_manager.complete_pairing(
                self.client_address[0], body, local_ip=local_ip
            )
            self._send_json(status, data)
            return

        valid_paths = {
            "/api/exec",
            "/api/terminal/exec",
            "/api/map",
            "/api/pipeline",
            "/api/services/custom",
            "/api/services/custom/remove",
            "/api/services/probe",
            "/api/gateway/settings",
            "/api/gateway/logs/clear",
            "/api/gateway/allow-domain",
            "/api/gateway/quarantine",
            "/api/gateway/check-isolation",
            "/api/network/profile",
            "/api/network/hardening",
            "/api/network/push-config",
            "/api/jobs/cancel",
            "/api/nodes/add",
            "/api/nodes/update",
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
        if not self._check_same_origin():
            return
        if not self._require_auth():
            return
        body = self._read_json()
        if body is None:
            return

        ctrl = self.server.controller

        if path == "/api/pair/open":
            try:
                ttl = self._parse_int_arg(body.get("ttl_sec"), 120)
                slots = self._parse_int_arg(body.get("max_devices"), 1)
            except (TypeError, ValueError, OverflowError):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "ttl_sec and max_devices must be integers"})
                return
            data = self.server.pairing_manager.open_session(ttl_sec=ttl, max_devices=slots)
            self._send_json(HTTPStatus.OK, data)
            return
        if path == "/api/pair/close":
            data = self.server.pairing_manager.close_session()
            self._send_json(HTTPStatus.OK, data)
            return

        def _parse_timeout(raw_val: Any) -> float | None:
            if raw_val in (None, ""):
                return float(ctrl.config.default_job_timeout_sec)
            if isinstance(raw_val, bool):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "timeout_sec must be a positive number"})
                return None
            try:
                val = float(raw_val)
                if not math.isfinite(val) or val <= 0 or val > 86400.0:
                    raise ValueError("timeout_sec must be a finite number between 0 and 86400")
                return val
            except (TypeError, ValueError, OverflowError):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "timeout_sec must be a positive number <= 86400"})
                return None

        if path == "/api/exec":
            command = str(body.get("command") or "").strip()
            target = str(body.get("target") or "auto").strip() or "auto"
            workload_hint = str(body.get("workload_hint") or body.get("workload") or "").strip()
            if not command:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty command"})
                return
            timeout = _parse_timeout(body.get("timeout_sec"))
            if timeout is None:
                return
            spec = JobSpec(
                index=0,
                job_id=f"web-{int(time.time())}-{uuid.uuid4().hex[:6]}",
                command=command,
                timeout_sec=timeout,
            )
            outcomes = ctrl.run_single(spec, target=target, workload_hint=workload_hint)
            self._send_json(HTTPStatus.OK, {"results": [o.to_dict() for o in outcomes]})

        elif path == "/api/terminal/exec":
            command = str(body.get("command") or "").strip()
            target = str(body.get("target") or "auto").strip() or "auto"
            cwd = str(body.get("cwd") or "").strip() or None
            job_id = str(body.get("job_id") or "").strip() or None
            workload_hint = str(body.get("workload_hint") or body.get("workload") or "").strip()
            if not command:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty command"})
                return
            timeout = _parse_timeout(body.get("timeout_sec"))
            if timeout is None:
                return
            try:
                results = ctrl.exec_terminal_command(
                    command=command,
                    target=target,
                    cwd=cwd,
                    timeout_sec=timeout,
                    job_id=job_id,
                    workload_hint=workload_hint,
                )
            except KeyError as exc:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.OK, {"results": results})

        elif path == "/api/map":
            mode = str(body.get("mode") or "commands")
            target = str(body.get("target") or "auto").strip() or "auto"
            workload_hint = str(body.get("workload_hint") or body.get("workload") or "").strip()
            timeout = _parse_timeout(body.get("timeout_sec"))
            if timeout is None:
                return
            jobs: list[JobSpec] = []
            batch_id = uuid.uuid4().hex[:6]
            if mode == "script":
                script_content = str(body.get("script_content") or "")
                interpreter = str(body.get("interpreter") or "python3").strip() or "python3"
                args_lines = body.get("args_lines") or []
                if not script_content.strip() or not isinstance(args_lines, list) or not args_lines:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "provide script_content and non-empty args_lines"})
                    return
                if len(args_lines) > 2000:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "maximum 2000 jobs per batch"})
                    return
                for idx, line in enumerate(args_lines):
                    try:
                        parsed_args = shlex.split(str("" if line is None else line))
                    except ValueError as exc:
                        self._send_json(
                            HTTPStatus.BAD_REQUEST,
                            {"error": f"Invalid arguments on line {idx + 1}: {exc}"},
                        )
                        return
                    jobs.append(
                        JobSpec(
                            index=idx,
                            job_id=f"webmap-{batch_id}-{idx:04d}",
                            script_content=script_content,
                            script_name="web_job.py" if "python" in interpreter else "web_job.sh",
                            interpreter=interpreter,
                            args=parsed_args,
                            timeout_sec=timeout,
                            env={"PHONECLUSTER_TASK_INDEX": str(idx)},
                        )
                    )
            else:
                commands = body.get("commands") or []
                if not isinstance(commands, list) or not commands:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "provide non-empty commands list"})
                    return
                if len(commands) > 2000:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "maximum 2000 jobs per batch"})
                    return
                for idx, cmd in enumerate(commands):
                    if cmd is None:
                        continue
                    cmd_s = str(cmd).strip()
                    if cmd_s:
                        jobs.append(
                            JobSpec(
                                index=idx,
                                job_id=f"webmap-{batch_id}-{idx:04d}",
                                command=cmd_s,
                                timeout_sec=timeout,
                                env={"PHONECLUSTER_TASK_INDEX": str(idx)},
                            )
                        )
                if not jobs:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "provide at least one non-empty command"})
                    return
            t0 = time.monotonic()
            outcomes = ctrl.map_jobs(jobs, retries=1, target=target, workload_hint=workload_hint)
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

        elif path == "/api/pipeline":
            steps = body.get("steps")
            if not isinstance(steps, list) or not steps or not all(isinstance(s, dict) for s in steps):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "provide a non-empty 'steps' array of pipeline step objects"},
                )
                return
            if len(steps) > 100:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "maximum 100 steps per pipeline"},
                )
                return
            stop_on_error = bool(body.get("stop_on_error", True))
            res = ctrl.run_pipeline(steps, stop_on_error=stop_on_error)
            self._send_json(HTTPStatus.OK, res)

        elif path == "/api/services/custom":
            raw_name = str(body.get("name") or "").strip().lower()
            url = str(body.get("url") or "").strip()
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", raw_name):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "service name must be 1-40 chars (letters, digits, '_' or '-')"},
                )
                return
            allowed_schemes = {"http", "https", "mqtt", "tcp", "redis", "postgresql", "ssh"}
            url_ok = False
            if url and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
                try:
                    p_svc = urllib.parse.urlsplit(url)
                    svc_port = p_svc.port
                    url_ok = (
                        p_svc.scheme.lower() in allowed_schemes
                        and bool(p_svc.hostname)
                        and (svc_port is None or 1 <= svc_port <= 65535)
                    )
                except ValueError:
                    url_ok = False
            if not url_ok:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "url must be a valid http://, https://, mqtt://, tcp://, redis://, postgresql://, or ssh:// URL with a hostname and valid port"},
                )
                return
            with ctrl.config_lock:
                prev_existed = raw_name in ctrl.config.custom_services
                prev_val = ctrl.config.custom_services.get(raw_name)
                ctrl.config.custom_services[raw_name] = url

                def _rb_svc_add() -> None:
                    if prev_existed and prev_val is not None:
                        ctrl.config.custom_services[raw_name] = prev_val
                    else:
                        ctrl.config.custom_services.pop(raw_name, None)

                if not self._save_config_or_rollback(_rb_svc_add):
                    return
                custom_copy = dict(ctrl.config.custom_services)
            self._send_json(
                HTTPStatus.OK,
                {"name": raw_name, "url": url, "custom_services": custom_copy},
            )

        elif path == "/api/services/custom/remove":
            raw_name = str(body.get("name") or "").strip()
            with ctrl.config_lock:
                matched_key: str | None = None
                if raw_name in ctrl.config.custom_services:
                    matched_key = raw_name
                else:
                    lower_name = raw_name.lower()
                    matched_key = next(
                        (k for k in ctrl.config.custom_services if k.lower() == lower_name),
                        None,
                    )
                if not matched_key:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": f"custom service '{raw_name}' not found"})
                    return
                removed_val = ctrl.config.custom_services.pop(matched_key, None)

                def _rb_svc_rm() -> None:
                    if matched_key is not None and removed_val is not None:
                        ctrl.config.custom_services[matched_key] = removed_val

                if not self._save_config_or_rollback(_rb_svc_rm):
                    return
            self._send_json(HTTPStatus.OK, {"removed": matched_key})

        elif path == "/api/services/probe":
            host = normalize_host(str(body.get("host") or ""))
            try:
                port = self._parse_int_arg(body.get("port"), 0)
            except (TypeError, ValueError, OverflowError):
                port = 0
            if not host or port <= 0 or port > 65535:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "valid host and port required"})
                return
            # Restrict probes strictly to endpoints already registered in the live Service Mesh
            svc_entries = ctrl.get_services_info().get("services", [])
            allowed = any(
                normalize_host(str(e.get("host") or "")) == host and int(e.get("port") or 0) == port
                for e in svc_entries
            )
            if not allowed:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "probe allowed only for registered Service Mesh endpoints"},
                )
                return
            self._send_json(HTTPStatus.OK, ctrl.probe_tcp_endpoint(host, port))

        elif path == "/api/gateway/settings":
            with ctrl.config_lock:
                prev_gw = ctrl.config.gateway

                def _gw_val(key: str, fallback: Any) -> Any:
                    val = body.get(key)
                    return fallback if val is None else val

                merged = {
                    "enabled": _gw_val("enabled", prev_gw.enabled),
                    "bind_host": _gw_val("bind_host", prev_gw.bind_host),
                    "port": _gw_val("port", prev_gw.port),
                    "mode": _gw_val("mode", prev_gw.mode),
                    "allowed_domains": _gw_val("allowed_domains", prev_gw.allowed_domains),
                    "blocked_domains": _gw_val("blocked_domains", prev_gw.blocked_domains),
                    "allowed_ports": _gw_val("allowed_ports", prev_gw.allowed_ports),
                    "block_private_ips": _gw_val("block_private_ips", prev_gw.block_private_ips),
                    "inject_proxy_env": _gw_val("inject_proxy_env", prev_gw.inject_proxy_env),
                    "max_connections": _gw_val("max_connections", prev_gw.max_connections),
                    "idle_timeout_sec": _gw_val("idle_timeout_sec", prev_gw.idle_timeout_sec),
                    "quarantined_nodes": _gw_val("quarantined_nodes", prev_gw.quarantined_nodes),
                    "max_requests_per_min_per_node": _gw_val(
                        "max_requests_per_min_per_node", prev_gw.max_requests_per_min_per_node
                    ),
                }
                try:
                    updated_gw = GatewayConfig.from_dict(merged)
                except (ValueError, TypeError, OverflowError) as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                ctrl.config.gateway = updated_gw
                ok, msg = self.server.gateway_manager.sync_with_config()
                if not ok:
                    # Roll back to previous working gateway config so a bad port doesn't break a running proxy
                    ctrl.config.gateway = prev_gw
                    if prev_gw.enabled:
                        self.server.gateway_manager.sync_with_config()
                        ctrl.gateway_port_override = (
                            self.server.gateway_manager.bound_port
                            if self.server.gateway_manager.is_running
                            else -1
                        )
                    else:
                        ctrl.gateway_port_override = None
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": msg})
                    return
                prev_port_override = ctrl.gateway_port_override
                ctrl.gateway_port_override = (
                    self.server.gateway_manager.bound_port if updated_gw.enabled else None
                )

                def _rb_gw_settings() -> None:
                    ctrl.config.gateway = prev_gw
                    self.server.gateway_manager.sync_with_config()
                    ctrl.gateway_port_override = prev_port_override

                if not self._save_config_or_rollback(_rb_gw_settings):
                    return
            self._send_json(HTTPStatus.OK, self.server.gateway_manager.status())

        elif path == "/api/gateway/logs/clear":
            self.server.gateway_manager.audit_log.clear()
            self._send_json(HTTPStatus.OK, {"cleared": True})

        elif path == "/api/gateway/allow-domain":
            try:
                dom = validate_domain_pattern(str(body.get("domain") or ""))
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            with ctrl.config_lock:
                prev_allowed = list(ctrl.config.gateway.allowed_domains)
                prev_blocked = list(ctrl.config.gateway.blocked_domains)
                if dom not in ctrl.config.gateway.allowed_domains:
                    ctrl.config.gateway.allowed_domains.append(dom)
                ctrl.config.gateway.blocked_domains = [
                    d for d in ctrl.config.gateway.blocked_domains if d != dom
                ]

                def _rb_allow_dom() -> None:
                    ctrl.config.gateway.allowed_domains = prev_allowed
                    ctrl.config.gateway.blocked_domains = prev_blocked

                if not self._save_config_or_rollback(_rb_allow_dom):
                    return
                allowed_copy = list(ctrl.config.gateway.allowed_domains)
            self._send_json(HTTPStatus.OK, {"allowed": dom, "allowed_domains": allowed_copy})

        elif path == "/api/gateway/quarantine":
            node_id = str(body.get("node_id") or "").strip()
            quarantine = bool(True if body.get("quarantine") is None else body.get("quarantine"))
            with ctrl.config_lock:
                if not node_id or not any(n.id == node_id for n in ctrl.config.nodes):
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": f"node '{node_id}' not found"})
                    return
                target_n = ctrl.config.get_node(node_id)
                if target_n.role == "master":
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "cannot quarantine the master node"})
                    return
                prev_q = list(ctrl.config.gateway.quarantined_nodes)
                q_set = set(prev_q)
                if quarantine:
                    q_set.add(node_id)
                else:
                    q_set.discard(node_id)
                ctrl.config.gateway.quarantined_nodes = sorted(q_set)

                def _rb_quarantine() -> None:
                    ctrl.config.gateway.quarantined_nodes = prev_q

                if not self._save_config_or_rollback(_rb_quarantine):
                    return
                q_copy = list(ctrl.config.gateway.quarantined_nodes)
            closed_tunnels = (
                self.server.gateway_manager.disconnect_node(node_id) if quarantine else 0
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "node_id": node_id,
                    "quarantined": quarantine,
                    "quarantined_nodes": q_copy,
                    "disconnected_tunnels": closed_tunnels,
                },
            )

        elif path == "/api/network/profile":
            profile = str(body.get("profile") or "").strip()
            with ctrl.config_lock:
                prev_gw = GatewayConfig.from_dict(ctrl.config.to_dict().get("gateway"))
                prev_req_auth = ctrl.config.dashboard_require_auth
                prev_net = NetworkHardeningConfig.from_dict(ctrl.config.to_dict().get("network"))
                prev_port_override = ctrl.gateway_port_override
                try:
                    res = apply_security_profile(ctrl.config, profile)
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                ok, msg = self.server.gateway_manager.sync_with_config()
                if not ok:
                    ctrl.config.gateway = prev_gw
                    ctrl.config.dashboard_require_auth = prev_req_auth
                    ctrl.config.network = prev_net
                    if prev_gw.enabled:
                        self.server.gateway_manager.sync_with_config()
                        ctrl.gateway_port_override = (
                            self.server.gateway_manager.bound_port
                            if self.server.gateway_manager.is_running
                            else -1
                        )
                    else:
                        ctrl.gateway_port_override = None
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": msg})
                    return
                ctrl.gateway_port_override = (
                    self.server.gateway_manager.bound_port if ctrl.config.gateway.enabled else None
                )

                def _rb_profile() -> None:
                    ctrl.config.gateway = prev_gw
                    ctrl.config.dashboard_require_auth = prev_req_auth
                    ctrl.config.network = prev_net
                    self.server.gateway_manager.sync_with_config()
                    ctrl.gateway_port_override = prev_port_override

                if not self._save_config_or_rollback(_rb_profile):
                    return
            pushed = ctrl.push_config_to_all()
            self._send_json(
                HTTPStatus.OK,
                {**res, "gateway": self.server.gateway_manager.status(), "pushed": pushed},
            )

        elif path == "/api/network/hardening":
            with ctrl.config_lock:
                new_req_auth = (
                    bool(body["dashboard_require_auth"])
                    if "dashboard_require_auth" in body and body["dashboard_require_auth"] is not None
                    else ctrl.config.dashboard_require_auth
                )
                cur_net = ctrl.config.network
                master_node = next((n for n in ctrl.config.nodes if n.role == "master"), ctrl.config.nodes[0])
                raw_ips = body.get("allowed_master_ips", cur_net.allowed_master_ips)
                ips: list[str] = []
                if isinstance(raw_ips, list):
                    seen_ips: set[str] = set()
                    for item in raw_ips:
                        if item is None:
                            continue
                        if not isinstance(item, str):
                            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "allowed_master_ips entries must be strings"})
                            return
                        s_item = item.strip()
                        if not s_item:
                            continue
                        try:
                            validated_ip = validate_allowed_master_entry(s_item)
                        except ValueError as exc:
                            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                            return
                        if validated_ip not in seen_ips:
                            seen_ips.add(validated_ip)
                            ips.append(validated_ip)
                elif raw_ips is not None:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "allowed_master_ips must be a list"})
                    return
                else:
                    ips = list(cur_net.allowed_master_ips)
                # Ensure Master's own IP is ALWAYS preserved within the 32-entry cap (prevents self-lockout!)
                m_host = normalize_host(master_node.host)
                if m_host and not is_loopback_or_unspecified_host(m_host):
                    if m_host in ips:
                        ips = ips[:32]
                        if m_host not in ips:
                            ips = ips[:31] + [m_host]
                    else:
                        ips = ips[:31] + [m_host]
                else:
                    ips = ips[:32]
                raw_ag = body.get("adguard_url", cur_net.adguard_url)
                ag_url = str("" if raw_ag is None else raw_ag).strip()
                if ag_url:
                    try:
                        p_ag = urllib.parse.urlsplit(ag_url)
                        ag_port = p_ag.port
                    except ValueError:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "adguard_url is malformed"})
                        return
                    if (
                        any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in ag_url)
                        or p_ag.scheme.lower() not in {"http", "https"}
                        or not p_ag.hostname
                        or (ag_port is not None and not (1 <= ag_port <= 65535))
                    ):
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "adguard_url must start with http:// or https:// with a valid hostname"})
                        return
                raw_sub = body.get("lan_subnet", cur_net.lan_subnet)
                lan_sub = str("" if raw_sub is None else raw_sub).strip()
                if lan_sub:
                    try:
                        lan_sub = str(ipaddress.ip_network(lan_sub, strict=False))
                    except ValueError:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid lan_subnet CIDR '{lan_sub}'"})
                        return
                # Apply mutations only after ALL inputs validated cleanly, with rollback on disk save failure
                prev_req_auth = ctrl.config.dashboard_require_auth
                prev_net_obj = ctrl.config.network
                ctrl.config.dashboard_require_auth = new_req_auth
                ctrl.config.network = NetworkHardeningConfig(
                    enforce_worker_source_ip=bool(
                        cur_net.enforce_worker_source_ip
                        if body.get("enforce_worker_source_ip") is None
                        else body.get("enforce_worker_source_ip")
                    ),
                    require_signed_requests=bool(
                        cur_net.require_signed_requests
                        if body.get("require_signed_requests") is None
                        else body.get("require_signed_requests")
                    ),
                    allowed_master_ips=ips,
                    adguard_url=ag_url,
                    lan_subnet=lan_sub,
                )

                def _rb_hardening() -> None:
                    ctrl.config.dashboard_require_auth = prev_req_auth
                    ctrl.config.network = prev_net_obj

                if not self._save_config_or_rollback(_rb_hardening):
                    return
                resp_hardening = {
                    "saved": True,
                    "dashboard_require_auth": ctrl.config.dashboard_require_auth,
                    "enforce_worker_source_ip": ctrl.config.network.enforce_worker_source_ip,
                    "require_signed_requests": ctrl.config.network.require_signed_requests,
                    "allowed_master_ips": list(ctrl.config.network.allowed_master_ips),
                }
            resp_hardening["pushed"] = ctrl.push_config_to_all()
            self._send_json(HTTPStatus.OK, resp_hardening)

        elif path == "/api/network/push-config":
            raw_ids = body.get("node_ids")
            node_ids = [str(x).strip() for x in raw_ids if x is not None and str(x).strip()] if isinstance(raw_ids, list) else None
            self._send_json(HTTPStatus.OK, ctrl.push_config_to_all(node_ids=node_ids))

        elif path == "/api/gateway/check-isolation":
            results = ctrl.check_workers_wan_isolation()
            self._send_json(HTTPStatus.OK, {"workers": results})

        elif path == "/api/jobs/cancel":
            node_id = str(body.get("node_id") or "").strip()
            job_id = str(body.get("job_id") or "").strip()
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
            action = str(body.get("action") or "").strip()
            if action == "docker-status":
                self._send_json(HTTPStatus.OK, ctrl.docker_cluster_status())
                return
            if action == "docker-swarm-init":
                mgr_id = str(body.get("manager_node_id") or "").strip() or None
                adv = str(body.get("advertise_addr") or "").strip()
                if adv:
                    try:
                        adv = validate_host(adv)
                    except ValueError as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid advertise_addr: {exc}"})
                        return
                self._send_json(HTTPStatus.OK, ctrl.docker_swarm_setup(manager_node_id=mgr_id, advertise_addr=adv))
                return
            cidr = str(body.get("cidr") or "").strip()
            if not cidr:
                with ctrl.config_lock:
                    master_node = next((n for n in ctrl.config.nodes if n.role == "master"), ctrl.config.nodes[0])
                    cfg_subnet = ctrl.config.network.lan_subnet
                seed_host = (
                    detect_local_ip()
                    if is_loopback_or_unspecified_host(master_node.host)
                    else master_node.host
                )
                cidr = infer_lan_subnet(seed_host, cfg_subnet)
            elif action == "distcc-start":
                try:
                    cidr = str(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid CIDR subnet '{cidr}'"})
                    return
            action_args_map = {
                "distcc-start": ["distcc-start", cidr],
                "distcc-stop": ["distcc-stop"],
                "llama-rpc-start": ["llama-rpc-start"],
                "llama-rpc-stop": ["llama-rpc-stop"],
            }
            script_args = action_args_map.get(action)
            if not script_args:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"unsupported action '{action}'"})
                return
            # Ship 05_workload_helpers.sh inline so it works regardless of install directory on each phone!
            wl_job_id = f"wl-{action}-{uuid.uuid4().hex[:6]}"
            if WORKLOAD_HELPER_SCRIPT.exists():
                spec = JobSpec(
                    index=0,
                    job_id=wl_job_id,
                    script_content=WORKLOAD_HELPER_SCRIPT.read_text(encoding="utf-8"),
                    script_name="05_workload_helpers.sh",
                    interpreter="bash",
                    args=script_args,
                    timeout_sec=30.0,
                )
            else:
                quoted_args = " ".join(shlex.quote(a) for a in script_args)
                spec = JobSpec(
                    index=0,
                    job_id=wl_job_id,
                    command=f"bash ~/phonecluster/scripts/05_workload_helpers.sh {quoted_args}",
                    timeout_sec=30.0,
                )
            # For llama-rpc-start, prefer worker phones if any exist so a 512 MB Pi Master doesn't OOM
            if action == "llama-rpc-start":
                with ctrl.config_lock:
                    has_workers = any(n.role != "master" for n in ctrl.config.nodes)
                if has_workers:
                    import concurrent.futures as _cf
                    from .routing import build_cross_tier_env as _build_env

                    snaps = ctrl.poll_health()
                    quarantined = ctrl._quarantined_ids()
                    ready_workers = [
                        s
                        for s in snaps
                        if s.online and s.ready_for_jobs and s.node.role != "master" and s.node.id not in quarantined
                    ]
                    if ready_workers:
                        with ctrl.config_lock:
                            cross_env = _build_env(snaps, ctrl.config)
                        outcomes = []
                        with _cf.ThreadPoolExecutor(max_workers=min(32, len(ready_workers))) as pool:
                            fut_map = {
                                pool.submit(
                                    ctrl.exec_on_node,
                                    ws.node,
                                    ctrl._with_node_env(spec, ws.node, cross_env),
                                ): ws
                                for ws in ready_workers
                            }
                            for fut in _cf.as_completed(fut_map):
                                ws = fut_map[fut]
                                kind, data = fut.result()
                                t_num, p_name = resolve_node_tier_and_pool(ws.node, ws.health)
                                outcomes.append(
                                    ctrl._to_outcome(
                                        spec,
                                        ws.node.id,
                                        kind,
                                        data,
                                        attempts=1,
                                        node_tier=t_num,
                                        node_pool=p_name,
                                        routing_reason="Broadcast llama-rpc-start to ready worker phones",
                                    )
                                )
                        outcomes.sort(key=lambda o: o.node_id)
                        self._send_json(HTTPStatus.OK, {"action": action, "results": [o.to_dict() for o in outcomes]})
                        return
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "action": action,
                            "results": [
                                {
                                    "index": 0,
                                    "job_id": wl_job_id,
                                    "label": "llama-rpc-start",
                                    "node_id": "none",
                                    "ok": False,
                                    "returncode": -1,
                                    "duration_sec": 0.0,
                                    "error": "No online, ready, non-quarantined worker phones available for llama-rpc-start (Master skipped to protect low-RAM controllers).",
                                }
                            ],
                        },
                    )
                    return
            outcomes = ctrl.run_single(spec, target="all")
            self._send_json(HTTPStatus.OK, {"action": action, "results": [o.to_dict() for o in outcomes]})

        elif path == "/api/nodes/add":
            try:
                host = validate_host(str(body.get("host") or ""))
                ssh_user = validate_ssh_user(str(body.get("ssh_user") or ""))
                pool_name = validate_pool_name(str(body.get("pool") or "auto"))
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            try:
                tier = self._parse_int_arg(body.get("tier"), 0)
                worker_port = self._parse_int_arg(body.get("worker_port"), DEFAULT_WORKER_PORT)
                ssh_port = self._parse_int_arg(body.get("ssh_port"), DEFAULT_SSH_PORT)
                max_conc = max(1, min(32, self._parse_int_arg(body.get("max_concurrency"), 2)))
                raw_w = body.get("weight", 1.0)
                if raw_w is None:
                    weight = 1.0
                elif isinstance(raw_w, bool):
                    raise ValueError("weight must be a number, not boolean")
                else:
                    weight = max(0.1, float(raw_w))
                if not math.isfinite(weight):
                    raise ValueError("weight must be finite")
            except (TypeError, ValueError, OverflowError):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid numeric node parameter"})
                return
            if tier not in {0, 1, 2, 3}:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "tier must be 0, 1, 2, or 3"})
                return
            if not (1 <= worker_port <= 65535 and 1 <= ssh_port <= 65535):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "ports must be between 1 and 65535"})
                return
            with ctrl.config_lock:
                existing_ids = {n.id for n in ctrl.config.nodes}
                idx = len(ctrl.config.nodes)
                while f"node{idx}" in existing_ids:
                    idx += 1
                try:
                    node_id = validate_node_id(str(body.get("id") or f"node{idx}"))
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                if node_id in existing_ids:
                    self._send_json(HTTPStatus.CONFLICT, {"error": f"node id '{node_id}' already exists"})
                    return
                new_node = NodeConfig(
                    id=node_id,
                    host=host,
                    role="worker",
                    worker_port=worker_port,
                    ssh_port=ssh_port,
                    ssh_user=ssh_user,
                    max_concurrency=max_conc,
                    weight=weight,
                    tier=tier,
                    pool=pool_name,
                    tags=["worker"],
                    notes="Added via Web Control Center",
                )
                ctrl.config.nodes.append(new_node)
                if not self._save_config_or_rollback(lambda: ctrl.config.nodes.pop()):
                    return
            self._send_json(
                HTTPStatus.OK,
                {"node": {"id": new_node.id, "host": new_node.host, "tier": new_node.tier, "pool": new_node.pool}},
            )

        elif path == "/api/nodes/update":
            node_id = str(body.get("id") or "").strip()
            if not node_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing node id"})
                return
            # Validate ALL fields upfront so an invalid later field never leaves partial in-memory mutations!
            new_tier: int | None = None
            new_pool: str | None = None
            new_mc: int | None = None
            new_weight: float | None = None
            new_notes: str | None = None
            if "tier" in body:
                try:
                    t_val = self._parse_int_arg(body["tier"])
                except (TypeError, ValueError, OverflowError):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "tier must be 0, 1, 2, or 3"})
                    return
                if t_val not in {0, 1, 2, 3}:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "tier must be 0, 1, 2, or 3"})
                    return
                new_tier = t_val
            if "pool" in body:
                try:
                    new_pool = validate_pool_name(str(body["pool"] or "auto"))
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
            if "max_concurrency" in body:
                try:
                    mc_val = self._parse_int_arg(body["max_concurrency"])
                    if not (1 <= mc_val <= 32):
                        raise ValueError("must be between 1 and 32")
                    new_mc = mc_val
                except (TypeError, ValueError, OverflowError):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "max_concurrency must be an integer between 1 and 32"})
                    return
            if "weight" in body:
                try:
                    raw_w = body["weight"]
                    if isinstance(raw_w, bool):
                        raise ValueError("weight must be a number, not boolean")
                    w_val = float(raw_w)
                    if not math.isfinite(w_val) or w_val <= 0:
                        raise ValueError("must be positive")
                    new_weight = max(0.1, w_val)
                except (TypeError, ValueError, OverflowError):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid weight"})
                    return
            if "notes" in body:
                new_notes = str(body["notes"] or "")[:240]

            with ctrl.config_lock:
                target_node = next((n for n in ctrl.config.nodes if n.id == node_id), None)
                if target_node is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": f"node '{node_id}' not found"})
                    return
                prev_node_fields = (
                    target_node.tier,
                    target_node.pool,
                    target_node.max_concurrency,
                    target_node.weight,
                    target_node.notes,
                )
                if new_tier is not None:
                    target_node.tier = new_tier
                if new_pool is not None:
                    target_node.pool = new_pool
                if new_mc is not None:
                    target_node.max_concurrency = new_mc
                if new_weight is not None:
                    target_node.weight = new_weight
                if new_notes is not None:
                    target_node.notes = new_notes

                def _rb_node_upd() -> None:
                    (
                        target_node.tier,
                        target_node.pool,
                        target_node.max_concurrency,
                        target_node.weight,
                        target_node.notes,
                    ) = prev_node_fields

                if not self._save_config_or_rollback(_rb_node_upd):
                    return
                updated_rec = {
                    "id": target_node.id,
                    "tier": target_node.tier,
                    "pool": target_node.pool,
                    "max_concurrency": target_node.max_concurrency,
                    "weight": target_node.weight,
                }
            pushed = ctrl.push_config_to_all(node_ids=[node_id])
            self._send_json(HTTPStatus.OK, {"node": updated_rec, "pushed": pushed})

        elif path == "/api/nodes/remove":
            node_id = str(body.get("id") or "").strip()
            if not node_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing node id"})
                return
            with ctrl.config_lock:
                target_node = next((n for n in ctrl.config.nodes if n.id == node_id), None)
                if target_node is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": f"node '{node_id}' not found"})
                    return
                if target_node.role == "master":
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "cannot remove the master node"})
                    return
                if len(ctrl.config.nodes) <= 1:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "cannot remove the last remaining node in cluster"})
                    return
                prev_nodes = list(ctrl.config.nodes)
                prev_q_nodes = list(ctrl.config.gateway.quarantined_nodes)
                ctrl.config.nodes = [n for n in ctrl.config.nodes if n.id != node_id]
                if node_id in ctrl.config.gateway.quarantined_nodes:
                    ctrl.config.gateway.quarantined_nodes = [
                        q for q in ctrl.config.gateway.quarantined_nodes if q != node_id
                    ]

                def _rb_node_rm() -> None:
                    ctrl.config.nodes = prev_nodes
                    ctrl.config.gateway.quarantined_nodes = prev_q_nodes

                if not self._save_config_or_rollback(_rb_node_rm):
                    return
            self.server.gateway_manager.disconnect_node(node_id)
            self._send_json(HTTPStatus.OK, {"removed": node_id})

        elif path == "/api/settings":
            with ctrl.config_lock:
                cur_s = ctrl.config.safety

                def _set_val(k: str, fallback: Any) -> Any:
                    v = body.get(k)
                    return fallback if v is None else v

                try:
                    updated = SafetyConfig.from_dict(
                        {
                            "max_temp_c": _set_val("max_temp_c", cur_s.max_temp_c),
                            "resume_temp_c": _set_val("resume_temp_c", cur_s.resume_temp_c),
                            "min_free_ram_mb": _set_val("min_free_ram_mb", cur_s.min_free_ram_mb),
                            "battery_low_pct": _set_val("battery_low_pct", cur_s.battery_low_pct),
                            "battery_high_pct": _set_val("battery_high_pct", cur_s.battery_high_pct),
                            "battery_poll_sec": cur_s.battery_poll_sec,
                            "webhook_cooldown_sec": cur_s.webhook_cooldown_sec,
                            "battery_webhook_url": _set_val("battery_webhook_url", cur_s.battery_webhook_url),
                        }
                    )
                except (ValueError, TypeError, OverflowError) as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                if updated.battery_webhook_url and is_webhook_target_unsafe(updated.battery_webhook_url):
                    self._send_json(
                        HTTPStatus.BAD_REQUEST,
                        {"error": "webhook URL blocked by SSRF guard (link-local, cloud metadata, unspecified, or multicast targets are disallowed)"},
                    )
                    return
                ctrl.config.safety = updated

                def _rb_safety() -> None:
                    ctrl.config.safety = cur_s

                if not self._save_config_or_rollback(_rb_safety):
                    return
            pushed = ctrl.push_config_to_all()
            self._send_json(HTTPStatus.OK, {"saved": True, "pushed": pushed})

        elif path == "/api/settings/test-webhook":
            url = str(body.get("battery_webhook_url") or ctrl.config.safety.battery_webhook_url).strip()
            try:
                p_url = urllib.parse.urlsplit(url)
                _ = p_url.port
            except ValueError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "enter a valid http:// or https:// webhook URL"})
                return
            if (
                not url
                or any(c.isspace() or ord(c) < 32 for c in url)
                or p_url.scheme.lower() not in {"http", "https"}
                or not p_url.hostname
            ):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "enter a valid http:// or https:// webhook URL"})
                return
            if is_webhook_target_unsafe(url):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "webhook URL blocked by SSRF guard (link-local, cloud metadata, unspecified, or multicast targets are disallowed)"},
                )
                return
            test_payload = {
                "event": "test",
                "node_id": "master",
                "message": "PhoneCluster test battery/thermal webhook notification.",
                "timestamp": int(time.time()),
            }
            req = urllib.request.Request(
                url,
                data=safe_json_dumps(test_payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with _WEBHOOK_OPENER.open(req, timeout=5.0) as resp:
                    resp.read(1024)
                    self._send_json(HTTPStatus.OK, {"delivered": True, "http_status": resp.status})
            except urllib.error.HTTPError as exc:
                code = exc.code
                try:
                    exc.close()
                except OSError:
                    pass
                self._send_json(HTTPStatus.BAD_GATEWAY, {"error": f"webhook returned HTTP {code}"})
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
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

    sigterm_event = threading.Event()
    watcher_stop = threading.Event()

    def _sigterm_watcher() -> None:
        while not watcher_stop.is_set():
            if sigterm_event.wait(timeout=0.25):
                LOG.info("Received SIGTERM; shutting down Master Dashboard...")
                stop_event.set()
                server.shutdown()
                return

    threading.Thread(target=_sigterm_watcher, name="dashboard-sigterm", daemon=True).start()

    def _handle_sigterm(_signum: int, _frame: Any) -> None:
        sigterm_event.set()

    try:
        signal.signal(signal.SIGTERM, _handle_sigterm)
    except ValueError:
        pass  # Not on main thread

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
        watcher_stop.set()
        stop_event.set()
        server.server_close()
