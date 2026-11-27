"""Pass 15 regression tests: Web Control Center & TUI hardening, CSRF/SSRF/DoS guards, and UI QoL."""

from __future__ import annotations

import http.client
import json
import re
import threading
import urllib.error
import urllib.request
from pathlib import Path
from unittest import TestCase, mock

from phonecluster.auth import build_auth_headers
from phonecluster.config import ClusterConfig, GatewayConfig, NodeConfig, create_default_config, save_config
from phonecluster.dashboard import DASHBOARD_HTML, DashboardHTTPServer
from phonecluster.master import MasterController, NodeSnapshot
from phonecluster.tui import (
    _build_node_inspect_banner,
    _clean_term_text,
    _sort_nodes_for_tui,
    _truncate_ansi,
    render_top_frame,
)


def _open_json(req: urllib.request.Request) -> tuple[int, dict, dict]:
    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            raw = resp.read().decode("utf-8")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, hdrs, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        hdrs = {k.lower(): v for k, v in exc.headers.items()}
        code = exc.code
        exc.close()
        return code, hdrs, json.loads(raw) if raw else {}


class TestPass15DashboardBackendHardening(TestCase):
    def setUp(self) -> None:
        self.cfg = create_default_config(master_host="127.0.0.1", worker_hosts=["192.168.1.50"])
        self.cfg.nodes[0].ssh_user = "master_secret_user"
        self.cfg.nodes[1].ssh_user = "worker_secret_user"
        self.cfg.dashboard_require_auth = False
        self.token = self.cfg.auth_token
        self.ctrl = MasterController(self.cfg)
        self.fake_snaps = [
            NodeSnapshot(
                node=self.cfg.nodes[0],
                online=True,
                latency_ms=1.2,
                health={
                    "ready_for_jobs": True,
                    "cpu_cores": 4,
                    "cpu_pct": 12.5,
                    "mem_total_mb": 4096,
                    "mem_available_mb": 2048,
                    "temp_c": 33.0,
                    "docker_volume_root": "/home/secret_master/phonecluster/docker-data",
                },
            ),
            NodeSnapshot(
                node=self.cfg.nodes[1],
                online=True,
                latency_ms=2.4,
                health={
                    "ready_for_jobs": True,
                    "cpu_cores": 8,
                    "cpu_pct": 44.0,
                    "mem_total_mb": 6144,
                    "mem_available_mb": 3072,
                    "temp_c": 36.0,
                    "docker_volume_root": "/home/phablet/phonecluster/docker-data",
                },
            ),
        ]
        self.poll_patcher = mock.patch.object(self.ctrl, "poll_health", return_value=self.fake_snaps)
        self.jobs_patcher = mock.patch.object(
            self.ctrl,
            "get_all_jobs",
            return_value=[{"node_id": "node0", "online": True, "active": [], "recent": []}],
        )
        self.poll_patcher.start()
        self.jobs_patcher.start()
        self.dash = DashboardHTTPServer(
            ("127.0.0.1", 0),
            self.ctrl,
            enable_pairing_beacon=False,
            enable_usb_watchdog=False,
        )
        self.port = self.dash.server_address[1]
        self.thread = threading.Thread(target=self.dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.dash.shutdown()
        self.dash.server_close()
        self.thread.join(timeout=2.0)
        self.poll_patcher.stop()
        self.jobs_patcher.stop()

    def test_security_headers_parity_across_get_head_and_unsupported_methods(self) -> None:
        # 1. GET / HTML has full headers including object-src 'none', COOP, CORP, Permissions-Policy, Cache-Control
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=3.0) as resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            self.assertEqual(hdrs.get("x-content-type-options"), "nosniff")
            self.assertEqual(hdrs.get("x-frame-options"), "DENY")
            self.assertEqual(hdrs.get("referrer-policy"), "no-referrer")
            self.assertEqual(hdrs.get("cross-origin-resource-policy"), "same-origin")
            self.assertEqual(hdrs.get("cross-origin-opener-policy"), "same-origin")
            self.assertEqual(hdrs.get("cache-control"), "no-store")
            self.assertIn("camera=()", hdrs.get("permissions-policy", ""))
            self.assertIn("object-src 'none'", hdrs.get("content-security-policy", ""))

        # 2. HEAD / mirrors CSP, COOP, CORP, Permissions-Policy; HEAD /missing also emits security headers
        for path, want_code in [("/", 200), ("/nonexistent", 404)]:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3.0)
            try:
                conn.request("HEAD", path)
                res = conn.getresponse()
                res.read()
                self.assertEqual(res.status, want_code)
                self.assertEqual(res.getheader("X-Frame-Options"), "DENY")
                self.assertEqual(res.getheader("Cross-Origin-Resource-Policy"), "same-origin")
                self.assertIn("camera=()", res.getheader("Permissions-Policy") or "")
                if want_code == 200:
                    self.assertIn("object-src 'none'", res.getheader("Content-Security-Policy") or "")
                    self.assertEqual(res.getheader("Cross-Origin-Opener-Policy"), "same-origin")
            finally:
                conn.close()

        # 3. Unsupported method PUT returns JSON 501 with full security headers (not bare HTML)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3.0)
        try:
            conn.request("PUT", "/api/exec", body=b"{}")
            res = conn.getresponse()
            raw = res.read().decode("utf-8")
            self.assertEqual(res.status, 501)
            self.assertEqual(res.getheader("Content-Type"), "application/json")
            self.assertEqual(res.getheader("X-Frame-Options"), "DENY")
            self.assertIn("error", json.loads(raw))
        finally:
            conn.close()

    def test_cross_site_and_same_site_get_blocked_before_auth_rate_limiter(self) -> None:
        # 15 cross-site & same-site GETs to /api/auth/verify must be rejected with 403 BEFORE rate_limiter!
        for i in range(15):
            sfs = "cross-site" if i % 2 == 0 else "same-site"
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.port}/api/auth/verify",
                headers={"Sec-Fetch-Site": sfs},
            )
            code, _, data = _open_json(req)
            self.assertEqual(code, 403)
            self.assertIn("cross-origin", data.get("error", ""))

        # Legitimate admin token must NOT be locked out (still 200 OK!)
        req_ok = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/auth/verify",
            headers={**build_auth_headers(self.token), "Sec-Fetch-Site": "same-origin"},
        )
        code, _, data = _open_json(req_ok)
        self.assertEqual(code, 200)
        self.assertTrue(data.get("valid"))

        # Duplicate Sec-Fetch-Site / Origin headers rejected on POST
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3.0)
        try:
            conn.putrequest("POST", "/api/gateway/logs/clear")
            conn.putheader("Host", f"127.0.0.1:{self.port}")
            conn.putheader("Origin", f"http://127.0.0.1:{self.port}")
            conn.putheader("Origin", "http://evil.example")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Authorization", f"Bearer {self.token}")
            conn.putheader("Content-Length", "2")
            conn.endheaders()
            conn.send(b"{}")
            res = conn.getresponse()
            res.read()
            self.assertEqual(res.status, 403)
        finally:
            conn.close()

    def test_content_type_enforcement_and_pair_complete_hardening(self) -> None:
        # 1. text/plain POST rejected with 415 Unsupported Media Type
        req_txt = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/gateway/logs/clear",
            data=b"{}",
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "text/plain"},
            method="POST",
        )
        code, _, _ = _open_json(req_txt)
        self.assertEqual(code, 415)

        # 2. Browser POST with Origin but no Content-Type rejected with 415
        req_no_ct = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/gateway/logs/clear",
            data=b"{}",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Origin": f"http://127.0.0.1:{self.port}",
            },
            method="POST",
        )
        code, _, _ = _open_json(req_no_ct)
        self.assertEqual(code, 415)

        # 3. /api/pair/complete rejects ANY browser Origin/Sec-Fetch-Site and enforces 64 KiB body cap
        req_browser_pair = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/pair/complete",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{self.port}",
            },
            method="POST",
        )
        code, _, _ = _open_json(req_browser_pair)
        self.assertEqual(code, 403)

        big_payload = b'{"x":"' + (b"a" * 70000) + b'"}'
        req_big_pair = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/pair/complete",
            data=big_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        code, _, _ = _open_json(req_big_pair)
        self.assertEqual(code, 413)

    def test_sensitive_scan_audit_endpoints_require_auth_and_readonly_redacts_secrets(self) -> None:
        # Even when dashboard_require_auth=False, sensitive endpoints MUST reject unauthenticated GETs!
        for path in (
            "/api/discover",
            "/api/usb-hub",
            "/api/gateway/status",
            "/api/doctor",
            "/api/network/audit",
        ):
            req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
            code, _, _ = _open_json(req)
            self.assertEqual(code, 401, f"Expected 401 on unauthenticated GET {path}")

        # Reset rate limiter before authenticated checks
        self.dash.rate_limiter.record_success("127.0.0.1")

        # Unauthenticated Read-Only /api/status and /api/live strip ssh_user and health.docker_volume_root
        code, _, st_unauth = _open_json(urllib.request.Request(f"http://127.0.0.1:{self.port}/api/status"))
        self.assertEqual(code, 200)
        for n in st_unauth["nodes"]:
            self.assertNotIn("ssh_user", n)
            self.assertNotIn("docker_volume_root", n.get("health") or {})

        code, _, live_unauth = _open_json(urllib.request.Request(f"http://127.0.0.1:{self.port}/api/live"))
        self.assertEqual(code, 200)
        for n in live_unauth["summary"]["nodes"]:
            self.assertNotIn("ssh_user", n)
            self.assertNotIn("docker_volume_root", n.get("health") or {})

        # Authenticated /api/status preserves ssh_user and docker_volume_root
        req_st_auth = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/status",
            headers=build_auth_headers(self.token),
        )
        code, _, st_auth = _open_json(req_st_auth)
        self.assertEqual(code, 200)
        self.assertEqual(st_auth["nodes"][0]["ssh_user"], "master_secret_user")
        self.assertIn("docker_volume_root", st_auth["nodes"][0]["health"])

    def test_post_validation_ssrf_overflow_and_top_level_500_safety(self) -> None:
        def post(path: str, body: dict) -> tuple[int, dict]:
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.port}{path}",
                data=json.dumps(body).encode("utf-8"),
                headers={**build_auth_headers(self.token), "Content-Type": "application/json"},
                method="POST",
            )
            code, _, data = _open_json(req)
            return code, data

        # 1. /api/services/custom blocks credentials, metadata SSRF, and malformed hostnames
        code, _ = post("/api/services/custom", {"name": "creds", "url": "http://admin:secret@192.168.1.5:8080"})
        self.assertEqual(code, 400)
        code, _ = post("/api/services/custom", {"name": "imds", "url": "tcp://169.254.169.254:80"})
        self.assertEqual(code, 400)
        code, _ = post("/api/services/custom", {"name": "badhost", "url": "http://bad_host!:8080"})
        self.assertEqual(code, 400)
        code, _ = post("/api/services/custom", {"name": "lanapp", "url": "http://192.168.1.50:9000"})
        self.assertEqual(code, 200)

        # 2. /api/services/probe blocks metadata IP directly
        code, _ = post("/api/services/probe", {"host": "169.254.169.254", "port": 80})
        self.assertEqual(code, 403)

        # 3. /api/usb-hub/watchdog huge int returns 400 JSON (no OverflowError / RemoteDisconnected!)
        code, data = post("/api/usb-hub/watchdog", {"enabled": True, "interval_sec": 10**400})
        self.assertEqual(code, 400)
        self.assertIn("error", data)
        code, _ = post("/api/usb-hub/watchdog", {"enabled": True, "interval_sec": True})
        self.assertEqual(code, 400)
        code, _ = post("/api/usb-hub/watchdog", {"enabled": "false"})
        self.assertEqual(code, 400)

        # 4. /api/exec, /api/terminal/exec, /api/map strict type & mode validation
        code, _ = post("/api/exec", {"command": ["echo", "hi"]})
        self.assertEqual(code, 400)
        code, _ = post("/api/terminal/exec", {"command": "echo hi", "job_id": "bad\x1b[31m"})
        self.assertEqual(code, 400)
        code, _ = post("/api/map", {"mode": "bogus", "commands": ["echo hi"]})
        self.assertEqual(code, 400)

        # 5. /api/nodes/add & /api/nodes/update reject out-of-range concurrency/weight & strip control chars in notes
        code, _ = post("/api/nodes/add", {"host": "192.168.1.60", "max_concurrency": 999})
        self.assertEqual(code, 400)
        code, _ = post("/api/nodes/add", {"host": "192.168.1.60", "weight": 1e300})
        self.assertEqual(code, 400)
        with mock.patch.object(self.ctrl, "push_config_to_all", return_value={"total": 1, "ok_count": 1, "persisted_count": 1}):
            code, _ = post("/api/nodes/update", {"id": "node1", "notes": "Shelf\x00\x1b[31m\x9b 2"})
        self.assertEqual(code, 200)
        self.assertEqual(self.cfg.get_node("node1").notes, "Shelf[31m 2")

        # 6. Top-level unexpected exception returns clean 500 JSON (never drops socket or leaks stack trace)
        with mock.patch.object(self.ctrl, "get_services_info", side_effect=RuntimeError("/secret/internal/path boom")):
            code, _, err_data = _open_json(urllib.request.Request(f"http://127.0.0.1:{self.port}/api/services"))
        self.assertEqual(code, 500)
        self.assertEqual(err_data, {"error": "internal server error"})

        # 7. Per-IP connection slot tracker enforces cap on non-loopback IPs
        self.dash._max_conns_per_ip = 2
        k1 = self.dash._acquire_ip_slot(("192.168.1.99", 12345))
        k2 = self.dash._acquire_ip_slot(("192.168.1.99", 12346))
        k3 = self.dash._acquire_ip_slot(("192.168.1.99", 12347))
        self.assertIsNotNone(k1)
        self.assertIsNotNone(k2)
        self.assertIsNone(k3)
        self.dash._release_ip_slot(k1)
        self.dash._release_ip_slot(k2)


class TestPass15FrontendAndTuiHardening(TestCase):
    def test_dashboard_html_hardening_qol_and_vm_isolation_invariants(self) -> None:
        html = DASHBOARD_HTML
        script_m = re.search(r"<script>([\s\S]*?)</script>", html)
        self.assertIsNotNone(script_m)
        js = script_m.group(1)

        # Security & UX primitives present
        for marker in (
            "function safeHttpUrl(",
            "function handleAuthFailure(",
            "function scrubSensitiveDom(",
            "function confirmAction(",
            "async function withBusyAction(",
            "AbortController",
            "visibilitychange",
            'autocomplete="off"',
            "QUARANTINED · OFFLINE",
            "@media (max-width: 640px)",
            "@media (pointer: coarse)",
            "minmax(min(100%, 340px), 1fr)",
            'id="node-search"',
            'id="node-status-filter"',
            'id="node-sort"',
            'id="term-status-pill"',
            "onTermScreenClick()",
            "copyTermLog()",
            'id="map-job-count"',
            'id="map-filter-bar"',
            'id="wl-action-summary"',
            'id="gw-log-search"',
            'id="gw-log-action"',
            "highlightActiveProfile()",
            'id="shortcuts-modal"',
            "pc_setup_mode",
            'id="doctor-toolbar"',
            "copyPairPin()",
            'id="ed-notes"',
        ):
            self.assertIn(marker, html, f"Expected UI hardening/QoL marker missing: {marker}")

        # All static DOM IDs referenced via getElementById('...') exist
        ids = set(re.findall(r'id=["\']([a-zA-Z0-9_-]+)["\']', html))
        refs = set(re.findall(r"getElementById\('([a-zA-Z0-9_-]+)'\)", js))
        self.assertEqual(sorted(refs - ids), [])

        # Node VM test (tests/check_dashboard_actions.mjs) functions extract cleanly & stay isolated
        for name in ("formatJobOutput", "runParallelMap", "downloadLastMapJson", "workloadAction"):
            m = re.search(rf"^(?:async )?function {name}\([^\n]*\n[\s\S]*?^\}}", html, re.M)
            self.assertIsNotNone(m, f"Function {name} failed VM regex extraction")
            body = m.group(0)
            for forbidden in ("withBusyAction", "confirmAction", "inFlightActions", "hasOwn", "safeHttpUrl", "copyText", "handleAuthFailure"):
                self.assertIsNone(re.search(rf"\b{forbidden}\b", body), f"Forbidden outer ref {forbidden} in {name}")

    def test_tui_c1_escape_sanitization_compact_layout_help_sort_and_inspect(self) -> None:
        # 1. C1 8-bit CSI/OSC, 7-bit DCS/APC, and BiDi override stripped cleanly
        poisoned = "ok\x9b31mRED\x9d52;c;YWFh\x9c\x1bP1$rpayload\x1b\\\u202eevil"
        cleaned = _clean_term_text(poisoned)
        self.assertNotIn("\x9b", cleaned)
        self.assertNotIn("\x9d", cleaned)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\u202e", cleaned)
        self.assertNotIn("payload", cleaned)
        self.assertIn("ok", cleaned)

        # 2. ANSI-preserving truncation keeps color escape & ends with reset
        colored = "\033[1;38;5;78mREADY_SUPER_LONG_TEXT_HERE\033[0m"
        trunc = _truncate_ansi(colored, 10)
        self.assertIn("\033[1;38;5;78m", trunc)
        self.assertTrue(trunc.endswith("…\033[0m"))

        # 3. render_top_frame sanitizes poisoned SVCS/POOLS/node fields, renders live last_output,
        #    supports compact narrow Termux widths, sort_by, show_help, and inspect banner
        summary = {
            "cluster_name": "lab\x9b2J",
            "nodes_ready": 2,
            "nodes_total": 2,
            "total_cores": 12,
            "cluster_cpu_pct": 55.0,
            "cluster_ram_pct": 42.0,
            "mem_total_mb": 8192,
            "mem_available_mb": 4096,
            "max_temp_c": 38.5,
            "avg_latency_ms": 2.1,
            "total_active_jobs": 1,
            "pools": [{"tier": 1, "pool": "comp\x9b31m", "nodes_ready": 2, "nodes_total": 2, "total_cores": 12}],
            "services_registry": [{"name": "mqtt\x1b]52;c;evil\x07", "node_id": "n1\x9b2J"}],
            "nodes": [
                {
                    "id": "cool",
                    "host": "127.0.0.1",
                    "worker_port": 18761,
                    "role": "worker",
                    "tier": 1,
                    "pool": "compute",
                    "tags": ["usb-hub", "usb-mode:adb"],
                    "notes": "USB slot 1",
                    "online": True,
                    "ready_for_jobs": True,
                    "latency_ms": 1.2,
                    "health": {
                        "cpu_pct": 15.0,
                        "temp_c": 31.0,
                        "mem_total_mb": 4096,
                        "mem_available_mb": 3000,
                        "active_jobs": 0,
                        "max_concurrency": 2,
                        "disk_free_gb": 14.5,
                        "listening_ports": [{"port": 8765}],
                    },
                },
                {
                    "id": "hot",
                    "host": "192.168.1.42",
                    "role": "worker",
                    "tier": 3,
                    "pool": "docker",
                    "online": True,
                    "ready_for_jobs": True,
                    "latency_ms": 3.5,
                    "health": {
                        "cpu_pct": 88.0,
                        "temp_c": 38.5,
                        "mem_total_mb": 4096,
                        "mem_available_mb": 512,
                        "active_jobs": 1,
                        "max_concurrency": 2,
                        "active_job_list": [
                            {"job_id": "j1", "running_sec": 4.2, "command": "python3 train.py", "last_output": "epoch 3/10 loss=0.12"}
                        ],
                    },
                },
            ],
        }
        all_jobs = [
            {
                "node_id": "hot",
                "active": [{"job_id": "j1", "running_sec": 4.2, "command": "python3 train.py", "last_output": "epoch 3/10 loss=0.12"}],
                "recent": [],
            }
        ]
        # Sorting by cpu puts 'hot' ahead of 'cool'
        sorted_cpu = _sort_nodes_for_tui(summary["nodes"], sort_by="cpu")
        self.assertEqual([n["id"] for n in sorted_cpu], ["hot", "cool"])

        # Wide render includes live last_output preview & zero raw ESC/C1 leakage from poisoned inputs
        frame = render_top_frame(summary, {}, all_jobs, width=110, height=34, use_color=False, sort_by="cpu")
        self.assertNotIn("\x9b", frame)
        self.assertNotIn("\x1b", frame)
        self.assertIn("epoch 3/10 loss=0.12", frame)
        self.assertIn("SORT:CPU", frame)

        # Compact narrow Termux render keeps usb:18761 visible and preserves color codes
        narrow = render_top_frame(summary, {}, all_jobs, width=52, height=22, use_color=True)
        self.assertIn("usb:18761", narrow)

        # Interactive help overlay
        help_frame = render_top_frame(summary, {}, all_jobs, width=96, height=28, use_color=False, show_help=True)
        self.assertIn("KEYBINDINGS & SHORTCUTS", help_frame)
        self.assertIn("Inspect selected phone", help_frame)

        # Inspect banner
        banner = _build_node_inspect_banner(summary["nodes"][0], all_jobs)
        self.assertIn("Inspect cool", banner)
        self.assertIn("USB slot 1", banner)
        self.assertIn("14.5GB free", banner)
