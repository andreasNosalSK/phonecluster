"""Pass 14 regression tests covering deep bug fixes and high-impact QoL improvements."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import stat
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from phonecluster.auth import (
    build_signed_auth_headers,
    read_json_object_bounded,
    verify_hmac_request,
)
from phonecluster.cli import main as cli_main
from phonecluster.config import (
    AdbNodeConfig,
    ClusterConfig,
    NodeConfig,
    SafetyConfig,
    create_default_config,
    load_config,
    save_config,
)
from phonecluster.dashboard import DashboardHTTPServer
from phonecluster.discovery import discover_lan_nodes
from phonecluster.doctor import run_doctor
from phonecluster.gateway import (
    GatewayAuditLog,
    NetworkGuardServer,
    _is_disallowed_ip,
    build_worker_proxy_env,
    derive_proxy_password,
)
from phonecluster.master import MasterController, NodeSnapshot
from phonecluster.netguard import KNOWN_CLUSTER_PORTS, build_firewall_guides, detect_controller_host_info
from phonecluster.pairing import PairingManager, join_cluster_via_pairing
from phonecluster.routing import build_cross_tier_env
from phonecluster.telemetry import (
    ThermalGate,
    collect_node_health,
    detect_capabilities,
    detect_node_tier,
    read_battery_via_sysfs,
)
from phonecluster.tui import render_top_frame
from phonecluster.usbhub import (
    UsbHubWatchdog,
    apply_adb_usb_hub,
    build_rndis_router_commands,
    detect_subnet_collisions,
    generate_usb_hub_systemd_unit,
    plan_adb_usb_hub,
    plan_rndis_usb_hub,
    probe_adb_device_profile,
    sync_usb_hub_into_config,
    verify_usb_hub_connectivity,
)
from phonecluster.worker import WorkerHTTPServer, WorkerState


class TestPass14CoreAndWorkerFixes(unittest.TestCase):
    def test_tilde_config_load_and_dangling_symlink_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            cfg = create_default_config(worker_hosts=[])
            with patch.dict(os.environ, {"HOME": str(fake_home)}):
                save_config(cfg, "~/my-cluster.json")
                self.assertTrue((fake_home / "my-cluster.json").is_file())
                loaded = load_config("~/my-cluster.json")
                self.assertEqual(loaded.cluster_name, cfg.cluster_name)

            dangling = Path(tmp) / "dangling.json"
            dangling.symlink_to(Path(tmp) / "does-not-exist.json")
            with self.assertRaises(ValueError):
                load_config(dangling)

    def test_master_self_push_does_not_skew_shared_cluster_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cluster.json"
            cfg = create_default_config(master_host="127.0.0.1", worker_hosts=[])
            save_config(cfg, cfg_path)
            cfg = load_config(cfg_path)
            node0 = cfg.nodes[0]

            state = WorkerState(
                node_id=node0.id,
                role="master",
                auth_token=cfg.auth_token,
                safety=cfg.safety,
                max_concurrency=node0.max_concurrency,
                config_path=cfg_path,
            )
            srv = WorkerHTTPServer(("127.0.0.1", 0), state)
            node0.worker_port = srv.server_address[1]
            save_config(cfg, cfg_path)
            cfg = load_config(cfg_path)
            rev_before = cfg_path.read_bytes()

            th = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            th.start()
            try:
                ctrl = MasterController(cfg)
                push_res = ctrl.push_config_to_all()
                self.assertEqual(push_res["ok_count"], 1)
                self.assertEqual(push_res["persisted_count"], 1)
                # Master's cluster.json bytes must remain untouched -> no ConfigConflictError on next save!
                self.assertEqual(cfg_path.read_bytes(), rev_before)
                cfg.safety.max_temp_c = 39.5
                save_config(cfg, cfg_path)
            finally:
                srv.shutdown()
                srv.server_close()
                th.join(timeout=2.0)

    def test_read_json_object_bounded_uses_read1_and_clock_skew_auth_diagnostic(self) -> None:
        # 1. Slow response with read1() is aborted promptly at deadline_sec instead of blocking inside read(16384)
        class _ChunkedRead1Resp:
            def read1(self, _n: int = -1) -> bytes:
                time.sleep(0.06)
                return b"{"

            def read(self, _n: int = -1) -> bytes:
                raise AssertionError("read() should not be called when read1() exists")

        t0 = time.monotonic()
        with self.assertRaises(TimeoutError):
            read_json_object_bounded(_ChunkedRead1Resp(), 4096, deadline_sec=0.15)
        self.assertLess(time.monotonic() - t0, 1.0)

        # 2. Genuine Master HMAC with drifted clock gets clear clock-skew diagnosis WITHOUT IP ban,
        # while spoofed signature with drifted timestamp gets generic invalid signature AND increments rate_limiter.
        token = "strong-test-token-1234567890"
        state = WorkerState("node1", "worker", token, SafetyConfig())
        srv = WorkerHTTPServer(("127.0.0.1", 0), state)
        th = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        th.start()
        try:
            port = srv.server_address[1]
            # Verify pure auth helper message directly
            drifted_ts = int(time.time()) + 300
            hdrs_real = build_signed_auth_headers(token, "GET", "/health", b"", ts=drifted_ts)
            ok, reason = verify_hmac_request(hdrs_real, "GET", "/health", b"", token)
            self.assertFalse(ok)
            self.assertIn("clock skew", reason)

            # Send 12 drifted requests with valid token — must NEVER trigger HTTP 429 lockout
            for _ in range(12):
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/health",
                    headers=build_signed_auth_headers(token, "GET", "/health", b"", ts=drifted_ts),
                    method="GET",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req, timeout=2.0)
                self.assertEqual(ctx.exception.code, 401)
                body = json.loads(ctx.exception.read().decode("utf-8"))
                ctx.exception.close()
                self.assertIn("clock skew", body["error"])
                self.assertIn("clock_skew_sec", body)

            # Spoofed wrong-token drifted request MUST record rate-limiter failure and NOT claim clock skew
            req_bad = urllib.request.Request(
                f"http://127.0.0.1:{port}/health",
                headers=build_signed_auth_headers("wrong-token-abcdef", "GET", "/health", b"", ts=drifted_ts),
                method="GET",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx_bad:
                urllib.request.urlopen(req_bad, timeout=2.0)
            self.assertEqual(ctx_bad.exception.code, 401)
            bad_body = json.loads(ctx_bad.exception.read().decode("utf-8"))
            ctx_bad.exception.close()
            self.assertNotIn("clock skew", bad_body["error"])
        finally:
            srv.shutdown()
            srv.server_close()
            th.join(timeout=2.0)

    def test_telemetry_sysfs_upower_fallback_podman_split_and_thermal_hysteresis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ps = Path(tmp)
            # Peripheral mouse battery must be skipped
            mouse = ps / "hidpp_battery_0"
            mouse.mkdir()
            (mouse / "type").write_text("Battery\n", encoding="utf-8")
            (mouse / "scope").write_text("Device\n", encoding="utf-8")
            (mouse / "capacity").write_text("90\n", encoding="utf-8")
            # Restricted system battery dir (all reads fail / missing) -> returns None so UPower fallback runs
            bat = ps / "battery"
            bat.mkdir()
            self.assertIsNone(read_battery_via_sysfs(ps))

        # Podman-only node must NOT set tools["docker"] = True, while still classifying Tier 3 if podman socket exists
        with (
            patch("phonecluster.telemetry.find_executable", side_effect=lambda name: "/usr/bin/podman" if name == "podman" else None),
            patch("phonecluster.telemetry.SNAP_BIN_DIR", Path("/nonexistent-snap-bin")),
            patch("phonecluster.telemetry._read_listening_tcp_map", return_value={}),
        ):
            caps = detect_capabilities(listening_map={})
            self.assertFalse(caps["tools"]["docker"])
            self.assertTrue(caps["tools"]["podman"])
            tier, pool = detect_node_tier("debian-13", caps["tools"], docker_runtime={"socket_exists": True})
            self.assertEqual((tier, pool), (3, "docker"))

        # Thermal hysteresis cooldown reason must not falsely say "38.5C >= 40.0C"
        gate = ThermalGate(max_temp_c=40.0, resume_temp_c=37.0)
        gate.evaluate(41.0)
        safety = SafetyConfig(max_temp_c=40.0, resume_temp_c=37.0)
        with patch("phonecluster.telemetry.read_battery_info") as mock_bat:
            mock_bat.return_value = type(
                "B", (), {"percentage": 55, "temperature_c": 38.5, "status": "DISCHARGING", "health": "GOOD", "plugged": "UNPLUGGED", "source": "sysfs"}
            )()
            h = collect_node_health("n1", "worker", safety, gate, safety_only=True)
            self.assertTrue(h["overheated"])
            self.assertTrue(any("cooling down (38.5C > 37.0C resume)" in r for r in h["not_ready_reasons"]))


class TestPass14NetworkUsbAndPairingFixes(unittest.TestCase):
    def test_gateway_nat64_local_ssrf_loopback_ratelimit_and_lifetime_stats(self) -> None:
        # RFC 8215 local-use NAT64 & Python 3.9 parity blocks
        self.assertTrue(_is_disallowed_ip("64:ff9b:1::8.8.8.8"))
        self.assertTrue(_is_disallowed_ip("64:ff9b:1:7f00:0001::8.8.8.8"))
        self.assertTrue(_is_disallowed_ip("192.0.0.1"))
        self.assertTrue(_is_disallowed_ip("100.64.0.1"))

        # Lifetime per-node counters survive ring-buffer rotation
        log = GatewayAuditLog(maxlen=5)
        for i in range(12):
            log.record(
                node_id="node1",
                client_ip="192.168.1.202",
                method="CONNECT",
                host=f"h{i}.example.com",
                port=443,
                action="allow",
                reason="ok",
                bytes_in=10,
                bytes_out=20,
            )
        snap = log.snapshot()
        self.assertEqual(len(snap["events"]), 5)
        self.assertEqual(snap["per_node"]["node1"]["allowed"], 12)
        self.assertEqual(snap["per_node"]["node1"]["bytes_in"], 120)

        # URL-encoded username on loopback shares canonical rate-limit bucket & gives uniform 407 error
        cfg = create_default_config(master_host="127.0.0.1", worker_hosts=[])
        cfg.nodes.append(NodeConfig("usb1", "127.0.0.1", role="worker", worker_port=18761, ssh_port=18021, auth_token="tok-usb1-1234567890"))
        srv = NetworkGuardServer(("127.0.0.1", 0), cfg, GatewayAuditLog())
        try:
            def _auth(user: str, pw: str) -> tuple[str | None, str]:
                raw = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
                return srv.authenticate_worker({"proxy-authorization": f"Basic {raw}"}, "127.0.0.1")

            for _ in range(15):
                nid, msg = _auth("usb1", "bad-secret")
                self.assertIsNone(nid)
                self.assertEqual(msg, "invalid proxy credentials")
            # %75sb1 decodes to usb1 -> MUST be rate-limited immediately!
            nid_enc, msg_enc = _auth("%75sb1", "bad-secret")
            self.assertIsNone(nid_enc)
            self.assertIn("rate limited", msg_enc)

            # Unknown user returns same uniform message (no node-ID enumeration)
            nid_unk, msg_unk = _auth("no-such-node", "bad")
            self.assertIsNone(nid_unk)
            self.assertEqual(msg_unk, "invalid proxy credentials")
        finally:
            srv.server_close()

        # RNDIS proxy env prefers .1 USB gateway even when master_host LAN IP is passed
        cfg.gateway.enabled = True
        cfg.gateway.port = 8888
        rndis_node = NodeConfig("usb2", "10.77.2.2", role="worker", tags=["worker", "usb-hub", "usb-mode:rndis"], auth_token="tok-rndis-1234567890")
        cfg.nodes.append(rndis_node)
        env = build_worker_proxy_env(cfg, rndis_node, master_host="192.168.1.201")
        self.assertIn("@10.77.2.1:8888", env["HTTP_PROXY"])

    def test_usbhub_probe_systemd_quarantine_verify_and_rndis_fixes(self) -> None:
        # 1. probe_adb_device_profile succeeds even if battery sysfs fails with rc=1
        with patch("phonecluster.usbhub.subprocess.run") as m_run:
            m_run.return_value = subprocess.CompletedProcess(
                args=["adb"], returncode=1, stdout="OS=ubuntu-touch\nSSH_PORT=22\nSSH_USER=phablet\n", stderr=""
            )
            prof = probe_adb_device_profile("UT123", adb_bin="/usr/bin/adb")
            self.assertEqual(prof["os_env"], "ubuntu-touch")
            self.assertEqual(prof["remote_ssh_port"], 22)
            self.assertEqual(prof["ssh_user"], "phablet")
            self.assertIn("; true", m_run.call_args.args[0][-1])

        # 2. systemd unit: WorkingDirectory is UNQUOTED and %/$ are escaped cleanly
        unit = generate_usb_hub_systemd_unit(
            "adb",
            config_path="/opt/my%20app/cluster$1.json",
            repo_dir="/opt/phonecluster",
            use_python_module=True,
        )
        self.assertIn("WorkingDirectory=/opt/phonecluster\n", unit)
        self.assertNotIn('WorkingDirectory="', unit)
        self.assertIn("-m phonecluster.cli", unit)
        self.assertIn("my%%20app", unit)
        self.assertIn("cluster$$1.json", unit)

        # 3. plan_adb_usb_hub reserves gateway_port & tracks quarantined mesh revocations; apply reports revoke failures
        devs = [{"serial": "SER1", "state": "device"}, {"serial": "SER2", "state": "device"}]
        plan = plan_adb_usb_hub(devs, worker_base_port=8887, gateway_port=8888, enable_gateway_reverse=True)
        self.assertNotIn(8888, [n["worker_port"] for n in plan["nodes"]])

        cfg = create_default_config(master_host="127.0.0.1", worker_hosts=[])
        sync_usb_hub_into_config(cfg, plan)
        nid0, nid1 = plan["nodes"][0]["node_id"], plan["nodes"][1]["node_id"]
        ser1 = plan["nodes"][1]["serial"]
        q_plan = plan_adb_usb_hub(
            devs,
            existing_nodes=cfg.nodes,
            quarantined_nodes={nid1},
            enable_gateway_reverse=False,
        )
        self.assertEqual(q_plan["quarantined_serials"], [ser1])
        self.assertTrue(len(q_plan["revoked_forwards"]) >= 1)
        self.assertTrue(len(q_plan["revoked_reverses"]) >= 1)

        with patch("phonecluster.usbhub.subprocess.run") as m_adb:
            m_adb.return_value = subprocess.CompletedProcess(args=["adb"], returncode=1, stdout="", stderr="device offline")
            res = apply_adb_usb_hub({"forward_rules": [], "reverse_rules": [], "quarantined_serials": [ser1]}, adb_bin="/usr/bin/adb")
            self.assertFalse(res["ok"])
            self.assertGreaterEqual(res["failed"], 1)

        # 4. verify_usb_hub_connectivity catches missing src reverse half of ADB peer mesh!
        ctrl = MasterController(cfg)
        n1, n2 = cfg.get_node(nid0), cfg.get_node(nid1)
        snaps = [
            NodeSnapshot(n1, online=True, latency_ms=1.0, health={"ready_for_jobs": True, "battery_status": "CHARGING"}),
            NodeSnapshot(n2, online=True, latency_ms=1.0, health={"ready_for_jobs": True, "battery_status": "CHARGING"}),
        ]
        # Master forwards exist for both nodes & mesh ports, but usb1 has NO reverse rules!
        fwd_out = (
            f"SER1 tcp:{n1.worker_port} tcp:8765\n"
            f"SER2 tcp:{n2.worker_port} tcp:8765\n"
            f"SER1 tcp:{n1.adb.mesh_base_port} tcp:3632\n"
            f"SER2 tcp:{n2.adb.mesh_base_port} tcp:3632\n"
        )

        def _fake_adb(cmd, **_kw):
            if "forward" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=fwd_out, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with (
            patch.object(ctrl, "poll_health", return_value=snaps),
            patch("phonecluster.usbhub.subprocess.run", side_effect=_fake_adb),
        ):
            rep = verify_usb_hub_connectivity(ctrl, adb_bin="/usr/bin/adb")
            self.assertFalse(rep["ok"])
            self.assertTrue(any(not lk["ok"] and "rev:" in lk["error"] for lk in rep["peer_links"]))

        # 5. RNDIS plan skips existing ADB usb1 IDs, and nat_wan=True with empty wan_iface still drops FORWARD!
        r_plan = plan_rndis_usb_hub(
            [{"iface": "usb0", "mac": "02:aa:00:00:00:01", "driver": "rndis_host"}],
            existing_nodes=cfg.nodes,
        )
        self.assertNotIn(r_plan["nodes"][0]["node_id"], {nid0, nid1})
        r_cmds = build_rndis_router_commands(r_plan, nat_wan=True, wan_iface="")
        self.assertTrue(any("! -d 10.77.0.0/16 -j DROP" in c for c in r_cmds["host_commands"]))

        # 6. detect_subnet_collisions handles same-iface duplicate and overlapping /24 vs /30
        self.assertEqual(
            detect_subnet_collisions([{"iface": "usb0", "ipv4_cidrs": ["192.168.42.1/24", "192.168.42.2/24"]}]),
            [],
        )
        overlaps = detect_subnet_collisions(
            [
                {"iface": "usb0", "ipv4_cidrs": ["10.77.1.1/24"]},
                {"iface": "usb1", "ipv4_cidrs": ["10.77.1.5/30"]},
            ]
        )
        self.assertEqual(len(overlaps), 1)

    def test_pairing_dh_check_zone_ipv6_loopback_adb_and_discovery_port(self) -> None:
        # 1. Invalid discovery_port raises ValueError cleanly
        with self.assertRaises(ValueError):
            discover_lan_nodes(discovery_port=70000)

        # 2. join_cluster_via_pairing rejects invalid DH public key (pub_a == 1)
        bad_hello = (
            200,
            {
                "session_id": "abc12345",
                "dh_pub": "1",
                "salt": "00" * 16,
                "fingerprint": "",
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            with patch("phonecluster.pairing._http_json", return_value=bad_hello):
                with self.assertRaises(RuntimeError) as ctx:
                    join_cluster_via_pairing("127.0.0.1", 8767, "123456", config_out=Path(tmp) / "out.json")
                self.assertIn("invalid DH public key", str(ctx.exception))

        # 3. Link-local IPv6 %zone rejected at complete_pairing without corrupting config
        cfg = create_default_config(master_host="127.0.0.1", worker_hosts=[])
        cfg.nodes.append(
            NodeConfig(
                "usb1", "127.0.0.1", role="worker", worker_port=18761, ssh_port=18021,
                adb=AdbNodeConfig("SER1", 8765, 8022, 25000), tags=["worker", "usb-hub", "usb-mode:adb"],
            )
        )
        pm = PairingManager(cfg, config_path=None, enable_beacon=False, fail_delay_sec=0.0)
        pm.open_session(ttl_sec=60, max_devices=2)
        st, body = pm.complete_pairing("fe80::1234%wlan0", {"session_id": "x", "dh_pub": "2", "client_proof": "aa", "metadata": {}})
        self.assertEqual(st, 400)
        self.assertIn("Unsupported client IP", body["error"])
        pm.close_session()

    def test_netguard_swarm_ports_firewall_guides_and_doctor(self) -> None:
        self.assertIn(2377, KNOWN_CLUSTER_PORTS)
        self.assertIn(7946, KNOWN_CLUSTER_PORTS)

        cfg = create_default_config(master_host="fd00::1", worker_hosts=["10.77.1.2"])
        cfg.nodes[1].tags = ["worker", "usb-hub", "usb-mode:rndis"]
        cfg.network.lan_subnet = "fd00::/64"
        host_info = detect_controller_host_info(cfg)
        host_info["lan_ip"] = "127.0.0.1"
        guides = build_firewall_guides(cfg, host_info)
        # Must NOT inject bogus 192.168.1.0/24 on IPv6-only host
        self.assertNotIn("192.168.1.0/24", guides["nftables"])
        # Must allow RNDIS worker to reach gateway in nftables and emit UFW worker deny rules
        self.assertIn("10.77.1.2", guides["nftables"])
        self.assertIn("ufw insert 1 deny from 10.77.1.2", guides["ufw"])

        # Doctor: 0 ready nodes among online nodes must warn; USB hub section emitted
        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "cluster.json"
            c2 = create_default_config(master_host="127.0.0.1", worker_hosts=[])
            c2.nodes.append(
                NodeConfig("usb1", "127.0.0.1", role="worker", worker_port=18761, ssh_port=18021, adb=AdbNodeConfig("S1", 8765, 8022, 25000))
            )
            save_config(c2, cfg_p)
            snaps = [
                NodeSnapshot(c2.nodes[0], online=True, health={"ready_for_jobs": False, "low_ram": True, "mem_available_mb": 100}),
                NodeSnapshot(c2.nodes[1], online=True, health={"ready_for_jobs": False, "low_ram": True, "mem_available_mb": 100}),
            ]
            with (
                patch("phonecluster.doctor.MasterController.poll_health", return_value=snaps),
                patch("phonecluster.doctor.detect_usb_hub_topology", return_value={"adb_installed": True, "adb_devices": [], "adb_ready_count": 0, "usb_net_count": 0, "ipv4_forwarding_enabled": False, "subnet_collisions": []}),
            ):
                doc = run_doctor(cfg_p, check_remote=True)
            by_name = {c["name"]: c for c in doc["checks"]}
            self.assertEqual(by_name["Cluster Nodes"]["status"], "warn")
            self.assertIn("USB 3.0 Hub", by_name)
            self.assertIn("Cluster Memory Headroom", by_name)


class TestPass14DashboardCliRoutingAndTui(unittest.TestCase):
    def test_dashboard_config_reload_and_fresh_live_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "cluster.json"
            cfg = create_default_config(master_host="127.0.0.1", worker_hosts=[])
            save_config(cfg, cfg_p)
            ctrl = MasterController(load_config(cfg_p))
            dash = DashboardHTTPServer(
                ("127.0.0.1", 0), ctrl, config_path=cfg_p, enable_pairing_beacon=False, enable_usb_watchdog=False
            )
            dash.sample_live_in_background = True
            dash.latest_live = {"summary": {"cluster_name": "stale"}, "jobs": [], "history": {"cluster": [], "nodes": {}}}
            th = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            th.start()
            try:
                port = dash.server_address[1]
                # Simulate external CLI modifying cluster.json on disk
                disk_cfg = load_config(cfg_p)
                disk_cfg.cluster_name = "reloaded-from-disk"
                save_config(disk_cfg, cfg_p)

                # POST /api/config/reload picks up disk config without restarting dashboard
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/config/reload",
                    data=b"{}",
                    headers={
                        "Authorization": f"Bearer {cfg.auth_token}",
                        "Content-Type": "application/json",
                        "Origin": f"http://127.0.0.1:{port}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    reloaded = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(reloaded["reloaded"])
                self.assertEqual(reloaded["cluster_name"], "reloaded-from-disk")

                # GET /api/live?fresh=1 immediately returns updated cluster_name instead of stale cache
                with patch.object(ctrl, "poll_health", return_value=[]):
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/live?fresh=1", timeout=3.0) as resp2:
                        live = json.loads(resp2.read().decode("utf-8"))
                self.assertEqual(live["summary"]["cluster_name"], "reloaded-from-disk")
            finally:
                dash.shutdown()
                dash.server_close()
                th.join(timeout=2.0)

    def test_cli_init_config_respects_config_flag_and_adb_distcc_mpi_and_tui_compact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "custom_cluster.json"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = cli_main(["--config", str(target), "init-config", "--master-host", "127.0.0.1", "--workers", ""])
            self.assertEqual(rc, 0)
            self.assertTrue(target.is_file())

        # ADB workers: distcc uses mesh forward port (NOT localhost), MPI skips ADB nodes
        cfg = create_default_config(master_host="127.0.0.1", worker_hosts=[])
        adb_node = NodeConfig(
            "usb1", "127.0.0.1", role="worker", worker_port=18761, ssh_port=18021,
            adb=AdbNodeConfig("SER1", 8765, 8022, 25000, peer_mesh=True),
            tags=["worker", "usb-hub", "usb-mode:adb"],
        )
        cfg.nodes.append(adb_node)
        ctrl = MasterController(cfg)
        snaps = [
            NodeSnapshot(cfg.nodes[0], online=True, health={"ready_for_jobs": True, "cpu_cores": 4, "services": {"distccd_3632": True}, "tools": {"distccd": True, "mpirun": True}}),
            NodeSnapshot(adb_node, online=True, health={"ready_for_jobs": True, "cpu_cores": 8, "services": {"distccd_3632": True, "mosquitto_1883": True}, "tools": {"distccd": True, "mpirun": True}}),
        ]
        distcc = ctrl.build_distcc_hosts(snapshots=snaps)
        self.assertIn("127.0.0.1:25000/8,lzo", distcc)
        self.assertEqual(distcc.count("localhost/"), 1)
        mpi = ctrl.build_mpi_hostfile(snapshots=snaps)
        self.assertEqual(len(mpi.strip().splitlines()), 1)

        # Local loopback Master sees ADB worker services via build_cross_tier_env
        m_env = build_cross_tier_env(snaps, cfg, for_node=cfg.nodes[0])
        self.assertEqual(m_env.get("PHONECLUSTER_MQTT_URL"), "mqtt://127.0.0.1:25003")

        # Compact phone-width TUI rendering handles narrow width and None/non-numeric header metrics cleanly
        summary = {
            "cluster_name": "pocket",
            "cluster_cpu_pct": None,
            "cluster_ram_pct": "bad",
            "mem_total_mb": 4096,
            "mem_available_mb": 2048,
            "max_temp_c": None,
            "nodes_ready": 1,
            "nodes_total": 1,
            "total_cores": 4,
            "safety": {"max_temp_c": 40.0, "battery_high_pct": 60},
            "nodes": [{"id": "usb1", "host": "127.0.0.1", "worker_port": 18761, "tags": ["usb-mode:adb"], "role": "worker", "online": False, "error": "down"}],
        }
        frame = render_top_frame(summary, {"cluster": [], "nodes": {}}, [], width=48, height=18, use_color=False)
        self.assertIn("usb:18761", frame)


if __name__ == "__main__":
    unittest.main()
