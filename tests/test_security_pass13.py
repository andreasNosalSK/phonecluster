"""Pass 13 security hardening regression tests (Network Guard, USB air-gap, Worker/Master/Auth/Config/Scripts)."""

from __future__ import annotations

import base64
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from unittest import TestCase, mock

from phonecluster.auth import (
    AuthRateLimiter,
    _connect_validated_webhook_socket,
    _is_webhook_redirect_target_unsafe,
    build_auth_headers,
    build_webhook_opener,
    read_json_object_bounded,
)
from phonecluster.bundled import bundled_script
from phonecluster.config import (
    ClusterConfig,
    GatewayConfig,
    NetworkHardeningConfig,
    NodeConfig,
    SafetyConfig,
    config_revision,
    create_default_config,
    load_config,
    save_config,
    validate_allowed_master_entry,
)
from phonecluster.dashboard import DashboardHTTPServer
from phonecluster.discovery import DiscoveryResponder, PROBE_TYPE
from phonecluster.gateway import (
    GatewayAuditLog,
    NetworkGuardServer,
    _is_disallowed_ip,
    build_worker_proxy_env,
    derive_proxy_password,
)
from phonecluster.master import JobSpec, MasterController, NodeSnapshot, score_node
from phonecluster.netguard import build_firewall_guides, detect_controller_host_info
from phonecluster.pairing import (
    PAIR_SEARCH_TYPE,
    PairingBeaconResponder,
    _install_ssh_pubkey,
    decrypt_bundle,
    encrypt_bundle,
    join_cluster_via_pairing,
)
from phonecluster.routing import build_cross_tier_env
from phonecluster.usbhub import (
    apply_adb_usb_hub,
    build_rndis_router_commands,
    list_usb_net_interfaces,
    plan_adb_usb_hub,
    plan_rndis_usb_hub,
    sync_usb_hub_into_config,
)
from phonecluster.worker import WorkerHTTPServer, WorkerState, _execute_job_payload

REPO = Path(__file__).resolve().parents[1]


class TestSecurityPass13(TestCase):
    def test_job_proxy_env_cannot_be_overridden_or_smuggled_and_rndis_gateway_routed(self) -> None:
        master = NodeConfig(id="node0", host="192.168.1.201", role="master")
        lan_worker = NodeConfig(id="node1", host="192.168.1.202", role="worker", auth_token="tok-lan-worker-12345")
        rndis_worker = NodeConfig(
            id="usb2",
            host="10.77.2.2",
            role="worker",
            auth_token="tok-rndis-worker-12345",
            tags=["worker", "usb-hub", "usb-mode:rndis"],
        )
        cfg = ClusterConfig(
            cluster_name="sec-proxy",
            auth_token="master-tok-1234567890",
            nodes=[master, lan_worker, rndis_worker],
            gateway=GatewayConfig(enabled=True, port=8888, mode="allowlist", inject_proxy_env=True),
            custom_services={
                "evil_wildcard": "http://*",
                "public_site": "https://example.com:443",
                "local_ha": "http://ha.cluster:8123",
                "lan_box": "http://192.168.1.50:9000",
            },
        )
        # 1. RNDIS worker proxy env points to its /30 Master gateway IP (10.77.2.1), sets ALL_PROXY/PIP_PROXY,
        # and strips wildcard/public hosts from NO_PROXY
        rndis_env = build_worker_proxy_env(cfg, rndis_worker)
        self.assertIn("@10.77.2.1:8888", rndis_env["HTTP_PROXY"])
        self.assertEqual(rndis_env["ALL_PROXY"], rndis_env["HTTP_PROXY"])
        self.assertEqual(rndis_env["all_proxy"], rndis_env["HTTP_PROXY"])
        self.assertEqual(rndis_env["PIP_PROXY"], rndis_env["HTTP_PROXY"])
        no_proxy_parts = rndis_env["NO_PROXY"].split(",")
        self.assertNotIn("*", no_proxy_parts)
        self.assertNotIn("example.com", no_proxy_parts)
        self.assertIn("ha.cluster", no_proxy_parts)
        self.assertIn("192.168.1.50", no_proxy_parts)

        # 2. Master._with_node_env refuses user spec.env proxy overrides and key-whitespace smuggling
        ctrl = MasterController(cfg)
        spec = JobSpec(
            index=0,
            job_id="j-override",
            command="env",
            env={
                "HTTP_PROXY": "",
                "HTTPS_PROXY": "http://127.0.0.1:9999",
                "http_proxy": "",
                "ALL_PROXY": "socks5://evil:1080",
                "NO_PROXY": "*",
                "PIP_PROXY": "http://evil:8080",
                "GIT_CONFIG_COUNT": "1",
                "NPM_CONFIG_HTTPS_PROXY": "http://evil:8080",
                "HTTP_PROXY ": "http://smuggled:9999",
                "HTTP_PROXY\x00": "http://smuggled:9999",
                "PHONECLUSTER_GATEWAY_ENABLED": "0",
                "SAFE_APP_VAR": "ok",
            },
        )
        enriched = ctrl._with_node_env(spec, lan_worker, cross_env={})
        self.assertIn("@192.168.1.201:8888", enriched.env["HTTP_PROXY"])
        self.assertEqual(enriched.env["HTTPS_PROXY"], enriched.env["HTTP_PROXY"])
        self.assertEqual(enriched.env["ALL_PROXY"], enriched.env["HTTP_PROXY"])
        self.assertEqual(enriched.env["PIP_PROXY"], enriched.env["HTTP_PROXY"])
        self.assertNotEqual(enriched.env["NO_PROXY"], "*")
        self.assertEqual(enriched.env["PHONECLUSTER_GATEWAY_ENABLED"], "1")
        self.assertNotIn("GIT_CONFIG_COUNT", enriched.env)
        self.assertNotIn("NPM_CONFIG_HTTPS_PROXY", enriched.env)
        self.assertNotIn("HTTP_PROXY ", enriched.env)
        self.assertNotIn("HTTP_PROXY\x00", enriched.env)
        self.assertEqual(enriched.env["SAFE_APP_VAR"], "ok")

        # 3. Worker refuses whitespace/NUL env key smuggling and scrubs ambient os.environ proxy overrides
        with tempfile.TemporaryDirectory() as tmp:
            state = WorkerState("node1", "worker", "tok-lan-worker-12345", SafetyConfig(), workdir=Path(tmp))
            with mock.patch.dict(
                os.environ,
                {"ALL_PROXY": "http://ambient-bypass:1234", "PIP_PROXY": "http://ambient-pip:1234", "GIT_CONFIG_COUNT": "1"},
                clear=False,
            ):
                code, out = _execute_job_payload(
                    state,
                    {
                        "job_id": "env-check",
                        "command": (
                            f"{sys.executable} -c "
                            "\"import json, os; print(json.dumps({k: os.environ.get(k) for k in "
                            "('HTTP_PROXY', 'ALL_PROXY', 'PIP_PROXY', 'GIT_CONFIG_COUNT')}))\""
                        ),
                        "env": {
                            "PHONECLUSTER_GATEWAY_ENABLED": "1",
                            "HTTP_PROXY": "http://u:p@192.168.1.201:8888",
                            "HTTP_PROXY ": "http://smuggled:9999",
                            "HTTP_PROXY\x00": "http://smuggled-nul:9999",
                        },
                        "force": True,
                    },
                )
            self.assertEqual(code, 200)
            seen = json.loads(out["stdout"])
            self.assertEqual(seen["HTTP_PROXY"], "http://u:p@192.168.1.201:8888")
            self.assertIsNone(seen["ALL_PROXY"])
            self.assertIsNone(seen["PIP_PROXY"])
            self.assertIsNone(seen["GIT_CONFIG_COUNT"])

    def test_gateway_siit_nat64_ssrf_per_node_cap_quarantined_ip_and_loopback_rl(self) -> None:
        # RFC 2765 SIIT & RFC 8215 local-use NAT64 SSRF addresses blocked
        self.assertTrue(_is_disallowed_ip("::ffff:0:127.0.0.1"))
        self.assertTrue(_is_disallowed_ip("::ffff:0:192.168.1.1"))
        self.assertTrue(_is_disallowed_ip("64:ff9b:1::127.0.0.1"))
        self.assertFalse(_is_disallowed_ip("93.184.216.34"))

        n0 = NodeConfig(id="node0", host="192.168.1.10", role="master")
        n1 = NodeConfig(id="node1", host="192.168.1.11", role="worker", auth_token="tok-w1-12345678")
        n2 = NodeConfig(id="node2", host="192.168.1.12", role="worker", auth_token="tok-w2-12345678")
        cfg = ClusterConfig(
            cluster_name="gw-sec",
            auth_token="master-tok-12345678",
            nodes=[n0, n1, n2],
            gateway=GatewayConfig(enabled=True, bind_host="127.0.0.1", port=0, max_connections=8, quarantined_nodes=["node1"]),
        )
        srv = NetworkGuardServer(("127.0.0.1", 0), cfg, GatewayAuditLog())
        try:
            # Quarantined worker source IP is recognized even before credentials are checked
            self.assertEqual(srv.is_quarantined_source_ip("192.168.1.11"), "node1")
            self.assertEqual(srv.is_quarantined_source_ip("::ffff:192.168.1.11"), "node1")
            self.assertIsNone(srv.is_quarantined_source_ip("192.168.1.12"))
            self.assertIsNone(srv.is_quarantined_source_ip("127.0.0.1"))

            # Per-node concurrent connection cap prevents one worker from starving the cluster
            cap = srv.max_connections_per_node
            self.assertEqual(cap, 4)
            for _ in range(cap):
                self.assertTrue(srv.try_acquire_node_conn("node2"))
            self.assertFalse(srv.try_acquire_node_conn("node2"))
            self.assertTrue(srv.try_acquire_node_conn("node0"))
            for _ in range(cap):
                srv.release_node_conn("node2")
            srv.release_node_conn("node0")

            # On loopback (ADB USB-hub reverse tunnels), bad auth for node1 does NOT lock out node2
            bad_h = {"proxy-authorization": "Basic " + base64.b64encode(b"node1:wrong").decode("ascii")}
            for _ in range(20):
                nid, _ = srv.authenticate_worker(bad_h, "127.0.0.1")
                self.assertIsNone(nid)
            good_pw = derive_proxy_password(n2.auth_token, "node2")
            good_h = {"proxy-authorization": "Basic " + base64.b64encode(f"node2:{good_pw}".encode()).decode("ascii")}
            nid2, reason2 = srv.authenticate_worker(good_h, "127.0.0.1")
            self.assertEqual((nid2, reason2), ("node2", "ok"))
        finally:
            srv.server_close()

    def test_webhook_opener_no_proxy_single_resolve_redirect_and_ipv6_rate_limit(self) -> None:
        # 1. Webhook opener ignores ambient HTTP_PROXY/HTTPS_PROXY (ProxyHandler is not active even when env is set)
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:9999", "HTTPS_PROXY": "http://127.0.0.1:9999"}):
            opener = build_webhook_opener()
        proxy_handlers = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
        self.assertEqual(proxy_handlers, [])

        # 2. Pinned origin peer prevents rebind classification spoofing on redirects
        self.assertTrue(
            _is_webhook_redirect_target_unsafe(
                "https://rebind.example/hook",
                "http://127.0.0.1:8765/exec",
                orig_peer_ip="93.184.216.34",
            )
        )
        self.assertTrue(
            _is_webhook_redirect_target_unsafe(
                "https://rebind.example/hook",
                "http://192.168.1.5:8123/api",
                orig_peer_ip="93.184.216.34",
            )
        )

        # 3. Connect-time single-resolve policy enforces allow_private / allow_loopback even if DNS rebinds
        fake_lb = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
        fake_priv = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 80))]
        with mock.patch("phonecluster.auth.socket.getaddrinfo", return_value=fake_lb):
            with self.assertRaises(OSError):
                _connect_validated_webhook_socket("rebind.example", 80, 1.0, allow_loopback=False)
        with mock.patch("phonecluster.auth.socket.getaddrinfo", return_value=fake_priv):
            with self.assertRaises(OSError):
                _connect_validated_webhook_socket("rebind.example", 80, 1.0, allow_private=False)

        # 4. IPv6 SLAAC /64 bucketing in AuthRateLimiter
        rl = AuthRateLimiter(max_failures=2, window_sec=60.0, block_sec=60.0)
        rl.record_failure("2001:db8:abcd:1::1")
        rl.record_failure("2001:db8:abcd:1::2")
        blocked, _ = rl.is_blocked("2001:db8:abcd:1::9999")
        self.assertTrue(blocked)
        self.assertFalse(rl.is_blocked("::1")[0])

    def test_udp_recursion_error_survival_and_pairing_hardening(self) -> None:
        deep_json = ("[" * 1200 + "]" * 1200).encode("utf-8")

        # 1. PairingBeaconResponder survives single-packet RecursionError payload
        beacon = PairingBeaconResponder(
            cluster_name="sec",
            pair_port=8767,
            session_id="sid123",
            fingerprint="ABCD",
            expires_at=time.monotonic() + 10.0,
            listen_host="127.0.0.1",
            discovery_port=0,
        )
        self.assertTrue(beacon.bind())
        beacon.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as cli_s:
                cli_s.settimeout(1.5)
                cli_s.sendto(deep_json, ("127.0.0.1", beacon.bound_port))
                cli_s.sendto(json.dumps({"type": PAIR_SEARCH_TYPE}).encode("utf-8"), ("127.0.0.1", beacon.bound_port))
                reply_bytes, _ = cli_s.recvfrom(4096)
            self.assertTrue(beacon.is_alive())
            self.assertEqual(json.loads(reply_bytes.decode("utf-8"))["session_id"], "sid123")
        finally:
            beacon.stop()
            beacon.join(timeout=2.0)

        # 2. DiscoveryResponder survives single-packet RecursionError payload
        disc = DiscoveryResponder(
            node_id="node1",
            role="worker",
            worker_port=8765,
            ssh_port=8022,
            listen_host="127.0.0.1",
            discovery_port=0,
        )
        self.assertTrue(disc.bind())
        disc.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as cli_s:
                cli_s.settimeout(1.5)
                cli_s.sendto(deep_json, ("127.0.0.1", disc.bound_port))
                cli_s.sendto(json.dumps({"type": PROBE_TYPE}).encode("utf-8"), ("127.0.0.1", disc.bound_port))
                reply_bytes, _ = cli_s.recvfrom(4096)
            self.assertTrue(disc.is_alive())
            self.assertEqual(json.loads(reply_bytes.decode("utf-8"))["node_id"], "node1")
        finally:
            disc.stop()
            disc.join(timeout=2.0)

        # 3. decrypt_bundle enforces 16-byte nonce
        env = encrypt_bundle(b"k" * 32, b"m" * 32, {"x": 1}, "aad")
        env["nonce"] = base64.b64encode(b"short").decode("ascii")
        with self.assertRaises(ValueError):
            decrypt_bundle(b"k" * 32, b"m" * 32, env, "aad")

        # 4. join_cluster_via_pairing rejects oversized >2048-bit dh_pub cleanly (no OverflowError)
        with tempfile.TemporaryDirectory() as tmp:
            bad_hello = (200, {"session_id": "s1", "dh_pub": "f" * 513, "salt": "aa" * 16})
            with mock.patch("phonecluster.pairing._http_json", return_value=bad_hello):
                with self.assertRaises(RuntimeError):
                    join_cluster_via_pairing("127.0.0.1", 8767, "123456", Path(tmp) / "out.json")

        # 5. _install_ssh_pubkey refuses symlink authorized_keys
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            victim = home / "victim.txt"
            victim.write_text("keep\n", encoding="utf-8")
            (ssh_dir / "authorized_keys").symlink_to(victim)
            sample_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@host"
            with mock.patch("phonecluster.pairing.Path.home", return_value=home):
                with self.assertRaises(ValueError):
                    _install_ssh_pubkey(sample_key)
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep\n")

    def test_config_symlink_lockfile_transfer_and_bundled_script_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "victim.txt"
            victim.write_text("do-not-overwrite\n", encoding="utf-8")
            sym_cfg = root / "cluster.json"
            sym_cfg.symlink_to(victim)

            cfg = create_default_config(worker_hosts=[])
            with self.assertRaises(ValueError):
                config_revision(sym_cfg)
            with self.assertRaises(ValueError):
                save_config(cfg, sym_cfg)
            with self.assertRaises(ValueError):
                load_config(sym_cfg)
            self.assertEqual(victim.read_text(encoding="utf-8"), "do-not-overwrite\n")

            # Symlinked lockfile is also rejected
            real_cfg = root / "real.json"
            (root / ".real.json.lock").symlink_to(victim)
            with self.assertRaises(OSError):
                save_config(cfg, real_cfg)
            self.assertEqual(victim.read_text(encoding="utf-8"), "do-not-overwrite\n")

            # config_transfer rejects NaN & deeply nested JSON
            clean_cfg = root / "clean.json"
            save_config(cfg, clean_cfg)
            rev = config_revision(clean_cfg)
            orig_bytes = clean_cfg.read_bytes()
            r_nan = subprocess.run(
                [sys.executable, "-m", "phonecluster.config_transfer", str(clean_cfg), "--expect", rev],
                input=b'{"x": NaN}',
                capture_output=True,
                timeout=5,
            )
            self.assertNotEqual(r_nan.returncode, 0)
            self.assertEqual(clean_cfg.read_bytes(), orig_bytes)

        # Wildcard /0 CIDRs and wildcard URL hosts rejected
        with self.assertRaises(ValueError):
            validate_allowed_master_entry("0.0.0.0/0")
        with self.assertRaises(ValueError):
            validate_allowed_master_entry("::/0")
        with self.assertRaises(ValueError):
            SafetyConfig.from_dict({"battery_webhook_url": "http://*/hook"})
        with self.assertRaises(ValueError):
            NetworkHardeningConfig.from_dict({"adguard_url": "http://*:3000"})

        # bundled_script blocks path traversal and absolute paths
        self.assertIsNone(bundled_script("../install.sh"))
        self.assertIsNone(bundled_script("/etc/passwd"))
        self.assertIsNone(bundled_script(".."))
        self.assertIsNotNone(bundled_script("05_workload_helpers.sh"))

    def test_worker_ip_connection_cap_and_bounded_read_deadline(self) -> None:
        # 1. WorkerHTTPServer caps non-loopback per-IP concurrent slots
        state = WorkerState("node1", "worker", "tok-12345678", SafetyConfig())
        srv = WorkerHTTPServer(("127.0.0.1", 0), state)
        try:
            keys = []
            for _ in range(srv._max_conns_per_ip):
                k = srv._acquire_ip_slot("192.168.1.99")
                self.assertIsNotNone(k)
                keys.append(k)
            self.assertIsNone(srv._acquire_ip_slot("192.168.1.99"))
            self.assertIsNotNone(srv._acquire_ip_slot("192.168.1.100"))
            srv._release_ip_slot("192.168.1.100")
            for k in keys:
                srv._release_ip_slot(k)
        finally:
            srv.server_close()

        # 2. read_json_object_bounded enforces total wall-clock deadline against slow-drip responses
        class _SlowResp:
            def read(self, _n: int = -1) -> bytes:
                time.sleep(0.06)
                return b" "

        with self.assertRaises(TimeoutError):
            read_json_object_bounded(_SlowResp(), 4096, deadline_sec=0.1)

    def test_master_telemetry_clamping_docker_resilience_quarantine_and_dashboard_guards(self) -> None:
        m = NodeConfig(id="node0", host="192.168.1.10", role="master")
        w1 = NodeConfig(id="node1", host="192.168.1.11", role="worker", auth_token="tok-w1-12345678")
        w2 = NodeConfig(id="node2", host="192.168.1.12", role="worker", auth_token="tok-w2-12345678")
        cfg = ClusterConfig(
            cluster_name="clamp-sec",
            auth_token="master-tok-12345678",
            nodes=[m, w1, w2],
            gateway=GatewayConfig(quarantined_nodes=["node2"]),
        )
        ctrl = MasterController(cfg)

        # 1. Spoofed temp_c=-499 and cpu_cores=999999 are clamped
        spoof_snap = NodeSnapshot(
            w1,
            online=True,
            health={
                "ready_for_jobs": True,
                "temp_c": -499.0,
                "cpu_cores": 999999,
                "mem_total_mb": 999999999,
                "mem_available_mb": 999999999,
                "services": {"distccd_3632": True},
                "tools": {"distccd": True, "mpirun": True},
            },
        )
        normal_snap = NodeSnapshot(
            m,
            online=True,
            health={"ready_for_jobs": True, "temp_c": 30.0, "cpu_cores": 8, "mem_available_mb": 4096},
        )
        # Spoofed -499C gets fallback 0.5 temp_bonus rather than +44.0 bonus, so healthy 30C node beats it
        self.assertGreater(score_node(normal_snap), score_node(spoof_snap))
        distcc_str = ctrl.build_distcc_hosts(snapshots=[spoof_snap])
        self.assertIn("/128,lzo", distcc_str)
        self.assertNotIn("999999", distcc_str)
        mpi_str = ctrl.build_mpi_hostfile(snapshots=[spoof_snap])
        self.assertIn("slots=128", mpi_str)
        env = build_cross_tier_env([spoof_snap], cfg)
        self.assertIn("/128,lzo", env.get("PHONECLUSTER_DISTCC_HOSTS", ""))

        # 2. docker_cluster_status survives poisoned worker non-int containers_running without crashing
        docker_snap = NodeSnapshot(w1, online=True, health={"tools": {"docker": True}})
        poison_out = json.dumps({"ok": True, "engine_ok": True, "containers_running": "not-an-int", "containers": "bad"})
        with mock.patch.object(ctrl, "poll_health", return_value=[docker_snap]), mock.patch.object(
            ctrl, "exec_on_node", return_value=("ok", {"returncode": 0, "stdout": poison_out})
        ):
            dstat = ctrl.docker_cluster_status()
        self.assertEqual(dstat["total_running_containers"], 0)
        self.assertEqual(dstat["nodes"][0]["containers"], [])

        # 3. docker_swarm_setup rejects malformed join token starting with '-'
        bad_mgr = json.dumps({"ok": True, "initialized": True, "token": "--evil-flag"})
        with mock.patch.object(ctrl, "poll_health", return_value=[NodeSnapshot(m, online=True, health={"tools": {"docker": True}})]):
            with mock.patch.object(ctrl, "exec_on_node", return_value=("ok", {"returncode": 0, "stdout": bad_mgr})):
                sw = ctrl.docker_swarm_setup()
        self.assertFalse(sw["ok"])
        self.assertIn("malformed join token", sw["error"].lower())

        # 4. check_workers_wan_isolation & push_config_to_all skip quarantined node2
        called_nodes = []

        def fake_exec(node, spec):
            called_nodes.append(node.id)
            return "ok", {"returncode": 0, "stdout": "WAN_BLOCKED:OSError"}

        with mock.patch.object(ctrl, "exec_on_node", side_effect=fake_exec):
            wan_res = ctrl.check_workers_wan_isolation()
        self.assertEqual(called_nodes, ["node1"])
        q_row = next(r for r in wan_res if r["node_id"] == "node2")
        self.assertIn("quarantined", q_row["detail"].lower())

        pushed_nodes = []
        with mock.patch.object(ctrl, "push_config_to_node", side_effect=lambda n, *a, **kw: (pushed_nodes.append(n.id) or {"node_id": n.id, "ok": True, "persisted": True})):
            ctrl.push_config_to_all()
        self.assertNotIn("node2", pushed_nodes)

        # 5. Dashboard rejects quarantining master via /api/gateway/settings & rejects 0.0.0.0/0 in distcc-start
        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "cluster.json"
            save_config(cfg, cfg_p)
            dash = DashboardHTTPServer(("127.0.0.1", 0), ctrl, config_path=cfg_p, enable_pairing_beacon=False)
            d_port = dash.server_address[1]
            th = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            th.start()
            try:
                def post(path: str, payload: dict) -> tuple[int, dict]:
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{d_port}{path}",
                        data=json.dumps(payload).encode("utf-8"),
                        headers={**build_auth_headers(cfg.auth_token), "Content-Type": "application/json"},
                        method="POST",
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=3.0) as resp:
                            return resp.status, json.loads(resp.read().decode("utf-8"))
                    except urllib.error.HTTPError as exc:
                        try:
                            return exc.code, json.loads(exc.read().decode("utf-8"))
                        finally:
                            exc.close()

                st_q, body_q = post("/api/gateway/settings", {"quarantined_nodes": ["node0"]})
                self.assertEqual(st_q, 400)
                self.assertIn("master", body_q["error"].lower())

                st_c, body_c = post("/api/workloads/action", {"action": "distcc-start", "cidr": "0.0.0.0/0"})
                self.assertEqual(st_c, 400)
                self.assertIn("too broad", body_c["error"].lower())
            finally:
                dash.shutdown()
                dash.server_close()
                th.join(timeout=2.0)

    def test_usb_hub_airgap_firewall_quarantine_and_scripts_hardening(self) -> None:
        # 1. list_usb_net_interfaces skips host USB-Ethernet LAN NICs (r8152) and detects phone gadgets (rndis_host)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_net = root / "net"
            sys_net.mkdir()
            drv_r8152 = root / "drivers" / "r8152"
            drv_rndis = root / "drivers" / "rndis_host"
            drv_r8152.mkdir(parents=True)
            drv_rndis.mkdir(parents=True)

            # Simulated USB LAN dongle on /devices/.../usb1/... with r8152 driver
            eth_dev = root / "devices" / "pci0" / "usb1" / "eth_dongle"
            eth_dev.mkdir(parents=True)
            (eth_dev / "driver").symlink_to(drv_r8152)
            eth_entry = sys_net / "enx001122334455"
            eth_entry.mkdir()
            (eth_entry / "device").symlink_to(eth_dev)
            (eth_entry / "address").write_text("00:11:22:33:44:55\n", encoding="utf-8")

            # Simulated phone gadget with rndis_host driver
            ph_dev = root / "devices" / "pci0" / "usb1" / "phone1"
            ph_dev.mkdir(parents=True)
            (ph_dev / "driver").symlink_to(drv_rndis)
            ph_entry = sys_net / "enx02aa00000001"
            ph_entry.mkdir()
            (ph_entry / "device").symlink_to(ph_dev)
            (ph_entry / "address").write_text("02:aa:00:00:00:01\n", encoding="utf-8")

            found = list_usb_net_interfaces(sys_net_dir=sys_net, include_ips=False)
            self.assertEqual([i["iface"] for i in found], ["enx02aa00000001"])

        # 2. Quarantined ADB phone gets NO gateway/peer-mesh reverse rules and triggers reverse --remove-all
        plan = plan_adb_usb_hub(
            [{"serial": "SER1", "state": "device"}, {"serial": "SER2", "state": "device"}],
            quarantined_nodes={"usb1"},
        )
        self.assertEqual(plan["quarantined_serials"], ["SER1"])
        self.assertFalse(any(r["serial"] == "SER1" for r in plan["reverse_rules"]))
        self.assertTrue(any(r["serial"] == "SER2" for r in plan["reverse_rules"]))

        adb_calls = []

        def fake_adb(cmd, **kwargs):
            adb_calls.append(cmd[1:])
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch("phonecluster.usbhub.subprocess.run", side_effect=fake_adb):
            apply_adb_usb_hub(plan, adb_bin="/fake/adb")
        self.assertIn(["-s", "SER1", "reverse", "--remove-all"], adb_calls)

        # 3. RNDIS router commands enforce explicit FORWARD DROP, IPv6 disable/RA block, rp_filter, and INPUT isolation
        r_plan = plan_rndis_usb_hub([{"iface": "usb0", "mac": "02:aa:00:00:00:01", "driver": "rndis_host"}], subnet_prefix="10.77")
        cmds = "\n".join(build_rndis_router_commands(r_plan, nat_wan=False)["host_commands"])
        self.assertIn("disable_ipv6=1", cmds)
        self.assertIn("accept_ra=0", cmds)
        self.assertIn("rp_filter=1", cmds)
        self.assertIn("-s 10.77.0.0/16 ! -d 10.77.0.0/16 -j DROP", cmds)
        self.assertIn("INPUT", cmds)
        self.assertIn("-i usb0 -j DROP", cmds)

        # 4. sync_usb_hub_into_config allows only Master .1 host IPs (not /16 or worker .2 IPs)
        cfg = create_default_config(worker_hosts=[])
        sync_usb_hub_into_config(cfg, r_plan)
        self.assertIn("10.77.1.1", cfg.network.allowed_master_ips)
        self.assertNotIn("10.77.0.0/16", cfg.network.allowed_master_ips)
        self.assertNotIn("10.77.1.2", cfg.network.allowed_master_ips)

        # 5. Shell scripts enforce distcc CIDR rejection, RNDIS firewall chains, and tar safety
        p_distcc = subprocess.run(
            ["bash", str(REPO / "scripts" / "05_workload_helpers.sh"), "distcc-start", "0.0.0.0/0"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(p_distcc.returncode, 2)
        self.assertIn("too broad", p_distcc.stderr.lower())

        sh_usb = (REPO / "scripts" / "07_usb_hub_router.sh").read_text(encoding="utf-8")
        self.assertIn("PHONECLUSTER_USB_FWD", sh_usb)
        self.assertIn("PHONECLUSTER_USB_IN", sh_usb)
        self.assertIn("disable_ipv6=1", sh_usb)
        self.assertIn("! -d \"${CLUSTER_CIDR}\" -j DROP", sh_usb)

        # 6. Master nftables guide explicitly blocks worker phone IPs from Master admin ports
        cfg_fw = create_default_config(master_host="192.168.1.201", worker_hosts=["192.168.1.202"])
        guides = build_firewall_guides(cfg_fw, detect_controller_host_info(cfg_fw))
        self.assertIn("ip saddr { 192.168.1.202 } tcp dport {", guides["nftables"])
        self.assertIn("} drop", guides["nftables"])
