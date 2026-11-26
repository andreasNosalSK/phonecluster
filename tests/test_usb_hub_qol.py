"""Tests for USB 3.0 Hub communication QoL upgrades and Wireless vs USB Hub setup UX."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import threading
import urllib.request
from pathlib import Path
from unittest import TestCase, mock

from phonecluster.auth import build_auth_headers
from phonecluster.cli import main as cli_main
from phonecluster.config import (
    AdbNodeConfig,
    ClusterConfig,
    GatewayConfig,
    NodeConfig,
    create_default_config,
    load_config,
    save_config,
)
from phonecluster.dashboard import DASHBOARD_HTML, DashboardHTTPServer
from phonecluster.master import MasterController, NodeSnapshot
from phonecluster.routing import build_cross_tier_env
from phonecluster.usbhub import (
    generate_usb_hub_systemd_unit,
    plan_adb_usb_hub,
    probe_adb_device_profile,
    verify_usb_hub_connectivity,
)
from phonecluster.wizard import run_setup_wizard

REPO = Path(__file__).resolve().parents[1]


class TestUsbHubQolAndSetup(TestCase):
    def test_probe_adb_device_profile_and_mixed_os_hub_planning(self) -> None:
        ut_out = "OS=ubuntu-touch\nSSH_PORT=22\nSSH_USER=phablet\nBAT_PCT=81\nBAT_STATUS=CHARGING\n"
        tx_out = "OS=termux\nSSH_PORT=8022\nSSH_USER=u0_a250\nBAT_PCT=44\nBAT_STATUS=DISCHARGING\n"

        def fake_run(cmd, **kwargs):
            ser = cmd[2]
            stdout = ut_out if ser == "SER_UT" else tx_out
            return subprocess.CompletedProcess(cmd, 0, stdout, "")

        with mock.patch("phonecluster.usbhub.subprocess.run", side_effect=fake_run):
            p_ut = probe_adb_device_profile("SER_UT", adb_bin="/fake/adb")
            p_tx = probe_adb_device_profile("SER_TX", adb_bin="/fake/adb")

        self.assertEqual((p_ut["os_env"], p_ut["remote_ssh_port"], p_ut["ssh_user"], p_ut["usb_power_warning"]), ("ubuntu-touch", 22, "phablet", False))
        self.assertEqual((p_tx["os_env"], p_tx["remote_ssh_port"], p_tx["ssh_user"], p_tx["usb_power_warning"]), ("termux", 8022, "u0_a250", True))

        # Mixed Ubuntu Touch (port 22) + Android Termux (port 8022) on the same USB 3.0 hub
        plan = plan_adb_usb_hub(
            [
                {"serial": "SER_UT", "state": "device", "remote_ssh_port": 22, "ssh_user": "phablet", "os_env": "ubuntu-touch"},
                {"serial": "SER_TX", "state": "device", "remote_ssh_port": 8022, "ssh_user": "u0_a250", "os_env": "termux"},
            ]
        )
        by_ser = {n["serial"]: n for n in plan["nodes"]}
        self.assertEqual(by_ser["SER_UT"]["remote_ssh_port"], 22)
        self.assertEqual(by_ser["SER_UT"]["ssh_user"], "phablet")
        self.assertEqual(by_ser["SER_TX"]["remote_ssh_port"], 8022)
        self.assertEqual(by_ser["SER_TX"]["ssh_user"], "u0_a250")

    def test_wizard_obvious_wireless_vs_usb_hub_setup_modes(self) -> None:
        fake_topo_adb = {
            "adb_installed": True,
            "adb_devices": [
                {"serial": "ADB1", "state": "device", "model": "Redmi"},
                {"serial": "ADB2", "state": "device", "model": "UbuntuPhone"},
            ],
            "adb_ready_count": 2,
            "usb_net_interfaces": [],
            "usb_net_count": 0,
            "subnet_collisions": [],
            "ipv4_forwarding_enabled": False,
            "recommended_mode": "adb",
            "notes": [],
        }
        fake_profiles = {
            "ADB1": {"os_env": "termux", "remote_ssh_port": 8022, "ssh_user": "u0_a101", "usb_power_warning": False},
            "ADB2": {"os_env": "ubuntu-touch", "remote_ssh_port": 22, "ssh_user": "phablet", "usb_power_warning": False},
        }
        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "usb_adb.json"
            answers = iter([
                "usb-lab",      # cluster name
                "127.0.0.1",    # master host
                "phablet",      # default ssh user
                "22",           # default ssh port
                "u",            # choose USB 3.0 Hub!
                "adb",          # choose adb mode
                "y",            # apply tunnels now
                "40.0",         # max temp
                "",             # webhook
            ])
            with (
                mock.patch("phonecluster.wizard.detect_usb_hub_topology", return_value=fake_topo_adb),
                mock.patch("phonecluster.wizard.probe_adb_device_profile", side_effect=lambda ser: fake_profiles[ser]),
                mock.patch("phonecluster.wizard.apply_adb_usb_hub", return_value={"ok": True, "applied": 8, "unchanged": 0, "failed": 0}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                rc = run_setup_wizard(cfg_p, input_fn=lambda _p: next(answers))
            self.assertEqual(rc, 0)
            cfg = load_config(cfg_p)
            self.assertEqual([n.id for n in cfg.nodes], ["node0", "usb1", "usb2"])
            self.assertEqual(cfg.get_node("usb1").adb.remote_ssh_port, 8022)
            self.assertEqual(cfg.get_node("usb2").adb.remote_ssh_port, 22)
            self.assertEqual(cfg.get_node("usb2").ssh_user, "phablet")

        # Direct --transport usb-rndis flow
        fake_topo_rndis = {
            "adb_installed": False,
            "adb_devices": [],
            "adb_ready_count": 0,
            "usb_net_interfaces": [
                {"iface": "usb0", "mac": "02:aa:00:00:00:01", "driver": "rndis_host", "operstate": "up", "ipv4_cidrs": []},
                {"iface": "usb1", "mac": "02:bb:00:00:00:02", "driver": "rndis_host", "operstate": "up", "ipv4_cidrs": []},
            ],
            "usb_net_count": 2,
            "subnet_collisions": [],
            "ipv4_forwarding_enabled": True,
            "recommended_mode": "rndis",
            "notes": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            cfg_r = Path(tmp) / "usb_rndis.json"
            answers_r = iter(["ut-hub", "10.77.1.1", "phablet", "22", "10.77", "40", ""])
            with (
                mock.patch("phonecluster.wizard.detect_usb_hub_topology", return_value=fake_topo_rndis),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                rc = run_setup_wizard(cfg_r, input_fn=lambda _p: next(answers_r), transport="usb-rndis")
            self.assertEqual(rc, 0)
            cfg = load_config(cfg_r)
            self.assertEqual(cfg.get_node("usb1").host, "10.77.1.2")
            self.assertEqual(cfg.get_node("usb2").host, "10.77.2.2")
            self.assertIn("10.77.1.1", cfg.network.allowed_master_ips)
            self.assertNotIn("10.77.0.0/16", cfg.network.allowed_master_ips)

    def test_routing_injects_usb_mode_and_peer_endpoints(self) -> None:
        # 1. RNDIS /30 USB peers (quarantined sibling excluded)
        m = NodeConfig(id="node0", host="10.77.1.1", role="master")
        u1 = NodeConfig(id="usb1", host="10.77.1.2", role="worker", tags=["worker", "usb-hub", "usb-mode:rndis"])
        u2 = NodeConfig(id="usb2", host="10.77.2.2", role="worker", tags=["worker", "usb-hub", "usb-mode:rndis"])
        u3 = NodeConfig(id="usb3", host="10.77.3.2", role="worker", tags=["worker", "usb-hub", "usb-mode:rndis"])
        cfg = ClusterConfig("rndis-peers", "tok-12345678", [m, u1, u2, u3], gateway=GatewayConfig(quarantined_nodes=["usb3"]))
        snaps = [NodeSnapshot(n, online=True, health={"ready_for_jobs": True}) for n in [m, u1, u2, u3]]
        env = build_cross_tier_env(snaps, cfg, for_node=u1)
        self.assertEqual(env["PHONECLUSTER_USB_MODE"], "rndis")
        self.assertEqual(env["PHONECLUSTER_USB_PEERS"], "usb2=10.77.2.2")

        # 2. ADB Peer Mesh USB peers
        a1 = NodeConfig(id="usb1", host="127.0.0.1", worker_port=18761, ssh_port=18021, tags=["worker", "usb-hub", "usb-mode:adb"], adb=AdbNodeConfig("S1", 8765, 8022, 25000, True))
        a2 = NodeConfig(id="usb2", host="127.0.0.1", worker_port=18762, ssh_port=18022, tags=["worker", "usb-hub", "usb-mode:adb"], adb=AdbNodeConfig("S2", 8765, 22, 25005, True))
        cfg_a = ClusterConfig("adb-peers", "tok-12345678", [m, a1, a2])
        snaps_a = [NodeSnapshot(n, online=True, health={"ready_for_jobs": True}) for n in [m, a1, a2]]
        env_a = build_cross_tier_env(snaps_a, cfg_a, for_node=a1)
        self.assertEqual(env_a["PHONECLUSTER_USB_MODE"], "adb")
        self.assertIn("usb2:3632=127.0.0.1:25005", env_a["PHONECLUSTER_USB_PEERS"])
        self.assertIn("usb2:50052=127.0.0.1:25006", env_a["PHONECLUSTER_USB_PEERS"])

    def test_verify_usb_hub_connectivity_rndis_peers_and_power_warning(self) -> None:
        m = NodeConfig(id="node0", host="10.77.1.1", role="master")
        u1 = NodeConfig(id="usb1", host="10.77.1.2", role="worker", tags=["worker", "usb-hub", "usb-mode:rndis"])
        u2 = NodeConfig(id="usb2", host="10.77.2.2", role="worker", tags=["worker", "usb-hub", "usb-mode:rndis"])
        ctrl = MasterController(ClusterConfig("ver", "tok-12345678", [m, u1, u2]))
        snaps = [
            NodeSnapshot(m, online=True, latency_ms=1.0, health={"ready_for_jobs": True}),
            NodeSnapshot(u1, online=True, latency_ms=1.2, health={"ready_for_jobs": True, "battery_pct": 52, "battery_status": "CHARGING"}),
            NodeSnapshot(u2, online=True, latency_ms=1.5, health={"ready_for_jobs": True, "battery_pct": 38, "battery_status": "DISCHARGING"}),
        ]

        def fake_exec(node, spec):
            other = "usb2" if node.id == "usb1" else "usb1"
            other_ip = "10.77.2.2" if node.id == "usb1" else "10.77.1.2"
            out = json.dumps({"links": [{"to": other, "host": other_ip, "port": 8765, "ok": True, "latency_ms": 1.1, "error": ""}]})
            return "ok", {"returncode": 0, "stdout": out}

        with (
            mock.patch.object(ctrl, "poll_health", return_value=snaps),
            mock.patch.object(ctrl, "exec_on_node", side_effect=fake_exec),
            mock.patch("phonecluster.usbhub.read_ipv4_forwarding_enabled", return_value=True),
        ):
            rep = verify_usb_hub_connectivity(ctrl)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["online_count"], 2)
        self.assertEqual(len(rep["peer_links"]), 2)
        self.assertTrue(all(lk["ok"] for lk in rep["peer_links"]))
        self.assertTrue(any("discharging on USB" in w for w in rep["warnings"]))

    def test_dashboard_usb_hub_setup_verify_watchdog_and_tab6_ui(self) -> None:
        self.assertIn("setSetupConnectionMode('usb')", DASHBOARD_HTML)
        self.assertIn("applyUsbHubSetup('adb')", DASHBOARD_HTML)
        self.assertIn("verifyUsbHubUi()", DASHBOARD_HTML)
        self.assertIn("toggleUsbWatchdog()", DASHBOARD_HTML)

        cfg = create_default_config(master_host="127.0.0.1", worker_hosts=[])
        fake_topo = {
            "adb_installed": True,
            "adb_devices": [{"serial": "SER_DASH", "state": "device", "model": "Pixel"}],
            "adb_ready_count": 1,
            "usb_net_interfaces": [],
            "usb_net_count": 0,
            "subnet_collisions": [],
            "ipv4_forwarding_enabled": False,
            "recommended_mode": "adb",
            "notes": [],
        }
        fake_prof = {"os_env": "ubuntu-touch", "remote_ssh_port": 22, "ssh_user": "phablet", "usb_power_warning": False}

        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "dash.json"
            save_config(cfg, cfg_p)
            ctrl = MasterController(cfg)
            dash = DashboardHTTPServer(("127.0.0.1", 0), ctrl, config_path=cfg_p, enable_pairing_beacon=False, enable_usb_watchdog=False)
            port = dash.server_address[1]
            th = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            th.start()
            try:
                def call(method: str, path: str, payload: dict | None = None) -> dict:
                    data = json.dumps(payload).encode("utf-8") if payload is not None else None
                    hdrs = {**build_auth_headers(cfg.auth_token)}
                    if data is not None:
                        hdrs["Content-Type"] = "application/json"
                    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=hdrs, method=method)
                    with urllib.request.urlopen(req, timeout=4.0) as resp:
                        return json.loads(resp.read().decode("utf-8"))

                with (
                    mock.patch("phonecluster.dashboard.detect_usb_hub_topology", return_value=fake_topo),
                    mock.patch("phonecluster.dashboard.probe_adb_device_profile", return_value=fake_prof),
                    mock.patch("phonecluster.dashboard.apply_adb_usb_hub", return_value={"ok": True, "applied": 2, "unchanged": 0, "failed": 0, "errors": []}),
                    mock.patch("phonecluster.usbhub.list_adb_devices", return_value=[]),
                ):
                    res_setup = call("POST", "/api/usb-hub/setup", {"mode": "adb", "start_watchdog": True})
                    self.assertEqual(res_setup["updated_nodes"], ["usb1"])
                    self.assertTrue(res_setup["watchdog"]["running"])

                    res_get = call("GET", "/api/usb-hub")
                    self.assertTrue(res_get["watchdog"]["running"])

                    res_stop = call("POST", "/api/usb-hub/watchdog", {"enabled": False})
                    self.assertFalse(res_stop["watchdog"]["running"])

                with mock.patch(
                    "phonecluster.dashboard.verify_usb_hub_connectivity",
                    return_value={"ok": True, "usb_node_count": 1, "online_count": 1, "nodes": [], "peer_links": [], "warnings": [], "summary": "1/1 USB phone(s) online"},
                ):
                    res_ver = call("POST", "/api/usb-hub/verify", {})
                    self.assertTrue(res_ver["ok"])
            finally:
                dash.shutdown()
                dash.server_close()
                th.join(timeout=2.0)

    def test_cli_systemd_unit_verify_and_script_status(self) -> None:
        unit_adb = generate_usb_hub_systemd_unit("adb", config_path="/etc/pc/cluster.json", repo_dir="/opt/phonecluster")
        self.assertIn("usb-hub serve", unit_adb)
        unit_rndis = generate_usb_hub_systemd_unit("rndis", subnet_prefix="10.88", nat_wan=True, wan_iface="eth0")
        self.assertIn("07_usb_hub_router.sh", unit_rndis)
        self.assertIn("--prefix 10.88", unit_rndis)
        self.assertIn("--nat-wan --wan-iface eth0", unit_rndis)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli_main(["usb-hub", "systemd-unit", "--mode", "rndis", "--subnet-prefix", "10.77"])
        self.assertEqual(rc, 0)
        self.assertIn("ExecStart=", buf.getvalue())

        p_st = subprocess.run(
            ["bash", str(REPO / "scripts" / "07_usb_hub_router.sh"), "status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(p_st.returncode, 0, p_st.stderr)
        self.assertIn("USB 3.0 Hub Router Live Status", p_st.stdout)
