import threading
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from phonecluster.config import SafetyConfig
from phonecluster.worker import BatteryGuardLoop, WorkerState


class BatteryGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.health = {
            "battery_pct": 43,
            "battery_status": "DISCHARGING",
            "battery_health": "GOOD",
            "temp_c": 34.0,
            "overheated": False,
        }
        self.state = WorkerState(
            node_id="node1",
            role="worker",
            auth_token="test",
            safety=SafetyConfig(battery_webhook_url="http://127.0.0.1/hook"),
            health_provider=lambda: self.health,
        )
        self.guard = BatteryGuardLoop(self.state, threading.Event())

    def test_hazards_override_low_charge_even_during_cooldown(self) -> None:
        with patch("phonecluster.worker._post_webhook", return_value=True) as post:
            self.guard.check_once()
            self.health["battery_health"] = "OVER_VOLTAGE"
            self.guard.check_once()
            self.health.update(battery_health="GOOD", overheated=True, temp_c=41.0)
            self.guard.check_once()
            self.health.update(overheated=False, temp_c=36.0)
            self.guard.check_once()

        events = [call.args[1]["event"] for call in post.call_args_list]
        self.assertEqual(events, [
            "charge_on", "charge_off", "battery_hazard", "thermal_throttle", "charge_on"
        ])

    def test_overheated_node_sends_off_with_missing_percentage(self) -> None:
        self.health.update(battery_pct=None, overheated=True, temp_c=41.0)
        with patch("phonecluster.worker._post_webhook", return_value=True) as post:
            self.guard.check_once()
        self.assertEqual([call.args[1]["event"] for call in post.call_args_list],
                         ["charge_off", "thermal_throttle"])

    def test_failed_webhook_retries_current_decision_without_duplicate_alerts(self) -> None:
        self.health.update(battery_status="CHARGING", battery_pct=65)
        success = MagicMock()
        success.__enter__.return_value.status = 204
        with patch("phonecluster.worker._WEBHOOK_OPENER.open",
                   side_effect=[URLError("temporary failure"), success]) as send, \
             patch("phonecluster.worker.time.monotonic") as clock:
            for timestamp, attempts in [(0, 1), (10, 1), (30, 2), (100, 2)]:
                clock.return_value = timestamp
                self.guard.check_once()
                self.assertEqual(send.call_count, attempts)
        self.assertEqual([alert["event"] for alert in self.state.recent_alerts], ["charge_off"])

    def test_failed_charge_on_is_not_replayed_if_phone_becomes_hot(self) -> None:
        with patch("phonecluster.worker._post_webhook", side_effect=[False, True, True]) as post, \
             patch("phonecluster.worker.time.monotonic") as clock:
            clock.return_value = 1
            self.guard.check_once()
            clock.return_value = 31
            self.health.update(overheated=True, temp_c=41.0)
            self.guard.check_once()
        self.assertEqual([call.args[1]["event"] for call in post.call_args_list],
                         ["charge_on", "charge_off", "thermal_throttle"])

    def test_hazard_retries_power_off_through_missing_readings_before_restoring_power(self) -> None:
        self.health.update(battery_health="OVER_VOLTAGE")
        with patch("phonecluster.worker._post_webhook", side_effect=[False, True, True, True]) as post, \
             patch("phonecluster.worker.time.monotonic") as clock:
            clock.return_value = 1
            self.guard.check_once()
            clock.return_value = 31
            self.health.update(battery_health="UNKNOWN")
            self.guard.check_once()
            self.health.update(battery_health="GOOD", telemetry_stale=True)
            self.guard.check_once()
            self.health.update(telemetry_stale=False, temp_c=None)
            self.guard.check_once()
            self.health.update(temp_c=34.0)
            self.guard.check_once()
        self.assertEqual([call.args[1]["event"] for call in post.call_args_list],
                         ["charge_off", "battery_hazard", "charge_off", "charge_on"])
