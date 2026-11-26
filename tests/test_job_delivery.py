"""Delivery and journaling regressions for interrupted worker connections."""

import contextlib
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from phonecluster import cli
from phonecluster.config import ClusterConfig, NodeConfig
from phonecluster.master import JobOutcome, JobSpec, MasterController, NodeSnapshot


class TestJobDelivery(unittest.TestCase):
    def setUp(self):
        self.nodes = [
            NodeConfig(id="node0", host="127.0.0.1", role="master", max_concurrency=1),
            NodeConfig(id="node1", host="127.0.0.2", role="worker", max_concurrency=1),
        ]
        config = ClusterConfig(cluster_name="delivery", auth_token="test-token-0123456789", nodes=self.nodes)
        self.controller = MasterController(config)
        snapshots = [
            NodeSnapshot(node, online=True, health={"ready_for_jobs": True, "tier": 1})
            for node in self.nodes
        ]
        self.poll = self.enter_patch(mock.patch.object(self.controller, "poll_health", return_value=snapshots))
        self.job = JobSpec(index=0, job_id="result-test", command="echo done")

    def enter_patch(self, patcher):
        self.addCleanup(patcher.stop)
        return patcher.start()

    def submit(self, mode, **kwargs):
        if mode == "run":
            return self.controller.run_single(self.job, target="best", **kwargs)[0]
        return self.controller.map_jobs([self.job], target="best", wait_for_ready_sec=0, **kwargs)[0]

    def success(self):
        return io.BytesIO(json.dumps({"job_id": self.job.job_id, "returncode": 0}).encode())

    @staticmethod
    def busy():
        return urllib.error.HTTPError("http://worker/exec", 503, "Busy", {}, io.BytesIO(b'{"error":"node_busy"}'))

    def test_lost_result_stops_dispatch_and_reports_job_identity(self):
        for mode in ("run", "map"):
            with self.subTest(mode=mode), mock.patch(
                "phonecluster.master._DIRECT_OPENER.open", side_effect=ConnectionResetError("lost response")
            ) as dispatch:
                result = self.submit(mode)
                dispatch.assert_called_once()
                self.assertTrue(result.to_dict()["outcome_unknown"])
                self.assertEqual(result.unconfirmed_nodes, [result.node_id])
                self.assertIn(self.job.job_id, result.error)
                self.assertFalse(result.ok)

    def test_worker_rejection_retries_and_explicit_replay_records_uncertainty(self):
        for mode in ("run", "map"):
            for retry_unknown in (False, True):
                with self.subTest(mode=mode, retry_unknown=retry_unknown), mock.patch(
                    "phonecluster.master._DIRECT_OPENER.open",
                    side_effect=[TimeoutError("result lost") if retry_unknown else self.busy(), self.success()],
                ) as dispatch:
                    result = self.submit(mode, retry_unknown=retry_unknown)
                    self.assertTrue(result.ok, result.error)
                    self.assertFalse(result.outcome_unknown)
                    self.assertEqual(result.attempts, 2)
                    self.assertEqual(dispatch.call_count, 2)
                    hosts = [call.args[0].host for call in dispatch.call_args_list]
                    self.assertNotEqual(*hosts)
                    self.assertEqual(len(result.unconfirmed_nodes), int(retry_unknown))

    def test_invalid_result_and_non_worker_503_are_ambiguous(self):
        for response in (
            io.BytesIO(b"truncated"),
            io.BytesIO(b'{"job_id":"different","returncode":0}'),
            urllib.error.HTTPError("http://worker/exec", 503, "Unavailable", {}, io.BytesIO(b"unavailable")),
        ):
            with self.subTest(response=response), mock.patch(
                "phonecluster.master._DIRECT_OPENER.open", side_effect=[response]
            ) as dispatch:
                result = self.submit("run")
                self.assertTrue(result.outcome_unknown)
                dispatch.assert_called_once()

    def test_unknown_survives_replay_when_workers_are_unavailable(self):
        self.poll.side_effect = [self.poll.return_value, []]
        with mock.patch("phonecluster.master._DIRECT_OPENER.open", side_effect=TimeoutError("lost")):
            result = self.submit("map", retry_unknown=True)
        self.assertTrue(result.outcome_unknown)
        self.assertEqual(len(result.unconfirmed_nodes), 1)
        self.assertEqual(result.attempts, 1)

    def test_cli_map_flushes_each_completion_before_interruption(self):
        with tempfile.TemporaryDirectory() as tempdir:
            output = Path(tempdir) / "nested" / "result.jsonl"

            def interrupted_map(jobs, *, on_result, retry_unknown, **kwargs):
                self.assertTrue(retry_unknown)
                completed = jobs[1]
                on_result(JobOutcome(completed.index, completed.job_id, completed.label, "node1", 0, 0.1), 1, 2)
                records = output.read_text().splitlines()
                self.assertEqual(len(records), 1)
                self.assertEqual(json.loads(records[0])["index"], 1)
                raise KeyboardInterrupt

            with mock.patch.object(cli, "load_config", return_value=self.controller.config), mock.patch.object(
                cli.MasterController, "map_jobs", side_effect=interrupted_map
            ), contextlib.redirect_stderr(io.StringIO()):
                status = cli.main(["map", "--retry-unknown", "--quiet", "--output-jsonl", str(output), "--repeat", "2", "echo"])
            self.assertEqual(status, 130)
            self.assertEqual(len(output.read_text().splitlines()), 1)

    def test_cli_map_preserves_existing_output_before_dispatch(self):
        with tempfile.TemporaryDirectory() as tempdir:
            output = Path(tempdir) / "results.jsonl"
            output.write_text("previous batch\n", encoding="utf-8")
            with mock.patch.object(cli, "load_config", return_value=self.controller.config), mock.patch.object(
                cli.MasterController, "map_jobs"
            ) as run, contextlib.redirect_stderr(io.StringIO()):
                status = cli.main(["map", "--target", "tier:99", "--output-jsonl", str(output), "--repeat", "1", "echo"])
            self.assertEqual(status, 2)
            run.assert_not_called()
            self.assertEqual(output.read_text(encoding="utf-8"), "previous batch\n")
