"""Optional browser checks. Run with PYTHONPATH=. python3 tests/check_dashboard_controls.py."""

import shutil
import unittest
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from phonecluster.dashboard import DASHBOARD_HTML


class DashboardControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = sync_playwright().start()
        cls.addClassCleanup(cls.driver.stop)
        cls.browser = cls.driver.chromium.launch(executable_path=shutil.which("chromium"))
        cls.addClassCleanup(cls.browser.close)

    def setUp(self):
        self.page = self.browser.new_page()
        self.addCleanup(self.page.close)
        self.page.set_default_timeout(2500)
        self.page_errors = []
        self.page.on("pageerror", lambda exc: self.page_errors.append(str(exc)))
        self.nodes = [{"id": "phone-a", "role": "worker", "tier": 1, "host": "phone-a.test"}]
        self.jobs = []
        self.calls = []
        self.held = []
        self.hold_paths = set()
        self.responses = {
            "/api/terminal/exec": {"results": []},
            "/api/map": {"ok_count": 0, "fail_count": 1, "wall_sec": 1,
                         "results": [{"ok": False, "node_id": "phone-a", "label": "check",
                                      "stdout": "collection complete", "stderr": "assertion failed",
                                      "error": "worker detail"}]},
            "/api/pipeline": {"ok": True, "steps_completed": 1, "steps_total": 1,
                              "results": [{"ok": True, "name": "Submitted step", "step_index": 1,
                                           "node_id": "phone-a", "stdout": "output", "stderr": "warning"}]},
        }
        self.page.route("**/*", self.handle)
        self.page.add_init_script("sessionStorage.setItem('pc_token', 'fixture')")
        self.page.goto("http://dashboard.test/")
        expect(self.page.locator("article[data-node-id='phone-a']")).to_have_count(1)
        self.page.locator("#poll-select").select_option("0")

    def tearDown(self):
        self.assertEqual(self.page_errors, [])

    def handle(self, route):
        path = urlsplit(route.request.url).path
        if path == "/":
            route.fulfill(content_type="text/html", body=DASHBOARD_HTML)
        elif path == "/api/live":
            route.fulfill(json={"summary": {"cluster_name": "fixture", "timestamp": 1,
                                            "nodes": self.nodes, "nodes_total": len(self.nodes)},
                                "jobs": self.jobs})
        elif route.request.method == "POST":
            self.calls.append((path, route.request.post_data_json))
            if path in self.hold_paths:
                self.held.append(route)
            else:
                route.fulfill(json=self.responses.get(path, {}))
        else:
            route.fulfill(json={})

    def test_removed_terminal_target_requires_operator_choice(self):
        self.page.locator("[data-action='terminal']").click()
        command = self.page.locator("#term-input")
        command.fill("hostname")
        self.nodes = []
        self.page.get_by_role("button", name="Refresh", exact=True).click()
        expect(self.page.locator("article[data-node-id='phone-a']")).to_have_count(0)
        command.press("Enter")
        self.page.wait_for_function("!activeTermJob")
        self.assertEqual(self.calls, [])
        expect(command).to_have_value("hostname")
        expect(self.page.locator("#btn-term-run")).to_be_disabled()
        expect(self.page.locator("#term-target")).to_have_value("phone-a")
        self.page.locator("#term-target").select_option("auto")
        command.press("Enter")
        self.page.wait_for_function("!activeTermJob")
        self.assertEqual(self.calls[0][1]["target"], "auto")

    def test_unreachable_job_feed_keeps_available_rows(self):
        self.jobs = [{"node_id": "phone-a", "online": False, "active": [], "recent": []}]
        self.page.evaluate("refreshLive()")
        board = self.page.locator("#tasks-board-wrap")
        expect(board).to_contain_text("Job status unavailable for phone-a")
        expect(board).not_to_contain_text("No active or recent")
        self.jobs.append({"node_id": "phone-b", "online": True, "recent": [],
                          "active": [{"job_id": "job-7", "command": "example", "running_sec": 1}]})
        self.page.evaluate("refreshLive()")
        expect(board).to_contain_text("phone-a")
        expect(board).to_contain_text("job-7")

    def test_job_cancel_keeps_keyboard_focus_on_same_phone(self):
        job = {"job_id": "job-7", "command": "example", "running_sec": 1}
        self.jobs = [{"node_id": node, "online": True, "active": [job], "recent": []}
                     for node in ("phone-a", "phone-b")]
        self.page.evaluate("refreshLive()")
        # Use the table row to select the phone even on versions with an unnamed Cancel button.
        cancel = self.page.get_by_role("row").filter(has_text="phone-b").get_by_role("button")
        cancel.focus()
        self.jobs.reverse()
        self.page.evaluate("refreshLive()")
        expect(cancel).to_be_focused()
        self.jobs.pop(0)
        self.page.evaluate("refreshLive()")
        expect(self.page.locator("#btn-board-tasks")).to_be_focused()

    def test_batch_shortcut_while_pending(self):
        self.hold_paths.add("/api/map")
        self.page.locator("#tab-jobs").click()
        with self.page.expect_request("**/api/map"):
            self.page.locator("#btn-run-map").click()
        self.page.locator("#map-commands").press("Control+Enter")
        # Round-trip a separate request so pending requests reach the interceptor.
        self.page.evaluate("() => fetch('/fixture-barrier')")
        self.assertEqual(len(self.held), 1)
        self.held[0].fulfill(json=self.responses["/api/map"])
        expect(self.page.locator("#btn-run-map")).to_be_enabled()

    def test_batch_shows_both_output_streams_and_error(self):
        self.page.locator("#tab-jobs").click()
        self.page.locator("#btn-run-map").click()
        out = self.page.locator("#map-out")
        for message in ("collection complete", "assertion failed", "worker detail"):
            expect(out).to_contain_text(message)

    def test_pipeline_results_belong_to_submitted_draft(self):
        self.page.locator("#tab-jobs").click()
        self.hold_paths.add("/api/pipeline")
        with self.page.expect_request("**/api/pipeline"):
            self.page.locator("#btn-run-pipe").click()
        self.page.locator("#pipe-cmd-0").fill("echo edited")
        self.held[0].fulfill(json=self.responses["/api/pipeline"])
        expect(self.page.locator("#btn-run-pipe")).to_be_enabled()
        expect(self.page.locator("#pipe-flow .ok")).to_have_count(0)
        cards = self.page.locator("#pipe-results-cards")
        expect(cards).to_contain_text("Submitted step")
        expect(cards).to_contain_text("warning")
        self.hold_paths.clear()
        self.responses["/api/pipeline"] = {"error": "fixture refusal"}
        self.page.locator("#btn-run-pipe").click()
        expect(cards).to_contain_text("fixture refusal")
        expect(self.page.locator("#pipe-out")).to_have_text("")

    def test_raw_pipeline_draft_survives_navigation_and_requires_apply(self):
        self.page.set_viewport_size({"width": 390, "height": 844})
        self.page.locator("#tab-jobs").click()
        self.page.locator("#btn-toggle-pipe-json").click()
        raw = self.page.locator("#pipe-json")
        raw.fill("[invalid")
        apply_edits = self.page.get_by_role("button", name="Apply JSON to Visual Steps")
        apply_edits.click()
        expect(self.page.locator("#toast-msg")).to_contain_text("Invalid Pipeline JSON")
        expect(self.page.locator("#btn-run-pipe")).to_be_disabled()
        draft = '[{"name":"My draft","command":"echo draft","target":"phone-a"}]'
        raw.fill(draft)
        self.page.locator("#tab-overview").click()
        self.page.locator("#tab-jobs").click()
        expect(raw).to_have_value(draft)
        self.assertEqual(self.calls, [])
        apply_edits.click()
        expect(self.page.locator("#pipe-cmd-0")).to_have_value("echo draft")
        self.page.locator("#btn-toggle-pipe-json").click()
        raw.fill("discard me")
        self.page.get_by_role("button", name="Discard JSON edits and close").click()
        with self.page.expect_request("**/api/pipeline") as submission:
            self.page.locator("#btn-run-pipe").click()
        self.assertEqual(submission.value.post_data_json["steps"][0]["command"], "echo draft")

    def test_unknown_delivery_in_batch_and_pipeline(self):
        self.page.locator("#tab-jobs").click()
        self.responses["/api/map"]["results"][0]["outcome_unknown"] = True
        self.page.locator("#btn-run-map").click()
        expect(self.page.locator("#map-summary-chips")).to_contain_text("Unknown: 1")
        expect(self.page.locator("#map-summary-chips")).not_to_contain_text("FAIL")
        response = self.responses["/api/pipeline"]
        response["ok"] = False
        response["results"][0].update(ok=False, outcome_unknown=True)
        self.page.locator("#btn-run-pipe").click()
        expect(self.page.locator("#pipe-summary-chips")).to_contain_text("unconfirmed")
        expect(self.page.locator("#pipe-results-cards")).to_contain_text("Outcome unknown")
        self.page.locator("#pipe-details > summary").click()
        expect(self.page.locator("#pipe-out")).to_be_visible()

    def test_pending_policy_and_empty_fleet(self):
        self.page.locator("#tab-network").click()
        push = self.page.get_by_role("button", name="Push Live Policy to All Workers")
        for total, live, disk, tone in [(1, 1, 0, "warn"), (0, 0, 0, "warn"), (2, 2, 2, "ok")]:
            self.responses["/api/network/push-config"] = {
                "ok_count": live, "persisted_count": disk, "total": total, "results": []}
            with self.page.expect_response("**/api/network/push-config"):
                push.click()
            expect(self.page.locator("#toast")).to_have_class("toast " + tone)
            expected = f"{disk}/{total} saved to disk" if total else "No workers targeted"
            expect(self.page.locator("#toast-msg")).to_contain_text(expected)


if __name__ == "__main__":
    unittest.main()
