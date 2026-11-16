"""Dashboard Wi-Fi trace: the 't' job and the trace screen, driven headless.

Skipped where textual isn't installed (the plain CI test job only installs PyYAML).
"""
import asyncio
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_wireless as fx
from netauditor import wireless
from netauditor.inventory import Host

HAVE_TEXTUAL = importlib.util.find_spec("textual") is not None


@unittest.skipUnless(HAVE_TEXTUAL, "textual not installed")
class TestDashboardTrace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.log = self.dir / "IN2611.log"
        self.log.write_text("\n".join(fx.nps_lines()) + "\n", encoding="utf-8")
        self.saved = self.dir / "aps.txt"
        self.saved.write_text(fx.JOIN_STATS + "\n" + fx.AP_SUMMARY, encoding="utf-8")
        self.out = self.dir / "out"
        self.out.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def _app(self, controllers):
        from netauditor.ui import AuditUI
        return AuditUI([], inv_hosts=[], outdir=self.out, controllers=controllers)

    def test_trace_key_runs_job_and_opens_screen(self):
        from netauditor.ui import TraceScreen
        ctrl = Host(host=fx.NAS, name="WLC01", group="delahey", device_type="cisco_wlc_ssh",
                    nps_host="nps01", ap_list=str(self.saved))

        async def run():
            app = self._app([ctrl])
            app.trace_min_requests, app.trace_min_rejects = 20, 5   # fixture-sized thresholds
            with mock.patch.object(wireless, "nps_log_paths", return_value=[str(self.log)]), \
                    mock.patch.object(wireless, "nps_date", return_value=fx.DAY):
                async with app.run_test(size=(160, 50)) as pilot:
                    await pilot.press("t")
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                    screen = app.screen
                    self.assertIsInstance(screen, TraceScreen)
                    table = screen.query_one("#trace")
                    self.assertEqual(table.row_count, 2)
                    self.assertIn("DE-AP-LIB-07", str(table.get_row_at(0)))
                    detail = str(screen.query_one("#trdetail").render())
                    self.assertIn("Library upstairs", detail)
                    await pilot.press("b")   # by access point
                    self.assertEqual(screen.query_one("#trace").row_count, 2)
                    await pilot.press("escape")
                    await pilot.press("T")   # reopen the saved trace without re-running
                    await pilot.pause()
                    self.assertIsInstance(app.screen, TraceScreen)
            self.assertTrue((self.out / "trace.html").exists())

        asyncio.run(run())

    def test_trace_without_controllers_warns(self):
        async def run():
            app = self._app([])
            async with app.run_test() as pilot:
                with mock.patch.object(app, "notify") as notify:
                    await pilot.press("t")
                    await pilot.pause()
                    self.assertIn("controllers", notify.call_args[0][0])
                    self.assertFalse(app._busy)

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
