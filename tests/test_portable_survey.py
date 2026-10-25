import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

MODULE = Path(__file__).with_name("portable_survey.py")
if not MODULE.exists():
    MODULE = Path(__file__).resolve().parents[1] / "skills/colossus/scripts/portable_survey.py"
spec = importlib.util.spec_from_file_location("survey", MODULE)
survey = importlib.util.module_from_spec(spec)
spec.loader.exec_module(survey)


class SurveyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="colossus-survey-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "fixture"
        self.root.mkdir()

    def scan(self):
        return survey.run(survey.start([str(self.root)]), seconds=30)

    def test_resume_disjoint_totals_repeated_read_only(self):
        for name in ("build", "worktrees", "releases", ".venv", "models", "cache", "backups"):
            (self.root / name).mkdir()
            (self.root / name / "payload").write_bytes(b"payload")
        state = survey.start([str(self.root)])
        survey.run(state, seconds=0)
        self.assertEqual(state["stop_reason"], "deadline")
        self.assertFalse(survey.summarize(state)["complete"])
        for _ in range(50):
            survey.run(state, budget=2, seconds=30)
            if state["phase"] == "done":
                break
        self.assertTrue(survey.summarize(state)["complete"], state)
        totals = survey.summarize(state)
        self.assertEqual(totals["logical_bytes"], 49)
        self.assertEqual(sum(v["logical_bytes"] for v in totals["disjoint_top_level"].values()), 49)
        again = survey.summarize(self.scan())
        totals["coverage"].pop("validation_window")
        again["coverage"].pop("validation_window")
        self.assertEqual(totals, again)
        self.assertTrue(all(e["protected"] for e in state["entries"].values()))

    def test_hardlinks_count_once(self):
        a, b = self.root / "a", self.root / "b"
        a.write_bytes(b"12345")
        try:
            os.link(a, b)
        except OSError as error:
            self.skipTest(str(error))
        report = survey.summarize(self.scan())
        self.assertEqual(report["logical_bytes"], 5)
        self.assertEqual(report["hardlink_aliases"], 1)
        self.assertEqual(report["equal_size_review_groups"], [])

    def test_symlink_not_followed(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (outside / "private").write_bytes(b"not scanned")
        try:
            (self.root / "link").symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(str(error))
        state = self.scan()
        self.assertEqual(survey.summarize(state)["logical_bytes"], 0)
        self.assertTrue(any(i["code"] == "link_or_placeholder_skipped" for i in state["issues"]))

    def test_denial_recorded_without_retry(self):
        (self.root / "denied").mkdir()
        original = survey.os.scandir
        calls = []
        def denied(path):
            if Path(path).name == "denied":
                calls.append(path)
                raise PermissionError("synthetic denied")
            return original(path)
        with patch.object(survey.os, "scandir", side_effect=denied):
            state = self.scan()
            survey.run(state, seconds=30)
        self.assertEqual(len(calls), 1)
        self.assertFalse(survey.summarize(state)["complete"])
        self.assertEqual(state["issues"][0]["code"], "access_denied")

    def test_recovery_net_and_unknown(self):
        original = self.root / "original"
        original.write_bytes(b"x" * 16384)
        before = self.scan()
        original.unlink()  # Disposable synthetic fixture only.
        (self.root / "backups").mkdir()
        (self.root / "backups" / "retained").write_bytes(b"x" * 8192)
        after = self.scan()
        result = survey.compare(before, after)
        self.assertEqual(result["observed_net_allocation_reduction_bytes"],
                         survey.summarize(before)["allocated_known_bytes"] - survey.summarize(after)["allocated_known_bytes"])
        self.assertGreater(result["retained_recovery_hint_allocated_known_bytes"], 0)
        self.assertIsNone(result["actual_reclaimed_free_space_bytes"])
        after["issues"].append(dict(code="denied"))
        self.assertIsNone(survey.compare(before, after)["observed_net_allocation_reduction_bytes"])

    def test_sparse_and_unknown_allocation(self):
        p = self.root / "sparse"
        with p.open("wb") as stream:
            stream.seek(1024 * 1024)
            stream.write(b"x")
        state = self.scan()
        row = state["entries"][str(p)]
        self.assertEqual(row["logical_bytes"], 1024 * 1024 + 1)
        self.assertIn(row["allocation_method"], ("GetCompressedFileSizeW", "stat.st_blocks*512", "unsupported"))
        with patch.object(survey, "allocation", return_value=(None, "unavailable", "synthetic unavailable")):
            unknown = self.scan()
        self.assertEqual(survey.summarize(unknown)["allocated_unknown_files"], 1)
        self.assertIsNone(survey.compare(unknown, unknown)["observed_net_allocation_reduction_bytes"])

    def test_changed_resume_and_overlapping_roots(self):
        (self.root / "a").write_bytes(b"a")
        state = survey.start([str(self.root)])
        survey.run(state, budget=1, seconds=30)
        (self.root / "new").write_bytes(b"new")
        survey.run(state, seconds=30)
        self.assertFalse(survey.summarize(state)["complete"])
        self.assertTrue(any(i["code"] in {"stale_directory", "stale_or_unavailable_root"} for i in state["issues"]))
        with self.assertRaises(ValueError):
            survey.start([str(self.root), str(self.root / "child")])

    def test_checkpoint_scope_and_new_output(self):
        state = self.scan()
        output = Path(self.temp.name) / "checkpoint.json"
        survey.save_new(str(output), state)
        self.assertEqual(survey.load(output, [str(self.root)]), state)
        with self.assertRaises(FileExistsError):
            survey.save_new(str(output), state)
        with self.assertRaises(ValueError):
            survey.save_new(str(self.root / "report.json"), state)
        with self.assertRaises(ValueError):
            survey.load(output, [str(self.root / "other")])

    def test_active_retained_ambiguous_equal_size_not_clearance(self):
        for name in ("active", "retained", "ambiguous"):
            (self.root / name).write_bytes(b"same")
        state = self.scan()
        self.assertEqual(len(survey.summarize(state)["equal_size_review_groups"]), 1)
        self.assertTrue(all(r["protected"] for r in state["entries"].values()))
        self.assertFalse(any("eligible" in r for r in state["entries"].values()))

    def test_platform_fallback_and_placeholder_signals(self):
        self.assertEqual(survey.allocation("unused", SimpleNamespace(st_blocks=7)),
                         (3584, "stat.st_blocks*512", None))
        for attr in (0x400, 0x1000, 0x40000, 0x400000):
            self.assertTrue(survey.skipped(SimpleNamespace(st_mode=0o100644, st_file_attributes=attr)))
        with patch.object(survey.os, "name", "unsupported"):
            self.assertIsNone(survey.allocation("unused", SimpleNamespace())[0])

    def test_cancel_and_entry_limit_are_incomplete(self):
        (self.root / "a").write_bytes(b"a")
        state = survey.start([str(self.root)])
        survey.run(state, max_entries=1, seconds=30)
        self.assertEqual(state["stop_reason"], "total_entry_limit")
        self.assertFalse(survey.summarize(state)["complete"])
        with patch.object(survey.os, "scandir", side_effect=KeyboardInterrupt):
            survey.run(state, seconds=30)
        self.assertEqual(state["stop_reason"], "cancelled")
        self.assertTrue(state["pending"])

    def test_file_mutation_revalidation_and_forged_scope(self):
        p = self.root / "a"
        p.write_bytes(b"a")
        state = survey.start([str(self.root)])
        survey.run(state, budget=2, seconds=30)
        p.write_bytes(b"different")
        survey.run(state, seconds=30)
        self.assertFalse(survey.summarize(state)["complete"])
        state["pending"] = [str(Path(self.temp.name) / "outside")]
        output = Path(self.temp.name) / "tampered.json"
        survey.save_new(str(output), state)
        with self.assertRaises(ValueError):
            survey.load(output, [str(self.root)])

    @unittest.skipUnless(os.name == "nt", "Windows junction test")
    def test_junction_target_not_counted(self):
        target = Path(self.temp.name) / "outside"
        target.mkdir()
        (target / "payload").write_bytes(b"private")
        env = dict(os.environ, COLOSSUS_TEST_LINK=str(self.root / "junction"),
                   COLOSSUS_TEST_TARGET=str(target))
        proc = subprocess.run(["powershell", "-NoProfile", "-Command",
                               "New-Item -ItemType Junction -Path $env:COLOSSUS_TEST_LINK -Target $env:COLOSSUS_TEST_TARGET -ErrorAction Stop | Out-Null"],
                              env=env, capture_output=True, text=True)
        if proc.returncode:
            self.skipTest(proc.stderr)
        state = self.scan()
        self.assertEqual(survey.summarize(state)["logical_bytes"], 0)
        self.assertTrue(any(i["code"] == "link_or_placeholder_skipped" for i in state["issues"]))
        self.assertTrue((target / "payload").exists())

    def test_cli_checkpoint_and_completed_resume_refusal(self):
        output = Path(self.temp.name) / "complete.json"
        proc = subprocess.run([sys.executable, "-B", str(MODULE), "--root", str(self.root),
                               "--output", str(output), "--seconds", "30"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        resumed = subprocess.run([sys.executable, "-B", str(MODULE), "--root", str(self.root),
                                  "--resume", str(output), "--output", str(output.with_name("resumed.json"))],
                                 capture_output=True, text=True)
        self.assertEqual(resumed.returncode, 1)
        self.assertIn("completed checkpoint", resumed.stderr)

    def test_interrupt_between_directory_observation_and_queue(self):
        child = self.root / "build"
        child.mkdir()
        (child / "payload").write_bytes(b"must be counted")
        observe = survey.observe
        def interrupted(state, path):
            row = observe(state, path)
            if Path(path) == child:
                raise KeyboardInterrupt()
            return row
        state = survey.start([str(self.root)])
        with patch.object(survey, "observe", side_effect=interrupted):
            survey.run(state, seconds=30)
        self.assertEqual(state["stop_reason"], "cancelled")
        survey.run(state, seconds=30)
        self.assertTrue(survey.summarize(state)["complete"], state)
        self.assertEqual(survey.summarize(state)["logical_bytes"], len(b"must be counted"))

    def test_file_root_is_reported_not_crash(self):
        file = self.root / "file"
        file.write_bytes(b"file")
        state = survey.run(survey.start([str(file)]), seconds=30)
        summary = survey.summarize(state)
        self.assertFalse(summary["complete"])
        self.assertTrue(any(i["code"] == "invalid_root" for i in summary["issues"]))

    def test_denied_children_bounded_not_retried_across_batches(self):
        for n in range(5):
            (self.root / str(n)).write_bytes(b"x")
        original = survey.checked_stat
        calls = []
        def deny(path):
            if Path(path).name.isdigit():
                calls.append(str(path))
                raise PermissionError("synthetic child denial")
            return original(path)
        state = survey.start([str(self.root)])
        with patch.object(survey, "checked_stat", side_effect=deny):
            for _ in range(8):
                survey.run(state, budget=2, max_entries=4, seconds=30)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(calls), len(set(calls)))
        self.assertEqual(state["stop_reason"], "total_entry_limit")

    @unittest.skipUnless(os.name == "nt", "Windows path guard")
    def test_output_ads_and_device_names_rejected(self):
        state = self.scan()
        for name in ("report:stream", "NUL", "report.", "report "):
            with self.assertRaises((ValueError, OSError)):
                survey.save_new(str(Path(self.temp.name) / name), state)

    def test_unknown_subtotals_and_cli_comparison_explained(self):
        recovery = self.root / "backups"
        recovery.mkdir()
        (recovery / "blob").write_bytes(b"retained")
        with patch.object(survey, "allocation", return_value=(None, "unsupported", "synthetic unavailable")):
            state = self.scan()
        summary = survey.summarize(state)
        self.assertEqual(summary["disjoint_top_level"][str(recovery)]["allocated_unknown_files"], 1)
        self.assertEqual(survey.compare(state, state)["retained_recovery_hint_allocated_unknown_files"], 1)
        self.assertTrue(summary["review_candidates"][0]["blockers"])
        before = Path(self.temp.name) / "before.json"
        survey.save_new(str(before), self.scan())
        proc = subprocess.run([sys.executable, "-B", str(MODULE), "--root", str(self.root),
                               "--before", str(before), "--output", str(before.with_name("after.json")),
                               "--seconds", "30"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        presented = json.loads(proc.stdout)
        self.assertEqual(presented["comparison"]["observed_net_allocation_reduction_bytes"], 0)
        self.assertIn("issues", presented)

    def test_checkpoint_cursor_corruption_and_resume_root_replacement(self):
        state = self.scan()
        state["validation"] = []
        output = Path(self.temp.name) / "corrupt.json"
        survey.save_new(str(output), state)
        with self.assertRaises(ValueError):
            survey.load(output, [str(self.root)])
        inventory = survey.start([str(self.root)])
        inventory["validation_index"] = 1
        inventory_output = Path(self.temp.name) / "bad-inventory.json"
        survey.save_new(str(inventory_output), inventory)
        with self.assertRaises(ValueError):
            survey.load(inventory_output, [str(self.root)])
        pending = survey.start([str(self.root)])
        survey.run(pending, budget=1, seconds=30)
        original = survey.checked_stat
        def replaced(path):
            st = original(path)
            if Path(path) == self.root:
                values = {name: getattr(st, name) for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")}
                values["st_ino"] += 1
                values["st_file_attributes"] = getattr(st, "st_file_attributes", 0)
                return SimpleNamespace(**values)
            return st
        with patch.object(survey, "checked_stat", side_effect=replaced), patch.object(survey.os, "scandir") as scandir:
            survey.run(pending, seconds=30)
            scandir.assert_not_called()
        self.assertFalse(survey.summarize(pending)["complete"])
        self.assertTrue(any(i["code"] == "stale_or_unavailable_root" for i in pending["issues"]))

    def test_hardlinks_across_disjoint_roots_and_negative_delta(self):
        other = Path(self.temp.name) / "second"
        other.mkdir()
        a = self.root / "a"
        a.write_bytes(b"shared")
        try:
            os.link(a, other / "alias")
        except OSError as error:
            self.skipTest(str(error))
        state = survey.run(survey.start([str(self.root), str(other)]), seconds=30)
        result = survey.summarize(state)
        self.assertEqual(result["hardlink_aliases"], 1)
        self.assertEqual(result["logical_bytes"], 6)
        self.assertEqual(sum(v["logical_bytes"] for v in result["disjoint_top_level"].values()), 6)
        before = self.scan()
        (self.root / "extra").write_bytes(b"x" * 8192)
        after = self.scan()
        self.assertLess(survey.compare(before, after)["observed_net_allocation_reduction_bytes"], 0)
        self.assertIsNone(survey.compare(before, after)["actual_reclaimed_free_space_bytes"])


if __name__ == "__main__":
    unittest.main()
