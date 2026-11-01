"""Read-only checkpoint tests. All synthetic fixtures are retained under work/."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
import uuid
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / "skills/colossus/scripts/portable_survey.py"
spec = importlib.util.spec_from_file_location("checkpoint_survey", source)
survey = importlib.util.module_from_spec(spec)
spec.loader.exec_module(survey)


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.base = source.parents[3] / "work" / ("retained-checkpoint-" + uuid.uuid4().hex)
        self.root = self.base / "root"
        self.root.mkdir(parents=True)
        self.control = self.root / "control.bin"
        self.control.write_bytes(b"preserved synthetic control")
        self.state = survey.run(survey.start([str(self.root)]), seconds=30)
        self.assertTrue(survey.summarize(self.state)["complete"])

    def write(self, state=None, raw=None):
        path = self.base / (uuid.uuid4().hex + ".json")
        path.write_text(raw if raw is not None else json.dumps(
            self.state if state is None else state), encoding="utf-8")
        return str(path)

    def test_round_trip_does_not_open_referenced_targets(self):
        path = self.write()
        original = survey.checked_stat
        def selected_only(value):
            self.assertEqual(str(value), path)
            return original(value)
        with patch.object(survey, "checked_stat", side_effect=selected_only), \
                patch.object(survey.os, "scandir", side_effect=AssertionError("target traversal")):
            loaded = survey.load(path, [str(self.root)])
        self.assertEqual(loaded, self.state)
        self.assertEqual(self.control.read_bytes(), b"preserved synthetic control")

    def test_partial_checkpoint_resumes(self):
        state = survey.run(survey.start([str(self.root)]), budget=1, seconds=30)
        loaded = survey.load(self.write(state), [str(self.root)])
        survey.run(loaded, seconds=30)
        self.assertTrue(survey.summarize(loaded)["complete"])

    def test_rejects_invalid_shapes(self):
        cases = [None, [], {}, {**self.state, "entries": []},
                 {**self.state, "validation_index": True},
                 {**self.state, "invocations": -1},
                 {**self.state, "started": float("inf")},
                 {**self.state, "phase": []},
                 {**self.state, "pending": [str(self.root)]},
                 {**self.state, "validation": []},
                 {**self.state, "roots": []}]
        for state in cases:
            with self.subTest(state=state), self.assertRaises(ValueError):
                survey.load(self.write(raw=json.dumps(state)))

    def test_rejects_invalid_rows(self):
        cases = [("signature", [1]), ("identity", "forged"), ("protected", False),
                 ("logical_bytes", -1), ("allocated_bytes", True),
                 ("categories", "build"), ("observed", None),
                 ("enumerated", 1), ("child_names_digest", "bad"),
                 ("path", str(self.base)), ("kind", "unknown")]
        for field, value in cases:
            state = copy.deepcopy(self.state)
            state["entries"][str(self.root)][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                survey.load(self.write(state))

    def test_rejects_duplicate_keys(self):
        raw = json.dumps(self.state)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            survey.load(self.write(raw='{"version":3,' + raw[1:]))

    def test_rejects_nonfinite_and_deep_json(self):
        for raw in ('{"x":NaN}', '[' * 2000 + '0' + ']' * 2000):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                survey.load(self.write(raw=raw))

    def test_rejects_oversize_before_open(self):
        path = self.write()
        with patch.object(survey, "CHECKPOINT_BYTE_LIMIT", 16), \
                patch("builtins.open", side_effect=AssertionError("unbounded read")):
            with self.assertRaisesRegex(ValueError, "limit"):
                survey.load(path)

    def test_rejects_paths_outside_scope(self):
        for field in ("pending", "validation", "failed_paths"):
            state = copy.deepcopy(self.state)
            state[field] = [str(self.base)]
            with self.subTest(field=field), self.assertRaises(ValueError):
                survey.load(self.write(state))

    def test_rejects_wrong_roots_platform_and_version(self):
        with self.assertRaises(ValueError):
            survey.load(self.write(), [str(self.base)])
        for field, value in (("platform", "other"), ("version", 2)):
            state = {**self.state, field: value}
            with self.assertRaises(ValueError):
                survey.load(self.write(state))

    def test_rejects_changed_open_file(self):
        path = self.write()
        real = survey.signature
        calls = 0
        def changed(value):
            nonlocal calls
            calls += 1
            result = real(value)
            if calls == 1:
                result[1] += 1
            return result
        with patch.object(survey, "signature", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "changed"):
                survey.load(path)

    def test_cli_refuses_before_creating_output(self):
        invalid = self.write(raw='[]')
        output = self.base / "must-not-exist.json"
        result = subprocess.run([sys.executable, str(source), "--root", str(self.root),
                                 "--resume", invalid, "--output", str(output)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(self.control.read_bytes(), b"preserved synthetic control")

    def test_invalid_before_refused_before_survey(self):
        invalid = self.write(raw='[]')
        args = [str(source), "--root", str(self.root), "--before", invalid,
                "--output", str(self.base / "unused.json")]
        with patch.object(sys, "argv", args), \
                patch.object(survey, "run", side_effect=AssertionError("survey started")):
            self.assertEqual(survey.main(), 1)

    def test_rejects_nul_path(self):
        state = copy.deepcopy(self.state)
        state["pending"] = [str(self.root / "bad") + "\x00"]
        with self.assertRaisesRegex(ValueError, "NUL"):
            survey.load(self.write(state))

    def test_discards_stored_derived_reports(self):
        state = {**self.state, "summary": {"complete": True},
                 "comparison": {"actual_reclaimed_free_space_bytes": 999}}
        loaded = survey.load(self.write(state))
        self.assertNotIn("summary", loaded)
        self.assertNotIn("comparison", loaded)


if __name__ == "__main__":
    unittest.main()
