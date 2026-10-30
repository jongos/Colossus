"""Non-deleting regressions: all synthetic fixture directories are retained."""
import importlib.util
from pathlib import Path
import stat
import uuid
import unittest
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / "skills/colossus/scripts/portable_survey.py"
spec = importlib.util.spec_from_file_location("survey_membership", source)
survey = importlib.util.module_from_spec(spec)
spec.loader.exec_module(survey)

class MembershipTests(unittest.TestCase):
    def setUp(self):
        self.root = source.parents[3] / "work" / ("retained-membership-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        (self.root / "a").write_bytes(b"synthetic")
        original = survey.signature
        def coarse(s):
            result = original(s)
            if stat.S_ISDIR(s.st_mode):
                result[3:5] = [0, 0]
            return result
        self.mock = patch.object(survey, "signature", side_effect=coarse)
        self.mock.start()
        self.addCleanup(self.mock.stop)  # Mock restoration only; no file removal.

    def test_same_tick_addition_during_resume(self):
        state = survey.start([str(self.root)])
        survey.run(state, budget=1, seconds=30)
        (self.root / "new").write_bytes(b"new")
        survey.run(state, seconds=30)
        self.assertFalse(survey.summarize(state)["complete"])
        self.assertTrue(any(i["code"] == "stale_or_unavailable_root" for i in state["issues"]))

    def test_same_tick_nested_addition_during_revalidation(self):
        child = self.root / "nested"
        child.mkdir()
        state = survey.run(survey.start([str(self.root)]), seconds=30)
        self.assertTrue(survey.summarize(state)["complete"])
        (child / "new").write_bytes(b"new")
        state["phase"] = "revalidation"
        state["validation_index"] = 0
        survey.run(state, seconds=30)
        self.assertFalse(survey.summarize(state)["complete"])
        self.assertTrue(any(i["code"] == "changed" for i in state["issues"]))

    def test_unchanged_small_batches_finish(self):
        state = survey.start([str(self.root)])
        for _ in range(10):
            survey.run(state, budget=1, seconds=30)
            if state["phase"] == "done":
                break
        self.assertTrue(survey.summarize(state)["complete"], state)
        self.assertEqual((self.root / "a").read_bytes(), b"synthetic")

    def test_membership_limit_fails_closed(self):
        (self.root / "b").write_bytes(b"synthetic")
        with patch.object(survey, "MEMBERSHIP_LIMIT", 1):
            state = survey.run(survey.start([str(self.root)]), seconds=30)
        self.assertFalse(survey.summarize(state)["complete"])
        self.assertTrue(state["issues"])

if __name__ == "__main__":
    unittest.main()
