"""Hosted-only tests. All writes/deletions are disposable synthetic CI fixtures."""
from contextlib import ExitStack
import copy
import ctypes
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import next_cache_cleanup as adapter
import next_cache_native as native

REVIEW = {"runtime_independent": True, "retention_released": True, "regeneration_accepted": True,
          "basis": "Disposable synthetic hosted-CI fixture; no production data or recovery requirement."}


def hosted_only():
    if not (os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Windows" and os.environ.get("RUNNER_TEMP")):
        raise RuntimeError("These tests run exclusively on disposable Windows GitHub-hosted CI fixtures")


class CacheSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        hosted_only()

    def setUp(self):
        self.fixture = Path(tempfile.mkdtemp(prefix="colossus-next-synthetic-", dir=os.environ["RUNNER_TEMP"]))
        self.root = self.fixture / "repo"
        self.root.mkdir()
        self.git("init", "-q")
        (self.root / ".gitignore").write_text(".next/\n", encoding="utf-8")
        self.target = self.root / ".next" / "cache" / "webpack" / "server-production" / "0.pack"
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"synthetic cache\n")
        self.source = self.root / "source.ts"
        self.source.write_bytes(b"preserve source")
        self.secret = self.root / ".env"
        self.secret.write_bytes(b"synthetic credential sentinel")
        self.other = self.target.with_name("1.pack")
        self.other.write_bytes(b"unselected synthetic cache")
        self.receipt = self.fixture / "receipt.jsonl"
        # Fixtures are left for runner disposal. No recursive cleanup code exists here.

    def git(self, *args):
        r = subprocess.run(["git", *args], cwd=self.root, capture_output=True, check=True)
        return r.stdout

    def plan(self, paths=None):
        return adapter.make_plan([str(self.target)] if paths is None else paths, str(self.root), REVIEW)

    def execute(self, plan, answer=None, receipt=None):
        hosted_only()
        targets = [Path(r["path"]) for r in plan["evidence"]["targets"]]
        self.assertTrue(all(p.is_relative_to(self.fixture) for p in targets))
        self.assertTrue(self.fixture.is_relative_to(Path(os.environ["RUNNER_TEMP"])))
        with patch.object(sys.stdin, "isatty", return_value=True), patch.object(sys.stdout, "isatty", return_value=True):
            with patch("builtins.input", side_effect=answer if callable(answer) else None,
                       return_value=answer if isinstance(answer, str) else "DELETE " + plan["digest"]):
                adapter.execute(plan, receipt or self.receipt)

    def assert_preserved(self):
        self.assertTrue(self.target.exists())
        self.assertEqual(self.source.read_bytes(), b"preserve source")
        self.assertEqual(self.secret.read_bytes(), b"synthetic credential sentinel")
        self.assertEqual(self.other.read_bytes(), b"unselected synthetic cache")

    def test_allowlist(self):
        for rel in (".next/cache/.tsbuildinfo", ".next/cache/webpack/client-production/index.pack.old",
                    ".next/cache/webpack/edge-server-production/12.pack", ".next/cache/turbopack/abc_1/12.sst",
                    ".next/cache/turbopack/abc/0.meta", ".next/cache/turbopack/abc/0.del",
                    ".next/cache/turbopack/abc/CURRENT", ".next/cache/turbopack/abc/LOG"):
            with self.subTest(rel=rel):
                self.assertEqual(adapter.classify(str(self.root / rel), self.root)[1], self.root)

    def test_refuse_source_credentials_dependencies_outputs(self):
        for rel in ("source.ts", ".env", ".next/server/app.js", ".next/static/app.js",
                    ".next/cache/.previewinfo", ".next/cache/.rscinfo", ".next/cache/credentials.json",
                    "node_modules/.next/cache/.tsbuildinfo", ".aws/.next/cache/.tsbuildinfo",
                    ".next/cache/turbopack/.ssh/CURRENT", ".next/nested/.next/cache/.tsbuildinfo"):
            with self.subTest(rel=rel), self.assertRaises(ValueError):
                adapter.classify(str(self.root / rel), self.root)

    def test_protected_root_cannot_bypass(self):
        for name in adapter.PROTECTED:
            root = self.fixture / name
            with self.subTest(name=name), self.assertRaises(ValueError):
                adapter.classify(str(root / ".next/cache/.tsbuildinfo"), root)

    def test_exact_paths_only(self):
        for raw in ("relative", "\\\\server\\share\\a", "C:relative", "C:/repo/a", "C:\\repo\\..\\a",
                    "C:\\repo\\.\\a", "C:\\repo\\\\a", "C:\\repo\\a:stream", "C:\\repo\\a.",
                    "C:\\repo\\NUL", "C:\\repo\\PROGRA~1", "C:\\repo\\*.pack", "C:\\repo\\a\x01"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                native.path_check(raw)
        with self.assertRaises(ValueError):
            adapter.classify(str(self.fixture / ".next/cache/.tsbuildinfo"), self.root)

    def test_duplicate_and_budget_refusals(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.plan([str(self.target), str(self.target).replace(str(self.root), str(self.root).upper())])
        with self.assertRaisesRegex(ValueError, "count"):
            self.plan([str(self.target)] * 513)
        with patch.object(adapter, "MAX_FILE", 2), self.assertRaises(ValueError):
            self.plan()
        with patch.object(adapter, "MAX_TOTAL", 2), self.assertRaisesRegex(ValueError, "budget"):
            self.plan()
        self.assert_preserved()

    def test_review_attestation_required(self):
        for key in ("runtime_independent", "retention_released", "regeneration_accepted"):
            review = dict(REVIEW, **{key: False})
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapter.make_plan([str(self.target)], str(self.root), review)
        with self.assertRaises(ValueError):
            adapter.make_plan([str(self.target)], str(self.root), dict(REVIEW, basis=""))

    def test_tracked_and_casing_alias_refused(self):
        self.git("add", "-f", str(self.target))
        with self.assertRaisesRegex(ValueError, "tracked"):
            self.plan()
        with self.assertRaisesRegex(ValueError, "tracked"):
            self.plan([str(self.target).replace(str(self.root), str(self.root).upper())])
        self.assert_preserved()

    def test_unignored_refused(self):
        (self.root / ".gitignore").write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "ignored"):
            self.plan()

    def test_retention_hold_inherited(self):
        for parent in (self.fixture, self.root, self.target.parent):
            hold = parent / "colossus.artifacts.json"
            hold.write_text("{}", encoding="utf-8")
            with self.subTest(parent=parent), self.assertRaisesRegex(ValueError, "retention"):
                self.plan()
        self.assert_preserved()

    def test_runtime_metadata_failure_and_malformed(self):
        for result in (subprocess.CompletedProcess([], 1, b"", b"failure"),
                       subprocess.CompletedProcess([], 0, b"", b""),
                       subprocess.CompletedProcess([], 0, b"null", b""),
                       subprocess.CompletedProcess([], 0, b"[{}]", b"")):
            with patch.object(adapter.subprocess, "run", return_value=result), self.assertRaises(ValueError):
                adapter.runtimes()
        with patch.object(adapter.subprocess, "run", side_effect=subprocess.TimeoutExpired("synthetic", 20)):
            with self.assertRaises(subprocess.TimeoutExpired):
                adapter.runtimes()

    def test_real_runtime_inventory_and_active_node(self):
        self.assertEqual(adapter.runtimes(), [])
        node = shutil.which("node")
        self.assertIsNotNone(node)
        process = subprocess.Popen([node, "-e", "setInterval(()=>{},1000)"], cwd=self.fixture,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with self.assertRaisesRegex(ValueError, "runtime active"):
                self.plan()
        finally:
            process.terminate()
            process.wait(timeout=15)
        self.assert_preserved()

    def test_runtime_locks(self):
        lock = self.root / ".next" / "lock"
        lock.write_text("synthetic", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "runtime lock"):
            self.plan()

    def test_native_exclusive_and_ancestor_locking(self):
        with adapter.Session([str(self.target)], self.root):
            with self.assertRaises(OSError):
                self.target.open("rb")
            with self.assertRaises(OSError):
                self.target.parent.rename(self.target.parent.with_name("moved"))
            with self.assertRaises(OSError):
                (self.root / ".gitignore").write_text("changed", encoding="utf-8")
        self.assert_preserved()

    def test_existing_open_handle_refused(self):
        with self.target.open("rb"):
            with self.assertRaises(OSError):
                self.plan()
        self.assert_preserved()

    def test_hardlink_refused(self):
        os.link(self.target, self.fixture / "hardlink.pack")
        with self.assertRaisesRegex(ValueError, "file type/link"):
            self.plan()
        self.assert_preserved()

    def test_directory_target_refused(self):
        path = self.target.with_name("2.pack")
        path.mkdir()
        with self.assertRaisesRegex(ValueError, "file type/link"):
            self.plan([str(path)])

    def junction(self, link, target):
        # Test-only command; both exact paths are within this fresh disposable fixture.
        self.assertTrue(link.is_relative_to(self.fixture) and target.is_relative_to(self.fixture))
        subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
                       check=True, capture_output=True)

    def test_reparse_ancestor_refused(self):
        link = self.root / "alias"
        self.junction(link, self.root / ".next")
        path = link / ".next" / "cache" / ".tsbuildinfo"
        # Root itself as a junction also must be refused before any Git policy.
        with self.assertRaises(ValueError):
            self.plan([str(path)])
        alias_root = self.fixture / "alias-root"
        self.junction(alias_root, self.root)
        with self.assertRaisesRegex(ValueError, "reparse"):
            adapter.make_plan([str(alias_root / self.target.relative_to(self.root))], str(alias_root), REVIEW)
        self.assert_preserved()

    def test_reparse_target_refused(self):
        link = self.target.with_name("3.pack")
        # Directory junction with an allowlisted filename exercises native target reparse rejection.
        self.junction(link, self.fixture)
        with self.assertRaisesRegex(ValueError, "reparse"):
            self.plan([str(link)])

    def test_shared_git_metadata_and_include_refused(self):
        (self.root / ".git" / "commondir").write_text("../other", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "shared/external"):
            self.plan()

    def test_git_include_refused(self):
        with (self.root / ".git/config").open("a", encoding="utf-8") as f:
            f.write("\n[include]\n path = ../external\n")
        with self.assertRaisesRegex(ValueError, "external Git configuration"):
            self.plan()

    def test_nested_repository_refused(self):
        (self.target.parent / ".git").mkdir()
        with self.assertRaisesRegex(ValueError, "nested/external"):
            self.plan()

    def test_stale_target_refused(self):
        plan = self.plan()
        self.target.write_bytes(b"changed synthetic cache")
        with self.assertRaisesRegex(ValueError, "stale plan"):
            self.execute(plan)
        self.assert_preserved()

    def test_stale_policy_and_ancestor_refused(self):
        plan = self.plan()
        (self.root / ".gitignore").write_text(".next/\n# changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "stale plan"):
            self.execute(plan)
        self.assert_preserved()

    def test_plan_schema_and_digest(self):
        original = self.plan()
        for key, val in (("schema", "other"), ("operation", "other"), ("digest", "0" * 64)):
            plan = copy.deepcopy(original)
            plan[key] = val
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.execute(plan)
        self.assert_preserved()

    def test_piped_approval_refused(self):
        plan = self.plan()
        with patch.object(sys.stdin, "isatty", return_value=False), self.assertRaisesRegex(ValueError, "interactive"):
            adapter.execute(plan, self.receipt)
        self.assert_preserved()

    def test_wrong_approval_refused(self):
        with self.assertRaisesRegex(ValueError, "approval mismatch"):
            self.execute(self.plan(), "DELETE wrong")
        self.assert_preserved()

    def test_hold_added_during_approval_refused(self):
        def answer(_):
            (self.root / "colossus.artifacts.json").write_text("{}", encoding="utf-8")
            return "DELETE " + plan["digest"]
        plan = self.plan()
        with self.assertRaisesRegex(ValueError, "retention"):
            self.execute(plan, answer)
        self.assert_preserved()

    def test_ignore_added_during_approval_refused(self):
        def answer(_):
            (self.target.parent / ".gitignore").write_text("!0.pack\n", encoding="utf-8")
            return "DELETE " + plan["digest"]
        plan = self.plan()
        with self.assertRaisesRegex(ValueError, "policy appeared"):
            self.execute(plan, answer)
        self.assert_preserved()

    def test_runtime_started_during_approval_refused(self):
        plan = self.plan()
        with patch.object(adapter, "runtimes", side_effect=[[], [{"ProcessId": 1, "Name": "node.exe"}]]):
            with self.assertRaisesRegex(ValueError, "runtime active"):
                self.execute(plan)
        self.assert_preserved()

    def test_control_paths_refused(self):
        plan = self.plan()
        for output in ("relative.json", self.root / "receipt.jsonl"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.execute(plan, receipt=output)
        link = self.fixture / "output-link"
        self.junction(link, self.root)
        with self.assertRaisesRegex(ValueError, "reparse"):
            self.execute(plan, receipt=link / "receipt.jsonl")
        self.receipt.write_bytes(b"existing receipt")
        with self.assertRaises(OSError):
            self.execute(plan)
        self.assertEqual(self.receipt.read_bytes(), b"existing receipt")
        self.assert_preserved()

    def test_control_read_bounds_and_links(self):
        control = self.fixture / "control.json"
        control.write_bytes(b"x" * (native.MAX_CONTROL + 1))
        with self.assertRaisesRegex(ValueError, "control file"):
            native.read_control(control)
        control.write_bytes(b"{}")
        os.link(control, self.fixture / "control-link.json")
        with self.assertRaisesRegex(ValueError, "control file"):
            native.read_control(control)

    def test_receipt_native_lock_held_during_approval(self):
        plan = self.plan()
        def answer(_):
            with self.assertRaises(OSError):
                self.receipt.open("rb")
            with self.assertRaises(OSError):
                self.receipt.rename(self.fixture / "moved-receipt")
            return "no"
        with self.assertRaisesRegex(ValueError, "approval mismatch"):
            self.execute(plan, answer)
        self.assert_preserved()

    def test_receipt_failure_prevents_deletion(self):
        plan = self.plan()
        with patch.object(adapter.os, "fsync", side_effect=OSError("synthetic flush failure")):
            with self.assertRaises(OSError):
                self.execute(plan)
        self.assert_preserved()

    def test_disposition_failure_leaves_durable_intent(self):
        plan = self.plan()
        with patch.object(native.Handle, "remove", side_effect=OSError("synthetic disposition failure")):
            with self.assertRaises(OSError):
                self.execute(plan)
        events = [json.loads(s) for s in self.receipt.read_text().splitlines()]
        self.assertEqual([e["event"] for e in events], ["approved_preflight", "intent"])
        self.assert_preserved()

    def test_synthetic_success_exact_selection_and_receipts(self):
        second = self.target.with_name("2.pack")
        second.write_bytes(b"second selected synthetic cache")
        plan = self.plan([str(self.target), str(second)])
        sync = os.fsync
        with patch.object(adapter.os, "fsync", wraps=sync) as synced:
            self.execute(plan)
        self.assertEqual(synced.call_count, 6)
        self.assertFalse(self.target.exists())
        self.assertFalse(second.exists())
        self.assertEqual(self.source.read_bytes(), b"preserve source")
        self.assertEqual(self.secret.read_bytes(), b"synthetic credential sentinel")
        self.assertEqual(self.other.read_bytes(), b"unselected synthetic cache")
        self.assertTrue(self.target.parent.is_dir())
        events = [json.loads(s) for s in self.receipt.read_text().splitlines()]
        self.assertEqual([e["event"] for e in events],
                         ["approved_preflight", "intent", "removed", "intent", "removed", "complete"])
        self.assertEqual(events[0]["plan"], plan)
        self.assertEqual(events[-1]["files"], 2)
        self.assertIsNone(events[-1]["causal_reclaimed_bytes"])
        for intent, removed in ((events[1], events[2]), (events[3], events[4])):
            self.assertEqual(intent["stat"], removed["stat"])
            self.assertEqual(intent["sha256"], removed["sha256"])


if __name__ == "__main__":
    hosted_only()
    unittest.main(verbosity=2)
