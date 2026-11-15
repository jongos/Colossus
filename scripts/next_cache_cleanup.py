"""Opt-in, exact-file Next compiler-cache cleanup on Windows NTFS."""
import argparse
from contextlib import ExitStack
import csv
import io
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from next_cache_native import Handle, digest, new_output, path_check, read_control, require
from next_cache_git import git_run

MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 3 * 1024 * 1024 * 1024
MAX_FILES = 512
SCHEMA = "colossus-next-cache-2"
PROTECTED = {".git", ".hg", ".svn", "node_modules", ".pnpm-store", ".venv", "venv",
             ".aws", ".ssh", ".codex", ".cargo", ".npm", ".config", "credentials", "secrets"}
REVIEW_KEYS = {"runtime_independent", "retention_released", "regeneration_accepted", "basis"}


def exists(path):
    # lexists hides access errors; unknown policy must fail closed.
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False


def classify(value, root):
    p, root = path_check(value), path_check(root)
    require(not PROTECTED.intersection(x.casefold() for x in p.parts), "protected path")
    rel = p.relative_to(root)
    parts = rel.parts
    require(parts.count(".next") == 1, "one exact .next component required")
    n = parts.index(".next")
    require(not any(x.startswith(".") for x in p.parts[:p.parts.index(".next")]), "hidden project prefix refused")
    tail = "/".join(parts[n + 1:])
    require(bool(re.fullmatch(
        r"cache/(?:\.tsbuildinfo|webpack/(?:client|server|edge-server)-production/"
        r"(?:index|[0-9]+)\.pack(?:\.old)?|turbopack/[A-Za-z0-9_-]{1,128}/"
        r"(?:[0-9]+\.(?:sst|meta|del)|CURRENT|LOG))", tail)),
        "not an allowlisted compiler cache")
    return p, root.joinpath(*parts[:n])


def review_shape(review):
    require(isinstance(review, dict) and set(review) == REVIEW_KEYS, "unsupported review fields")
    require(all(review[x] is True for x in REVIEW_KEYS - {"basis"}), "unresolved runtime/retention/recovery review")
    require(isinstance(review["basis"], str) and 0 < len(review["basis"].strip()) <= 4096,
            "bounded review basis required")


def runtimes():
    script = ("$ErrorActionPreference='Stop'; "
              "$p=@(Get-CimInstance Win32_Process -ErrorAction Stop | "
              "Where-Object { $_.Name -match '^(node|nodejs|bun|deno|next)(\\.exe)?$' } | "
              "Select-Object ProcessId,Name); ConvertTo-Json -InputObject $p -Compress")
    r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, timeout=20, stdin=subprocess.DEVNULL,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    require(r.returncode == 0 and len(r.stdout) <= 1024 * 1024, "runtime inventory unavailable")
    data = json.loads(r.stdout.decode("utf-8-sig"))
    require(isinstance(data, list), "runtime inventory malformed")
    for row in data:
        require(isinstance(row, dict) and type(row.get("ProcessId")) is int
                and row["ProcessId"] > 0 and isinstance(row.get("Name"), str),
                "runtime inventory malformed")
    return data


def inactive(projects):
    require(not runtimes(), "Node/Bun/Deno/Next runtime active or unresolved")
    for project in projects:
        for rel in (".next/lock", ".next/dev/lock"):
            require(not exists(project / rel), "Next runtime lock exists")


class Session:
    def __init__(self, paths, root, *, deleting=False):
        self.stack = ExitStack()
        try:
            self.root = path_check(root)
            require(isinstance(paths, list) and 0 < len(paths) <= MAX_FILES, "target count refused")
            classified = [classify(p, self.root) for p in paths]
            require(len({p for p, _ in classified}) == len(paths), "duplicate target")
            self.projects = {project for _, project in classified}
            self.pins, self.policy, self.held = {}, {}, []
            self.ancestors = set()
            for p, _ in classified:
                for ancestor in reversed([p.parent, *p.parent.parents]):
                    self.pin(ancestor)
                    self.ancestors.add(ancestor)
            self.volume = self.pins[self.root].stat()["volume"]
            self.markers()
            self.database = self.root / ".git"
            self.pin(self.database)
            self.policy_file(self.database / "config", required=True)
            self.policy_file(self.database / "index")
            self.policy_file(self.database / "HEAD", required=True)
            if exists(self.database / "info"):
                self.pin(self.database / "info")
            self.policy_file(self.database / "info" / "exclude")
            for ancestor in self.ancestors:
                if ancestor.is_relative_to(self.root):
                    self.policy_file(ancestor / ".gitignore")
            self.git = path_check(shutil.which("git"))
            for ancestor in reversed([self.git.parent, *self.git.parent.parents]):
                self.pin(ancestor)
            gh = self.stack.enter_context(Handle(self.git, deny_write=True))
            require(not gh.stat()["directory"] and gh.stat()["links"] == 1, "invalid Git executable")
            self.git_hash = gh.fingerprint(MAX_FILE)
            require(Path(git_run(self.git, self.root, ["rev-parse", "--show-toplevel"]).decode("utf-8").strip())
                    == self.root, "Git root mismatch")
            total = 0
            for p, _ in classified:
                h = self.stack.enter_context(Handle(p, exclusive=True, delete=deleting))
                h.ntfs()
                s = h.stat()
                require(not s["directory"] and s["links"] == 1 and s["volume"] == self.volume
                        and 0 <= s["bytes"] <= MAX_FILE and s["allocated"] >= 0,
                        "file type/link/volume/size refused")
                self.membership(p)
                total += s["bytes"]
                require(total <= MAX_TOTAL, "plan byte budget exceeded")
                self.held.append((p, h, {"path": str(p), "stat": s, "sha256": h.fingerprint(MAX_FILE)}))
            self.recheck()
        except BaseException:
            self.stack.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stack.close()

    def pin(self, path):
        if path not in self.pins:
            h = self.stack.enter_context(Handle(path))
            h.ntfs()
            require(h.stat()["directory"], "invalid ancestor")
            self.pins[path] = h

    def policy_file(self, path, required=False):
        if path in self.policy:
            return
        if not exists(path):
            require(not required, "required Git policy missing")
            self.policy[path] = None
            return
        h = self.stack.enter_context(Handle(path, deny_write=True))
        h.ntfs()
        s = h.stat()
        require(not s["directory"] and s["links"] == 1 and s["bytes"] <= 1024 * 1024,
                "policy file type/link/size refused")
        raw = b"".join(h.chunks(1024 * 1024))
        require(h.stat() == s, "policy changed during read")
        if path == self.root / ".git" / "config":
            require(not re.search(rb"(?im)^\s*\[\s*(include|includeIf)\b", raw),
                    "external Git configuration refused")
            require(not re.search(rb"(?im)^\s*worktree\s*=", raw), "redirected Git worktree refused")
        self.policy[path] = (h, s, hashlib.sha256(raw).hexdigest())

    def markers(self):
        for ancestor in self.ancestors:
            require(not exists(ancestor / "colossus.artifacts.json"), "retention registry requires review")
            for marker in (".git", ".hg", ".svn"):
                if ancestor != self.root or marker != ".git":
                    require(not exists(ancestor / marker), "nested/external repository refused")
        for rel in ("commondir", "gitdir", "worktrees", "modules", "config.worktree",
                    "objects/info/alternates", "objects/info/http-alternates",
                    "index.lock", "config.lock", "HEAD.lock"):
            require(not exists(self.root / ".git" / rel), "shared/external/active Git metadata refused")

    def membership(self, path):
        rel = path.relative_to(self.root).as_posix()
        # Inspect all tracked paths to reject NTFS casing aliases and gitlink ancestors.
        rows = git_run(self.git, self.root, ["ls-files", "--stage", "-z"]).split(b"\0")
        for row in filter(None, rows):
            meta, name = row.split(b"\t", 1)
            tracked = name.decode("utf-8").casefold()
            require(tracked != rel.casefold(), "tracked file refused")
            if meta.split()[0] == b"160000":
                require(not rel.casefold().startswith(tracked + "/"), "submodule target refused")
        ignored = git_run(self.git, self.root,
                          ["ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", rel])
        require(ignored == rel.encode("utf-8") + b"\0", "target must be exactly ignored and untracked")

    def recheck(self, selected=None):
        self.markers()
        for path, record in self.policy.items():
            if record is None:
                require(not exists(path), "Git/ignore policy appeared")
            else:
                require(record[0].stat() == record[1], "Git/ignore policy changed")
        for p, h, record in self.held:
            require(h.stat() == record["stat"], "target changed")
            if selected is None or p == selected:
                self.membership(p)
        inactive(self.projects)

    def evidence(self):
        return {"targets": [record for _, _, record in self.held],
                "ancestors": {str(p): h.stat()["identity"] for p, h in self.pins.items()},
                "policy": {str(p): None if r is None else {"stat": r[1], "sha256": r[2]}
                           for p, r in self.policy.items()},
                "git_sha256": self.git_hash}


def make_plan(paths, root, review):
    review_shape(review)
    with Session(paths, root) as session:
        value = {"schema": SCHEMA, "operation": "permanent-delete-exact-next-cache",
                 "root": str(session.root), "review": review, "evidence": session.evidence()}
    value["digest"] = digest(value)
    return value


def validate_plan(value):
    require(isinstance(value, dict) and set(value) ==
            {"schema", "operation", "root", "review", "evidence", "digest"}, "unsupported plan fields")
    require(value["schema"] == SCHEMA and value["operation"] == "permanent-delete-exact-next-cache",
            "unsupported plan version/operation")
    review_shape(value["review"])
    require(value["digest"] == digest({k: v for k, v in value.items() if k != "digest"}),
            "plan digest mismatch")
    path_check(value["root"])
    e = value["evidence"]
    require(isinstance(e, dict) and set(e) == {"targets", "ancestors", "policy", "git_sha256"},
            "unsupported evidence fields")
    require(isinstance(e["targets"], list) and 0 < len(e["targets"]) <= MAX_FILES, "target count refused")
    for row in e["targets"]:
        require(isinstance(row, dict) and set(row) == {"path", "stat", "sha256"}, "unsupported target fields")
        classify(row["path"], value["root"])


def event(journal, row):
    journal.write(json.dumps(row) + "\n")
    journal.flush()
    os.fsync(journal.fileno())


def execute(value, receipt):
    validate_plan(value)
    require(sys.stdin.isatty() and sys.stdout.isatty(), "interactive terminal required; piped approval refused")
    with Session([x["path"] for x in value["evidence"]["targets"]], value["root"], deleting=True) as session:
        require(session.evidence() == value["evidence"], "stale plan; regenerate and review")
        # Open/pin the receipt before approval; any refusal leaves an empty or refusal receipt.
        stack, journal = new_output(receipt, session.root)
        with stack:
            print(json.dumps(value, indent=2))
            print("PERMANENT DELETION. Recovery is a future authorized rebuild, not restoration.")
            phrase = "DELETE " + value["digest"]
            require(input("Type " + phrase + ": ") == phrase, "approval mismatch")
            session.recheck()
            event(journal, {"event": "approved_preflight", "plan": value})
            for path, h, record in session.held:
                # Recheck all still-live targets and all mutable policy before each disposition.
                session.recheck(path)
                event(journal, {"event": "intent", **record})
                h.remove()
                h.close()
                require(not exists(path), "deletion outcome uncertain; do not retry")
                event(journal, {"event": "removed", **record})
                # Keep snapshots in the plan/receipt; exclude closed handles from later rechecks.
                session.held = [row for row in session.held if row[0] != path]
            event(journal, {"event": "complete", "files": len(value["evidence"]["targets"]),
                            "selected_allocation_bytes": sum(r["stat"]["allocated"] for r in value["evidence"]["targets"]),
                            "causal_reclaimed_bytes": None})


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=["plan", "execute"])
    ap.add_argument("--input", required=True)
    ap.add_argument("--root")
    ap.add_argument("--review", help="bounded JSON with explicit runtime/retention/recovery review")
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    if a.mode == "plan":
        require(a.root and a.review, "plan requires --root and --review")
        reader = csv.DictReader(io.StringIO(read_control(a.input)))
        require(reader.fieldnames == ["path"], "CSV must have exactly one path column")
        paths = []
        for row in reader:
            require(set(row) == {"path"} and isinstance(row["path"], str), "malformed CSV row")
            paths.append(row["path"])
            require(len(paths) <= MAX_FILES, "target count refused")
        value = make_plan(paths, a.root, json.loads(read_control(a.review)))
        stack, output = new_output(a.output, value["root"])
        with stack:
            json.dump(value, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps({"files": len(paths), "digest": value["digest"]}))
    else:
        require(a.root is None and a.review is None, "execute uses only the exact plan")
        execute(json.loads(read_control(a.input)), a.output)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("next-cache cleanup refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)
