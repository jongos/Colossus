#!/usr/bin/env python3
"""Colossus metadata survey. No content reads, deletion, or cleanup eligibility.

Python 3.10+; checkpoint JSON is local evidence, never an authorization token.
"""
import argparse
import collections
import ctypes
import json
import hashlib
import os
from pathlib import Path
import stat
import sys
import time

VERSION = 3
MEMBERSHIP_LIMIT = 10000
SKIP_ATTRIBUTES = 0x400 | 0x1000 | 0x40000 | 0x400000
CATEGORIES = {
    "build": {"build", "dist", "target", "out", "output"},
    "work_checkout": {"work", "worktrees", ".worktrees", "checkouts"},
    "release": {"release", "releases"},
    "tool_environment": {"tools", ".venv", "venv", "node_modules"},
    "model": {"models", "weights"},
    "cache": {"cache", ".cache", "__pycache__"},
    "recovery": {"recovery", "backup", "backups", "quarantine"},
}


def signature(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns,
            getattr(s, "st_file_attributes", 0)]


def child_names_digest(path):
    """Bounded membership evidence independent of directory timestamp resolution."""
    names = []
    deadline = time.monotonic() + 1.0
    with os.scandir(path) as children:
        for child in children:
            if len(names) >= MEMBERSHIP_LIMIT or time.monotonic() >= deadline:
                raise OSError("directory membership verification limit; coverage unresolved")
            names.append(child.name)
    return hashlib.sha256(json.dumps(sorted(names), ensure_ascii=True).encode("ascii")).hexdigest()


def unchanged(path, row):
    return (signature(checked_stat(path)) == row["signature"] and
            (row["kind"] != "directory" or
             child_names_digest(path) == row.get("child_names_digest")))


def skipped(s):
    return stat.S_ISLNK(s.st_mode) or bool(getattr(s, "st_file_attributes", 0) & SKIP_ATTRIBUTES)


def validate_path(path):
    p = Path(path)
    if not p.is_absolute() or ".." in p.parts:
        raise ValueError("absolute paths without parent components required")
    if os.name == "nt":
        if str(p).startswith("\\\\"):
            raise ValueError("network/device paths unsupported")
        for component in p.parts[1:]:
            stem = component.split(".")[0].upper()
            if (":" in component or component.endswith((".", " ")) or
                    stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} or
                    (stem[:3] in {"COM", "LPT"} and stem[3:] in "123456789" and len(stem) == 4)):
                raise OSError("ambiguous/device/stream path refused")


def checked_stat(path):
    """Reject observed ancestor links/placeholders; not a race-proof pin."""
    validate_path(path)
    p = Path(path)
    for ancestor in reversed(p.parents):
        if skipped(os.lstat(ancestor)):
            raise OSError("link/reparse/offline ancestor; traversal refused")
    return os.lstat(p)


def allocation(path, s):
    if hasattr(s, "st_blocks"):
        return s.st_blocks * 512, "stat.st_blocks*512", None
    if os.name == "nt":
        # GetCompressedFileSizeW reports sparse/compressed allocation, unlike
        # rounding logical size to a cluster. Failures must remain unknown.
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        fn = api.GetCompressedFileSizeW
        fn.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
        fn.restype = ctypes.c_ulong
        high = ctypes.c_ulong()
        ctypes.set_last_error(0)
        low = fn(str(path), ctypes.byref(high))
        error = ctypes.get_last_error()
        if low == 0xffffffff and error:
            return None, "unavailable", f"Win32 error {error}"
        return (high.value << 32) | low, "GetCompressedFileSizeW", None
    return None, "unsupported", "no supported allocated-size API"


def categories(path):
    parts = {p.lower() for p in Path(path).parts}
    result = [k for k, names in CATEGORIES.items() if parts & names]
    if Path(path).suffix.lower() in {".zip", ".gz", ".tar", ".7z", ".xz", ".bak"}:
        result.append("archive")
    return result or ["unclassified"]


def normalize_roots(roots):
    result = []
    for value in roots:
        p = Path(value)
        if not p.is_absolute() or ".." in p.parts:
            raise ValueError("explicit absolute roots without parent components required")
        value = os.path.normpath(str(p))
        if os.name == "nt" and (value.startswith("\\\\") or ":" in value[2:]):
            raise ValueError("network/device/stream paths unsupported")
        if any(Path(value).is_relative_to(other) or Path(other).is_relative_to(value) for other in result):
            raise ValueError("roots must be disjoint; overlapping or duplicate root")
        result.append(value)
    if not result:
        raise ValueError("at least one root required")
    return sorted(result)


def in_scope(path, roots):
    return any(Path(path).is_relative_to(Path(root)) for root in roots)


def start(roots):
    roots = normalize_roots(roots)
    return dict(version=VERSION, roots=roots, started=time.time(), ended=None,
                platform=sys.platform, entries={}, pending=list(roots), issues=[],
                failed_paths=[],
                validation=[], validation_index=0, phase="inventory", stop_reason=None,
                invocations=0)


def issue(state, path, code, detail):
    value = dict(path=str(path), code=code, detail=str(detail))
    if value not in state["issues"]:
        state["issues"].append(value)


def observe(state, path):
    s = checked_stat(path)
    row = dict(path=path, signature=signature(s), identity=None,
               logical_bytes=0, allocated_bytes=None, allocation_method=None,
               hard_links=s.st_nlink, categories=categories(path),
               observed=time.time(), protected=True)
    row["identity"] = f"{s.st_dev}:{s.st_ino}" if s.st_ino else None
    if skipped(s):
        row["kind"] = "link_or_placeholder"
        issue(state, path, "link_or_placeholder_skipped", "target not traversed or hydrated")
    elif stat.S_ISDIR(s.st_mode):
        row["kind"] = "directory"
        row["enumerated"] = False
        row["child_names_digest"] = child_names_digest(path)
    elif stat.S_ISREG(s.st_mode):
        row["kind"] = "file"
        row["logical_bytes"] = s.st_size
        row["allocated_bytes"], row["allocation_method"], error = allocation(path, s)
        if error:
            issue(state, path, "allocation_unknown", error)
        if signature(checked_stat(path)) != signature(s):
            issue(state, path, "changed", "metadata changed during allocation observation")
    else:
        row["kind"] = "special"
        issue(state, path, "special_skipped", "not a regular file or directory")
    if row["identity"] is None:
        issue(state, path, "identity_unknown", "cannot deduplicate hardlinks reliably")
    state["entries"][path] = row
    return row


def run(state, budget=10000, seconds=10, max_entries=1000000):
    if budget <= 0 or seconds < 0 or max_entries <= 0:
        raise ValueError("positive entry budgets and nonnegative seconds required")
    begin = time.monotonic()
    work = 0
    state["stop_reason"] = None
    state["invocations"] += 1
    failed = set(state["failed_paths"])
    # Reconcile the frontier after an interruption between observing a directory
    # and queuing it. Every observed, unenumerated directory is still owed a visit.
    if state["phase"] == "inventory":
        owed = list(state["pending"])
        for path, row in state["entries"].items():
            root = next(r for r in state["roots"] if Path(path).is_relative_to(r))
            same_device = row["signature"][0] == state["entries"].get(root, row)["signature"][0]
            if not same_device:
                issue(state, path, "filesystem_boundary", "not traversed")
            if row["kind"] == "directory" and not row["enumerated"] and same_device and path not in failed:
                owed.append(path)
        state["pending"] = list(dict.fromkeys(owed))
    # A resumed frontier is not authority to traverse a replaced root. This check
    # is independent of the resumable final per-entry validation cursor.
    if state["invocations"] > 1:
        for root in state["roots"]:
            row = state["entries"].get(root)
            if row is None or root in failed:
                continue
            try:
                if not unchanged(root, row):
                    raise OSError("root metadata/identity changed; start a fresh survey")
            except OSError as error:
                issue(state, root, "stale_or_unavailable_root", error)
                state["failed_paths"].append(root)
                failed.add(root)
        state["pending"] = [p for p in state["pending"]
                            if not any(Path(p).is_relative_to(r) for r in failed if r in state["roots"])]

    def capacity():
        # Conservatively count failures even when their directory metadata exists.
        return len(state["entries"]) + len(failed) >= max_entries

    def stop():
        if time.monotonic() - begin >= seconds:
            state["stop_reason"] = "deadline"
        elif work >= budget:
            state["stop_reason"] = "batch_limit"
        return state["stop_reason"] is not None

    try:
        while state["pending"] and not stop():
            path = state["pending"][0]
            try:
                row = state["entries"].get(path)
                if row is None:
                    if capacity():
                        state["stop_reason"] = "total_entry_limit"
                        break
                    work += 1
                    row = observe(state, path)
                if path in state["roots"] and row["kind"] != "directory":
                    issue(state, path, "invalid_root", "root must be a local directory")
                if row["kind"] != "directory":
                    state["pending"].pop(0)
                    continue
                if row["enumerated"] or any(Path(path).is_relative_to(p) for p in failed):
                    state["pending"].pop(0)
                    continue
                if not unchanged(path, row):
                    issue(state, path, "stale_directory", "directory changed; restart a fresh survey")
                    state["failed_paths"].append(path)
                    failed.add(path)
                    state["pending"].pop(0)
                    continue
                # Restart enumeration after suspension; previously observed entries
                # are skipped. No recursive iterator or unbounded directory list.
                with os.scandir(path) as children:
                    for child in children:
                        if stop():
                            break
                        if child.path in state["entries"] or child.path in state["failed_paths"]:
                            continue
                        if capacity():
                            state["stop_reason"] = "total_entry_limit"
                            break
                        work += 1
                        try:
                            item = observe(state, child.path)
                            if item["signature"][0] != row["signature"][0]:
                                issue(state, child.path, "filesystem_boundary", "not traversed")
                            elif item["kind"] == "directory":
                                state["pending"].append(child.path)
                        except OSError as error:
                            state["failed_paths"].append(child.path)
                            failed.add(child.path)
                            issue(state, child.path, "access_denied" if isinstance(error, PermissionError)
                                  else "metadata_error", error)
                    else:
                        row["enumerated"] = True
                        state["pending"].pop(0)
            except OSError as error:
                state["failed_paths"].append(path)
                failed.add(path)
                issue(state, path, "access_denied" if isinstance(error, PermissionError)
                      else "metadata_error", error)
                state["pending"].pop(0)
        if not state["pending"] and state["phase"] == "inventory":
            state["validation"] = list(state["entries"])
            state["phase"] = "revalidation"
        while state["phase"] == "revalidation" and not stop():
            index = state["validation_index"]
            if index == len(state["validation"]):
                state["phase"] = "done"
                break
            path = state["validation"][index]
            if any(Path(path).is_relative_to(r) for r in failed):
                state["validation_index"] += 1
                continue
            try:
                if not unchanged(path, state["entries"][path]):
                    issue(state, path, "changed", "metadata changed since inventory")
            except OSError as error:
                state["failed_paths"].append(path)
                failed.add(path)
                issue(state, path, "revalidation_error", error)
            state["entries"][path]["validated_at"] = time.time()
            state["validation_index"] += 1
            work += 1
    except KeyboardInterrupt:
        state["stop_reason"] = "cancelled"
    state["ended"] = time.time()
    return state


def summarize(state):
    seen = set()
    logical = allocated = unknown = aliases = 0
    groups = collections.defaultdict(lambda: dict(logical_bytes=0, allocated_known_bytes=0,
                                                allocated_unknown_files=0, files=0))
    sizes = collections.defaultdict(list)
    for path, row in state["entries"].items():
        if row["kind"] != "file":
            continue
        key = row["identity"] or path
        if key in seen:
            aliases += 1
            continue
        seen.add(key)
        logical += row["logical_bytes"]
        allocated += row["allocated_bytes"] or 0
        unknown += row["allocated_bytes"] is None
        sizes[row["logical_bytes"]].append(path)
        root = next(r for r in state["roots"] if Path(path).is_relative_to(r))
        rel = Path(path).relative_to(root)
        group = str(Path(root) / rel.parts[0]) if rel.parts else root
        groups[group]["files"] += 1
        groups[group]["logical_bytes"] += row["logical_bytes"]
        groups[group]["allocated_known_bytes"] += row["allocated_bytes"] or 0
        groups[group]["allocated_unknown_files"] += row["allocated_bytes"] is None
    review = [dict(path=path, category_hints=categories(path),
                   observation=f"{g['files']} uniquely counted files; allocation is a known subtotal with {g['allocated_unknown_files']} unknown files.",
                   proposed_operation="investigate", protected=True,
                   blockers=["source-of-truth role and ownership unresolved", "retention and current-use review required",
                             "dependencies and restoration evidence required"],
                   next_evidence="Inspect scoped provenance/retention records; compare only explicitly selected file contents. Names and size do not establish waste.")
              for path, g in groups.items()]
    validations = [r["validated_at"] for r in state["entries"].values() if "validated_at" in r]
    covered = all(r["kind"] != "directory" or r["enumerated"] for r in state["entries"].values())
    return dict(complete=state["phase"] == "done" and covered and not state["issues"] and not state["failed_paths"],
                coverage=dict(phase=state["phase"], stop_reason=state["stop_reason"],
                              observed_entries=len(state["entries"]),
                              failed_paths=state["failed_paths"],
                              validation_window=[min(validations), max(validations)] if validations else None,
                              atomic_or_fresh_snapshot=False,
                              pending_directories=state["pending"],
                              total_entries=None, unscanned_count=None),
                logical_bytes=logical, allocated_known_bytes=allocated,
                allocated_unknown_files=unknown, hardlink_aliases=aliases,
                allocated_known_decimal_GB=allocated / 1e9, allocated_known_GiB=allocated / 2**30,
                disjoint_top_level=groups,
                review_candidates=review, issues=state["issues"],
                equal_size_review_groups=[v for k, v in sizes.items() if k and len(v) > 1],
                limitations=["Non-atomic metadata observations, not physical exclusive extents or reclaim promises.",
                             "Same size is not equal content; categories are name hints, never waste or deletion clearance.",
                             "No content read, ownership, retention, current-use or recovery verification.",
                             "Directory allocation, streams, shared extents and filesystem snapshots excluded.",
                             "Ancestor checks are not handle-pinned: concurrent hostile path replacement is unsupported.",
                             "Resuming wide directories re-enumerates observed names; blocked OS calls cannot be interrupted.",
                             "Complete describes collection coverage, not freshness at finish: earlier validated files can change between batches."])


def compare(before, after):
    if before["roots"] != after["roots"]:
        raise ValueError("before/after roots must match exactly, including recovery locations")
    b, a = summarize(before), summarize(after)
    for root in before["roots"]:
        if (before["entries"].get(root, {}).get("identity") !=
                after["entries"].get(root, {}).get("identity")):
            raise ValueError("root identity changed; incomparable surveys")
    known = all(r["complete"] and not r["allocated_unknown_files"] for r in (a, b))
    recovery_seen = set()
    recovery_allocated = 0
    recovery_unknown = 0
    for path, row in after["entries"].items():
        if row["kind"] == "file" and "recovery" in row["categories"]:
            key = row["identity"] or path
            if key not in recovery_seen:
                recovery_seen.add(key)
                recovery_allocated += row["allocated_bytes"] or 0
                recovery_unknown += row["allocated_bytes"] is None
    return dict(before_allocated_known_bytes=b["allocated_known_bytes"],
                after_allocated_known_bytes=a["allocated_known_bytes"],
                observed_net_allocation_reduction_bytes=(b["allocated_known_bytes"] - a["allocated_known_bytes"]) if known else None,
                retained_recovery_hint_allocated_known_bytes=recovery_allocated,
                retained_recovery_hint_allocated_unknown_files=recovery_unknown,
                actual_reclaimed_free_space_bytes=None,
                qualification="Signed allocation delta includes retained copies only inside supplied roots. Not causal savings, free-space change, restoration proof or deletion authority.")


def load(path, roots=None):
    with open(path, encoding="utf-8") as stream:
        state = json.load(stream)
    if state["version"] != VERSION:
        raise ValueError("unsupported checkpoint version")
    if state["platform"] != sys.platform:
        raise ValueError("checkpoint belongs to a different platform")
    if state["roots"] != normalize_roots(state["roots"]):
        raise ValueError("invalid checkpoint roots")
    if roots is not None and state["roots"] != normalize_roots(roots):
        raise ValueError("resume requires the original explicit roots")
    paths = list(state["entries"]) + state["pending"] + state["validation"] + state["failed_paths"]
    if any(not Path(p).is_absolute() or ".." in Path(p).parts or not in_scope(p, state["roots"]) for p in paths):
        raise ValueError("checkpoint contains out-of-scope path")
    if state["phase"] not in {"inventory", "revalidation", "done"}:
        raise ValueError("invalid checkpoint phase")
    if state["phase"] == "inventory" and (state["validation"] or state["validation_index"]):
        raise ValueError("inventory checkpoint has a stale validation cursor; start fresh")
    if state["phase"] != "inventory" and state["validation"] != list(state["entries"]):
        raise ValueError("incomplete checkpoint revalidation frontier")
    if not 0 <= state["validation_index"] <= len(state["validation"]):
        raise ValueError("invalid checkpoint revalidation cursor")
    if state["phase"] == "done" and state["validation_index"] != len(state["validation"]):
        raise ValueError("unfinished checkpoint marked done")
    if any(row["path"] != path for path, row in state["entries"].items()):
        raise ValueError("checkpoint entry path mismatch")
    return state


def save_new(path, state):
    path = Path(path)
    validate_path(path)
    if not path.is_absolute() or ".." in path.parts or in_scope(str(path), state["roots"]):
        raise ValueError("output must be a new absolute file outside scan roots")
    if skipped(checked_stat(path.parent)):
        raise ValueError("output parent is a link/placeholder")
    with open(path, "x", encoding="utf-8") as stream:
        json.dump(state, stream, indent=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--resume")
    parser.add_argument("--before")
    parser.add_argument("--output", required=True)
    parser.add_argument("--batch-entries", type=int, default=10000)
    parser.add_argument("--seconds", type=float, default=10)
    parser.add_argument("--max-entries", type=int, default=1000000)
    args = parser.parse_args()
    try:
        state = load(args.resume, args.root) if args.resume else start(args.root)
        if args.resume and state["phase"] == "done":
            raise ValueError("completed checkpoint cannot resume; start a fresh survey")
        run(state, args.batch_entries, args.seconds, args.max_entries)
        state["summary"] = summarize(state)
        if args.before:
            state["comparison"] = compare(load(args.before, args.root), state)
        save_new(args.output, state)
        presented = dict(state["summary"])
        if "comparison" in state:
            presented["comparison"] = state["comparison"]
        print(json.dumps(presented, indent=2))
        return 0 if state["summary"]["complete"] else 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"colossus survey: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
