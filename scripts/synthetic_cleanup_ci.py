"""Synthetic-only CI harness. Preparation never deletes; approval is external.

The same runner waits for a human-approved record committed by the operator.
Never create that record without explicit approval of the published exact plan.
This is test infrastructure, not a production CLI approval mechanism.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import base64


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)


def environment(values):
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as stream:
        for key, value in values.items():
            if "\n" in str(value) or "\r" in str(value):
                raise ValueError("invalid environment value")
            stream.write(f"{key}={value}\n")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare():
    run = os.environ["GITHUB_RUN_ID"]
    attempt = os.environ["GITHUB_RUN_ATTEMPT"]
    assert run.isdecimal() and attempt.isdecimal()
    # Fresh synthetic root, outside the repository; no removal or reuse.
    root = Path(f"D:/colossus-approved-synthetic-{run}-{attempt}")
    root.mkdir(exist_ok=False)
    targets = root / "targets"
    control = root / "control"
    targets.mkdir()
    control.mkdir()
    manifest = []
    for name, byte in [("delete-a.bin", b"A"), ("delete-b.bin", b"B")]:
        path = targets / name
        with path.open("xb") as stream:
            for _ in range(64):
                stream.write(byte * (1024 * 1024))
            stream.flush()
            os.fsync(stream.fileno())
        manifest.append({"path": str(path), "bytes": path.stat().st_size,
                         "sha256": sha(path), "operation": "permanent-delete"})
    keep = targets / "preserve.bin"
    with keep.open("xb") as stream:
        stream.write(b"KEEP THIS SYNTHETIC CONTROL\n")
    manifest.append({"path": str(keep), "bytes": keep.stat().st_size,
                     "sha256": sha(keep), "modified_ns": keep.stat().st_mtime_ns,
                     "operation": "preserve"})
    plan_path = control / "plan.json"
    cli = Path("target/debug/colossus.exe").resolve()
    args = [str(cli), "cleanup", "plan", "--root", str(targets),
            "--reason", "Validate approved synthetic deletion and space observations only",
            "--recovery", "Permanent deletion of two newly generated 64 MiB synthetic files; no undo. No user data.",
            "--output", str(plan_path)]
    for entry in manifest[:2]:
        args.extend(["--file", entry["path"]])
    result = subprocess.run(args, check=True, capture_output=True)
    (control / "review.txt").write_bytes(result.stdout)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    expires = datetime.now(timezone.utc) + timedelta(hours=2)
    approval_path = f"test-approvals/{run}-{attempt}.json"
    request = {
        "status": "AWAITING HUMAN APPROVAL; NO DELETION AUTHORIZED",
        "run_id": run, "run_attempt": attempt,
        "source_commit": os.environ["GITHUB_SHA"],
        "plan_digest": plan["digest"],
        "expires_at_utc": expires.isoformat(),
        "approval_record_path": approval_path,
        "files": manifest,
        "space_validation": "Require confirmed removed allocation equal to the plan and a positive observed volume free-space delta. Concurrent volume activity prevents causal attribution.",
    }
    write_json(control / "approval-request.json", request)
    environment({"COLOSSUS_SYNTHETIC_CONTROL": control,
                 "COLOSSUS_TEST_APPROVED_PLAN": plan_path,
                 "COLOSSUS_TEST_RECEIPT": control / "receipt.jsonl"})
    print(json.dumps(request, indent=2), flush=True)


def wait():
    control = Path(os.environ["COLOSSUS_SYNTHETIC_CONTROL"])
    request = json.loads((control / "approval-request.json").read_text(encoding="utf-8"))
    expected = {key: request[key] for key in ["run_id", "run_attempt", "source_commit", "plan_digest"]}
    expected["approve"] = True
    deadline = datetime.fromisoformat(request["expires_at_utc"])
    repo = os.environ["GITHUB_REPOSITORY"]
    url = f"https://api.github.com/repos/{repo}/contents/{request['approval_record_path']}?ref=dev%2Fapproved-cleanup"
    headers = {"Authorization": f"Bearer {os.environ['GH_TOKEN']}",
               "Accept": "application/vnd.github+json", "User-Agent": "colossus-synthetic-test"}
    while datetime.now(timezone.utc) < deadline:
        try:
            with urlopen(Request(url, headers=headers), timeout=30) as response:
                envelope = json.load(response)
            record = json.loads(base64.b64decode(envelope["content"], validate=False))
            if record != expected:
                raise RuntimeError("Approval record does not exactly match this run, source and plan; no deletion")
            if datetime.now(timezone.utc) >= deadline:
                raise RuntimeError("Approval expired; no deletion")
            write_json(control / "accepted-approval.json", record)
            environment({"COLOSSUS_TEST_APPROVED_DIGEST": record["plan_digest"]})
            print("Matching externally approved record received; proceeding to exact-plan preflight.", flush=True)
            return
        except HTTPError as exc:
            if exc.code != 404:
                raise
        time.sleep(15)
    raise RuntimeError("Approval window expired; no deletion test ran")


def verify():
    control = Path(os.environ["COLOSSUS_SYNTHETIC_CONTROL"])
    plan = json.loads((control / "plan.json").read_text(encoding="utf-8"))
    request = json.loads((control / "approval-request.json").read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in (control / "receipt.jsonl").read_text(encoding="utf-8").splitlines()]
    first, end = rows[0], rows[-1]
    assert first["event"] == "approved_preflight" and first["plan"] == plan
    assert end["event"] == "finished" and end["complete"] is True
    assert end["removed_files"] == end["planned_files"] == 2
    assert end["cancelled"] is False
    removed = [row["path"] for row in rows if row["event"] == "removed"]
    assert removed == [target["path"] for target in plan["targets"]]
    assert all(not Path(path).exists() for path in removed)
    expected_allocation = sum(target["allocated"] for target in plan["targets"])
    assert expected_allocation > 0
    assert end["selected_removed_allocation_bytes"] == expected_allocation
    before, after = first["free_bytes_before"], end["free_bytes_after"]
    assert isinstance(before, int) and isinstance(after, int)
    assert after - before == end["observed_free_space_delta_bytes"]
    assert after > before, "No positive observed space recovery: do not install"
    assert end["causal_reclaimed_bytes"] is None
    keep_record = request["files"][2]
    keep = Path(keep_record["path"])
    assert sha(keep) == keep_record["sha256"]
    assert keep.stat().st_mtime_ns == keep_record["modified_ns"]
    assert sorted(path.name for path in keep.parent.iterdir()) == ["preserve.bin"]
    report = {"passed": True, "plan_digest": plan["digest"],
              "removed_files": removed, "preserved_control": str(keep),
              "selected_removed_allocation_bytes": expected_allocation,
              "observed_free_space_delta_bytes": after - before,
              "causal_reclaimed_bytes": None,
              "limitation": "Volume free-space observations include concurrent activity; do not claim an exact causal reclaimed amount."}
    write_json(control / "verification.json", report)
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    {"prepare": prepare, "wait": wait, "verify": verify}[sys.argv[1]]()
