# Milestone 2: bounded provenance and filesystem validation

Version 0.2.0 adds optional read-only evidence collection. No cleanup, quarantine, deletion, package-manager execution or build execution is implemented.

## Evidence delivered

- Opt-in Cargo/npm manifest parsing, literal local dependency and workspace relationships, and strict artifact-record parsing.
- Separate declared ownership, generation and revision claims from observed project context. Shared dependencies and hard-link identities preserve multiple contexts; contradictory owners remain conflicts.
- Retention holds flow to descendants and candidate blockers. No claim or hash makes an artifact safe to remove.
- Explicit-file SHA256 with per-file and total byte limits, cooperative cancellation, identity checks and write-excluding handles. Equal content across distinct file identities is reported separately from hard-link aliases.
- Inventoried relative Git worktree metadata resolution and SHA1 consistency checking for supported index formats. These checks do not authenticate Git metadata.
- Schema 1.1.0, cross-record validation, CLI help and skill guidance updated together. Historical schema 1.0.0 is retained.

See [provenance semantics](PROVENANCE.md) for supported relationships and limits.

## Validation on Windows

56 tests passed: 2 unit tests, 26 original integration tests and 28 new provenance/filesystem tests. The ACL test was explicitly included. The symlink test was excluded because this host previously denied symlink creation (Windows error 1314). Formatting and Clippy with warnings denied passed; the standalone Windows release binary built successfully.

Live synthetic filesystem checks covered ACL denial, junction boundaries, swapped ancestors, hard links, alternate-stream preservation, write sharing, replacement detection, output boundary protection and source preservation. Input rejection covered UNC/device/drive-relative paths, reserved names and alternate-stream syntax. A volume mismatch was injected to test the refusal branch; this is not evidence from a real cross-volume mount.

Complete, byte-budget-partial and deadline-cancelled CLI runs returned 0, 2 and 130 respectively. All passed JSON-schema and cross-record checks. Source SHA256 values and modification times were unchanged. The three `example-*-v1.1.json` reports are generated from those synthetic runs with fixture paths normalized and report digests recomputed.

Ownership fanout, record counts and output associations are bounded. Hostile retention text is escaped in human output. Cancellation during a content read emits no partial hash. Cooperative cancellation does not promise a hard wall-clock bound for report serialization or every setup operation.

## Measured synthetic run

On Windows 11 build 26300, AMD64, 12 logical CPUs, local NTFS, a provenance-enabled scan of 1,000 generated 1 KiB files plus one package manifest completed in **0.592 seconds**, with **9,183,232 bytes (8.8 MiB)** sampled peak working set. The scan was complete and source content and modification times were preserved. Raw results: [benchmark-v0.2.json](benchmark-v0.2.json).

This is one warm-cache run; 10 ms memory sampling can miss brief peaks. It is not directly comparable to the initial milestone's larger workload. Synthetic fixtures remain available in temporary storage; no cleanup was performed.

## Remaining validation limits

Real cross-volume mounts, ReFS, mapped network drives, privilege-enabled symlinks, physical disk-full behavior, real console Ctrl-C delivery and non-Windows platforms are not certified. Windows share modes cannot establish an atomic snapshot against every existing writable mapping or filesystem filter. No rebuild, exclusive ownership or practical recovery has been verified.

The next milestone should remain read-only: authenticated or externally corroborated build evidence, stronger dependency semantics, and dedicated filesystem-host validation before any mutation design is implemented.
