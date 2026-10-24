# Phase 1 validation — 2026-10-24

## Result

The Windows-first read-only auditor, versioned schema, portable skill, tests and documentation are implemented. This is an experimental audit tool, not a cleanup executor or a claim that every platform safety condition has been independently verified.

**27 tests passed:** 1 unit test and 26 integration tests. One additional symbolic-link fixture could not be created because this Windows account lacks the required privilege (OS error 1314). It remains explicitly ignored by default and was filtered out of the final supported run, not counted as passing. The ACL test is opt-in by default and passed when explicitly enabled here.

Final test command:

```text
cargo test --locked -- --include-ignored --skip symlink_target_is_not_inspected
```

`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, the skill-creator validator, and JSON Schema/cross-record validation passed. A separate agent performed static adversarial review and a bounded skill scenario. That review found output-boundary gaps; retained directory/root identities and alternate-stream rejection fixed them, with regression tests. A follow-up static check confirmed the cancellation-root gap was addressed. This is not an external security audit.

## Tested behavior

| Case | Evidence |
|---|---|
| Source preservation | Before/after file bytes and last-write times match, including synthetic Git metadata; also verified for the 10,000-file benchmark |
| Dirty and untracked source | Possible modifications and untracked/ignored paths reported; all remain protected |
| Nested and linked/locked worktrees | Discovered; lock presence collected when its metadata is inventoried; unsupported/missing metadata remains visible |
| Junction escape | Target contents absent from report; traversal skipped; root-through-junction rejected |
| Hard links | Logical/allocation totals count one identity; alias remains listed |
| Sparse file | Actual `fsutil sparse setflag` fixture; 32 MiB logical size exceeds observed allocation |
| Permission/sharing denial | Synthetic ACL deny and exclusive file handle both produce incomplete coverage; test restores its synthetic ACL |
| Concurrent changes | Deterministic mutation after inventory and before final revalidation produces an explicit changed-file issue |
| Unicode, shell syntax and long paths | Names remain data; verbatim Windows path over 260 characters is scanned |
| Untrusted claims | Malicious README and forged artifact registration do not authorize any action |
| Misleading names/shared/offline dependencies | Source in a build-named directory remains protected; dependency ownership remains unknown |
| Cancellation/limits | Pre-cancellation, zero deadline, entry budget and depth cap report partial coverage |
| Output safety | Existing files, scanned roots, moved descendants/roots, cancelled/unvisited roots and alternate-stream output are rejected |
| Low disk | Injected Windows disk-full writer error propagates; actual volume exhaustion was not attempted |
| Reports/digest | JSON roundtrip produces the same human report; evidence changes alter the digest; schema and reference invariants pass |

Unverified environment cases: privileged symbolic links, arbitrary third-party reparse tags, real cross-volume mount transitions, ReFS/FAT/exFAT, network storage, disk removal, physical disk-full events and forced process termination during every phase. Junctions exercise the common reparse skip path; that does not certify every filesystem/filter implementation. Linux and macOS execution are explicitly unsupported. A real Ctrl-C console event was not separately automated; cancellation state and deadline paths were tested.

## Performance

One local release-build run on Windows 11 build 26300, AMD Ryzen 5 PRO 7530U (12 logical processors), 15,886,143,488 bytes RAM, fixed local NTFS volume:

| Measurement | Observed |
|---|---:|
| Files / directories | 10,000 / 100 (plus root) |
| Bytes per file | 1,024 |
| Logical bytes | 10,240,000 |
| Allocated bytes reported | 40,960,000 |
| Audit process elapsed | 14.8623 seconds |
| Sampled peak working set | 22,839,296 bytes (21.8 MiB) |
| Content and last-write preservation | Passed |
| Inventory coverage | Complete within stated limits |

Fixture creation and before/after hashing are excluded from audit elapsed time. The cache was warm after preservation hashing. Memory was sampled at 10 ms intervals and may miss short peaks. This is one run on an active workstation, not an isolated throughput claim. No other platforms were benchmarked. [Raw measurements](benchmark.json) and [reproduction script](../scripts/benchmark.py) are included; the script only generates synthetic files and retains its fixture.

## Build and example

Validated using Rust 1.99.1, `x86_64-pc-windows-gnullvm`, and LLVM-MinGW 20261020. The local release executable was built with `RUSTFLAGS=-C target-feature=+crt-static` and an explicit `--target x86_64-pc-windows-gnullvm`; it runs without the temporary toolchain's `libunwind.dll`. Windows OS runtime imports remain. Ordinary MSVC builds are documented but were not tested on this host.

[Example JSON](example-audit.json) comes from a synthetic three-file project. Paths were normalized to `C:\synthetic\example` and the digest recomputed after normalization. Example summary:

```text
Coverage: complete within stated limits
Files: 3 unique; 0 hard-link aliases
Logical bytes: 4168
Known allocated bytes: 4176; unknown files: 0
Review candidates: 1; eligible for deletion: 0
REVIEW C:\synthetic\example\target
Evidence e0: target directory with a sibling Cargo.toml
Blockers: source/unique assets possible; dependencies and retention unresolved;
          recovery and generation method unverified; metadata-only inspection
```

Residual risks are explicit in [architecture](ARCHITECTURE.md): this is not an atomic snapshot, Git status is partial metadata evidence, index checksum authenticity is unverified, process use/ownership/reconstruction are unknown, and allocation does not equal reclaimable space. Next milestone is stronger read-only provenance and platform validation before any executor is designed.
