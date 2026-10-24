# Milestone 3: local provenance consistency

Colossus 0.3.0 remains a read-only Windows auditor. Milestone 2 was committed and pushed to the public repository as [`738a8ba`](https://github.com/jongos/Colossus/commit/738a8ba9181aa5fa045596fc0e55c9ddedbede1a). Milestone 3 is a subsequent local development change, not yet committed or pushed.

## Delivered

- SHA256 fingerprints of the exact bytes read for evidence sources, separate from explicit content-comparison hashes.
- Dependency-target checks against parsed manifests of the same ecosystem at the exact inventoried target directory.
- Full revision-claim comparison with detached HEAD or supported loose branch metadata in the target's nearest repository, including inventoried linked-worktree common directories.
- Explicit `consistent`, `mismatch` and `unresolved` results with subject and supporting evidence IDs. Mismatches and unresolved comparisons associated with candidates remain blockers; matches remove no blocker.
- Schema 1.2.0, current examples, report rendering, CLI help, cross-record validation and skill interpretation guidance.

See [comparison semantics and limits](CORROBORATION.md). Matching local values do not authenticate provenance, prove exclusive ownership, verify a build or authorize cleanup. No build, Git command, package manager or cleanup operation is executed by the auditor.

## Validation

**70 tests passed:** 2 unit tests, 26 original integration tests, 28 Milestone 2 tests and 14 new tests. The ACL case was included. One privilege-dependent symlink test remains excluded; this host previously returned Windows error 1314. Formatting and Clippy with warnings denied passed, and the standalone release binary built successfully.

New cases cover exact-byte fingerprints, detached and loose-ref consistency, explicit mismatch blockers, missing/packed/chained refs, invalid revision expressions, nested repository context, common-directory resolution, content-budget exhaustion, exact ecosystem matching, hostile ref syntax, junction refs, cancellation and replacement of an inventoried HEAD file. The junction and replacement cases use live synthetic filesystem operations. They do not certify every reparse type or real cross-volume mount.

The complete CLI fixture returned exit 0 with three parsed projects, two dependency declarations, two artifact claims, four consistency checks and six evidence-source fingerprints. It deliberately includes consistent, mismatching and unresolved checks. A content-budget run returned exit 2 and a deadline-cancelled run returned 130. All three reports passed schema and cross-record checks. Historical 1.0.0 and 1.1.0 report examples still validate with their original schemas.

Before/after SHA256 and last-write-time checks confirmed source preservation for the CLI runs. Example paths are normalized to `C:\synthetic\milestone3` and report digests recomputed. No private project was scanned. Independent skill forward-testing used the generated report and preserved the investigation-only result without inventing evidence IDs.

## Limits and next work

This milestone provides local consistency, not externally authenticated build evidence. Packed refs, symbolic-ref chains, package versions/features, lockfile semantics, build attestations, object existence, working-tree cleanliness and practical reconstruction remain unverified. Reads are bounded and cooperatively cancellable, not an atomic filesystem snapshot.

Dedicated-host validation for real mounts, ReFS, mapped network drives and privileged symlinks remains outstanding. No new cross-platform or physical disk-full certification is claimed. Next read-only work should address externally corroborated build evidence, version-aware dependency checks and those environment-specific tests before any mutation design is implemented.
