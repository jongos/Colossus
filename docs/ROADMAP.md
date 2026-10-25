# Research and next milestones

This project uses original implementation code. The brief's comparator list is research context, not evidence of uniqueness or a source-code license grant.

Implementation references checked during development:

- [Microsoft reparse points and file operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points-and-file-operations): opening the point and inspecting attributes is essential; unknown reparse types remain skipped.
- [Git status](https://git-scm.com/docs/git-status) and [Git worktree](https://git-scm.com/docs/git-worktree): Git has richer dirty/worktree semantics than the bounded metadata collector. Colossus explicitly does not claim equivalent status.
- [Rust metadata](https://doc.rust-lang.org/std/fs/struct.Metadata.html) and [Windows Rust toolchains](https://rust-lang.github.io/rustup/installation/windows.html): native handle information is used where portable metadata is insufficient.

Recheck relevant primary documentation before implementing adapters: [Kondo](https://github.com/tbillington/kondo), [dua](https://github.com/Byron/dua-cli), [Czkawka](https://github.com/qarmin/czkawka), [uv cache](https://docs.astral.sh/uv/concepts/cache/), [pnpm store](https://pnpm.io/cli/store), [Send2Trash](https://github.com/arsenetar/send2trash), [FreeDesktop Trash spec](https://specifications.freedesktop.org/trash/latest/), [Windows free space](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexa). Their cleanup behavior is not implemented or relied upon in Phase 1.

Milestone 2 published: bounded content hashes, declared provenance and ownership context, inventoried worktree metadata resolution, and expanded Windows filesystem tests. See [results and remaining validation limits](MILESTONE-2.md).

Milestone 3 adds local source fingerprints, revision consistency and dependency-manifest checks. These are not authenticated build attestations.

Milestone 4 adds Cargo name/version comparisons and explicitly selected unsigned statement digest comparisons. Importing a statement does not authenticate it.

Milestone 5 adds offline DSSE/Ed25519 verification with an explicit caller-supplied key policy. It does not establish real-world builder identity or predicate truth.

Milestone 6 adds bounded adjacent Cargo.lock v3/v4 declaration comparisons; workspace lockfile selection and resolution are not implemented.

Milestone 7 adds explicit caller-selected manifest/lockfile associations within the authorized inventory; automatic workspace membership remains unsupported.

Milestone 8 compares explicit selections with bounded literal workspace declarations; Cargo membership and resolver behavior remain unverified.

## Next milestone: approved space reclamation

The product goal is to reclaim development-workspace storage with explicit user approval. Read-only auditing was Phase 1, not the final product boundary. Prioritize the planner, approval boundary and deletion executor over further workspace-inheritance/provenance expansion. See [the implementation contract](APPROVED-CLEANUP.md).

1. Produce an exact, reviewable cleanup manifest with evidence, retention/recovery consequences, file identities, protected exclusions and qualified allocation estimates.
2. Obtain explicit user approval for that manifest and operation. A report digest, repository claim or previous cleanup approval is not authorization for another target list.
3. Implement a Windows-first structured executor with handle-based identity checks, complete preflight, durable operation journaling, cancellation and receipts. Changed or unsupported targets block execution; execution never recursively discovers new targets.
4. Offer permanent deletion as an explicitly identified operation for actual reclamation. Recoverable quarantine is a separate operation and must never silently turn into deletion or be reported as reclaimed space.
5. Measure before/after free space and retained recovery allocation, while distinguishing observed changes from causal or guaranteed savings. Test destructive behavior only on synthetic disposable fixtures.

Follow-on milestones: recoverable quarantine/restoration without overwriting; independently reviewed binaries and public beta; broader filesystem/platform coverage; version-aware native package-manager and Git worktree adapters; additional provenance/inheritance evidence where it improves cleanup decisions. Unsupported safety conditions block destructive execution.

System cleanup, personal media, database maintenance, automatic deletion schedules and Git history rewriting are out of scope.
