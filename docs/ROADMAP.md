# Research and next milestones

This project uses original implementation code. The brief's comparator list is research context, not evidence of uniqueness or a source-code license grant.

Implementation references checked during development:

- [Microsoft reparse points and file operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points-and-file-operations): opening the point and inspecting attributes is essential; unknown reparse types remain skipped.
- [Git status](https://git-scm.com/docs/git-status) and [Git worktree](https://git-scm.com/docs/git-worktree): Git has richer dirty/worktree semantics than the bounded metadata collector. Colossus explicitly does not claim equivalent status.
- [Rust metadata](https://doc.rust-lang.org/std/fs/struct.Metadata.html) and [Windows Rust toolchains](https://rust-lang.github.io/rustup/installation/windows.html): native handle information is used where portable metadata is insufficient.

Recheck relevant primary documentation before implementing adapters: [Kondo](https://github.com/tbillington/kondo), [dua](https://github.com/Byron/dua-cli), [Czkawka](https://github.com/qarmin/czkawka), [uv cache](https://docs.astral.sh/uv/concepts/cache/), [pnpm store](https://pnpm.io/cli/store), [Send2Trash](https://github.com/arsenetar/send2trash), [FreeDesktop Trash spec](https://specifications.freedesktop.org/trash/latest/), [Windows free space](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexa). Their cleanup behavior is not implemented or relied upon in Phase 1.

Milestone 2 completed locally: bounded content hashes, declared provenance and ownership context, inventoried worktree metadata resolution, and expanded Windows filesystem tests. See [results and remaining validation limits](MILESTONE-2.md).

Next milestone: corroborate declared build provenance and dependency relationships without executing builds, and validate real mount/reparse types on a dedicated Windows test host. Add Linux/macOS handle-relative traversal only with platform-specific adversarial evidence. Do not infer safety from missing process references. Keep execution and cleanup out of this next read-only milestone.

Later milestones, **plan only**:

1. Candidate provenance, compatibility, dependency ownership and practical recovery verification.
2. Exact-manifest approval, same-volume quarantine, journaling, non-overwriting restoration and interruption recovery. Quarantine does not reclaim space and must never silently become deletion.
3. Separately approved permanent purge with identity revalidation, preservation checks and free-space measurements. Unsupported safety conditions block execution.
4. Independently reviewed binaries, installation checks and Windows-first public beta validation.
5. Native trash, verified version-aware package-manager operations and Git-aware worktree lifecycle handling.
6. Artifact registration for owner, task, revision, reproducibility and retention. Registration remains untrusted evidence, not authority.

System cleanup, personal media, database maintenance, automatic deletion schedules and Git history rewriting are out of scope.
