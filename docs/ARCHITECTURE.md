# Read-only architecture and boundaries

`platform` supplies Windows handle opens and identity/size observations. `scan` inventories and revalidates entries, then applies a deliberately conservative policy. `git` collects bounded Git metadata without a subprocess. `content` performs inventoried-identity reads with byte budgets and write-excluding handles. `provenance` parses opt-in declarations, resolves inventory-only relationships and associates ownership context without selecting a verified owner. `corroboration` compares local revision metadata and dependency manifests with claims and fingerprints observed source bytes. `model` defines versioned records. `report` derives both presentations from one report, seals it with SHA-256 and handles explicit report creation. The portable skill interprets evidence; it does not replace CLI checks.

## Filesystem model

Only explicit absolute local drive roots are accepted. Each ancestor is opened with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`, requesting generic read access and denying delete-sharing. Read-attributes-only access does not enforce the required sharing restriction; this distinction is covered by a rename regression test. Metadata-first means file content is not read, although read access is required for pinning. Reparse attributes are checked before traversal. Holding the ancestor handles blocks rename/replacement while path-based enumeration proceeds. Root handles remain held through evidence collection. Before subsequent metadata reads, each path chain is pinned again and compared with inventoried identity. Inaccessible/unsupported identities cause an explicit gap rather than a path-only fallback.

Identity combines the filesystem's 64-bit volume serial with its 128-bit file ID (`FileIdInfo`). Logical size and allocation come from handle information. Hard links share identity and count once; aliases remain listed. No directory allocation, alternate data stream inventory or shared-extent accounting is attempted. Allocation is not a reclaim prediction. Volume-serial collisions and unusual filesystem/filter semantics have not been independently audited. Network/device namespaces and reserved DOS device components are rejected. Drive type is checked before opening roots, including drive letters mapped to remote storage. Arbitrary reparse types are skipped.

Enumeration is sorted and single-worker. Unique identities, depth and entry limits bound traversal. The report and identity table use memory proportional to entries; this is not a streaming constant-memory scanner. Large-directory listing stops at the remaining budget and is marked incomplete. Validated root identities are retained before scanning, even if cancellation or entry limits prevent any inventory. User roots are retained in the manifest as supplied; traversal is sorted. Evidence timestamps and changing/interrupted files mean whole-report digests differ between observations. Deadlines and cancellation are cooperative: after stopping inventory/evidence work, policy summarization and serialization still finish the partial report and are not hard latency-bounded.

## Changing files and side effects

At the end, identity, last-write time and logical size are rechecked. Directory metadata changes are also checked after enumeration. Bounded Git reads compare metadata before and after reading. This is not an atomic snapshot: same-size changes with preserved times, changes after revalidation, and some concurrent mutations cannot be detected. A changed entry makes coverage incomplete; totals remain observed values, not a consistent point-in-time measurement.

No source content or last-write timestamps are intentionally changed. Read operations can cause filesystem-managed access-time updates, antivirus activity or other OS effects. Open handles can temporarily block deletion/renaming by another process. Reparse/cloud placeholders are not hydrated by following their targets. These are operational limits of read-only inspection, not cleanup permissions.

## Git evidence

The collector discovers `.git` markers, including nested repositories. It reads only inventoried bounded regular metadata files (16 MiB cap): HEAD, Gitdir/commondir claims, index and lock presence. It does not execute Git or read Git config/includes. Absolute and relative Gitdir/commondir declarations are resolved only against inventoried entries with component validation; skipped links or missing paths remain unresolved. Resolution does not open a new target or extend scope. `locked` and `index.lock` presence are observations, not proof that a repository is inactive.

SHA-1 index v2/v3 stat entries are compared to inventoried file metadata only after checksum consistency passes. This detects accidental corruption, not malicious metadata or authenticity. Unsupported formats, extended/unmerged entries, unsafe paths and missing metadata produce limitations. Staged changes, ignore rules, index-vs-HEAD equality and worktree dirtiness are not proven. `possibly_modified` includes metadata differences, missing files and uninspected paths. `untracked` includes ignored files. Bare repositories and Git layouts without `.git` markers are not recognized.

## Policy and plan

A directory named `target`, `build` or `dist` beside an inventoried build-manifest filename becomes an investigation candidate. This is a weak heuristic explicitly labelled as such; manifest content is not executed or assumed truthful. Names like `cache` alone produce no candidate. Source, unique assets and all other inventoried paths remain in the plan's protected paths, including candidates. Unknown process use, ownership, generation methods, dependencies, originating tasks, reconstruction costs and recovery stay unknown.

Optional [provenance evidence](PROVENANCE.md) adds parsed manifest context, declared path relationships, unauthenticated artifact records, ownership conflicts and selected-file SHA-256 groups. It does not establish exclusive ownership, executed build provenance, recoverability or disposable duplicates. The original Artifact fields for verified generation/recovery remain unknown. No superseded-release reasoning, registry trust, process enumeration, cache pruning or eligibility-for-deletion classification is implemented. Empty/null fields mean unknown, never verified absent.

The digest hashes the UTF-8 compact serde JSON report with `plan.manifest_digest` set to the empty string. It binds evidence and scope, but is not a signature or approval. Current report/Plan schema version is 1.7.0; the 1.0.0 through 1.3.0 schemas are retained for historical reports. Receipt remains reserved and no receipt is emitted. No executor, quarantine, restoration, pruning or watcher code exists.

## Output boundary

Explicit output parent chains are pinned and their identities compared against every originally inventoried directory identity, including moved roots or descendants. Alternate-data-stream filenames and ambiguous trailing dot/space names are rejected. `create_new` refuses existing files, links and aliases. The parent must exist outside scanned roots. File-write/flush failures propagate; a partial newly created output may remain. Writes are not atomic or crash-durable and must not be treated as a valid report unless parsing and validation succeed. CLI stdout redirection is controlled by the caller, not this guard.

Optional [local consistency checks](CORROBORATION.md) never elevate a candidate to cleanup eligibility. Manifest/registry fingerprints are capped at 10,000 source records in addition to the existing declaration budget. Revision checks add at most two bounded source fingerprints per distinct compared repository and reuse observations within a run.

`statements` reads only explicitly selected inventoried statement files, fingerprints their bytes and compares subject digests with explicit hashes. It never evaluates predicates; the separate `authentication` module verifies supported DSSE signatures only against caller-supplied keys. Cargo package-name and semver checks use already-read manifest fields. See [offline statement boundaries](STATEMENTS.md).

Signature verification binds the exact DSSE payload bytes and payload type. The same decoded bytes are parsed as the statement. Public keys come only from the explicit options, are validated before inventory, and are recorded in the report. No keyring, certificate chain, URL, repository policy or default key supplies trust. See [authentication limits](AUTHENTICATION.md).

`lockfiles` reads only adjacent inventoried Cargo.lock files under provenance collection, sharing the identity-checked content budget. It compares declarations without invoking a package manager. See [limits](LOCKFILES.md).

Explicit lockfile selections are validated before inventory, retained as caller configuration in reports, and resolved only against inventoried Cargo manifests/files. Selected observations are cached within the existing content budget; missing selections never expand scope.

`workspaces` extracts bounded literal declarations from the manifest bytes already read. It checks explicit lockfile associations within inventory, without extra content reads or Cargo execution. See [workspace checks](WORKSPACES.md).
