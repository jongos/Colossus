# Cargo lockfile observations

Milestone 6 adds two read-only consistency checks under `--provenance`, using existing inventory identity checks and the shared content-read budget. No package manager, build, network request or executable from the workspace runs.

Only an inventoried `Cargo.lock` in the same directory as each observed Cargo manifest is considered. Without an explicit selection, parent/workspace lockfiles are not searched. Missing adjacent locks are unresolved evidence, not collection errors. A workspace member may therefore remain unresolved even if its workspace root has a lockfile.

The parser supports explicit lockfile formats 3 and 4, at most 1 MiB per file and 10,000 package entries. It requires nonempty bounded names, semantic versions and correctly typed nonempty sources when present. Malformed TOML, duplicate fields, invalid package records, unsupported formats and read refusals produce coverage gaps. One malformed package invalidates comparisons from that lockfile; successful bounded reads still retain a source fingerprint. Extra fields, including dependency lists and checksums, are not interpreted or validated. Parsing is bounded but not interruptible inside the TOML parser; cancellation is checked before reading, during reads, between package records and between comparisons.

- `cargo_lock_package_version`: subject is the Cargo project evidence; compares its explicit version with exactly one source-less lock entry of the same name.
- `cargo_lock_dependency_version`: subject is a declared local dependency; first requires an inventoried target Cargo manifest whose name agrees with the dependency (including renames), then compares that target's explicit version with one source-less entry in the declaring project's adjacent lockfile. The requirement-versus-manifest check remains separate.

A unique equal version is `consistent`; a unique unequal version is `mismatch`. Missing entries, multiple source-less entries (even identical duplicates), missing/invalid/inherited manifest versions, absent targets and target-name disagreements remain `unresolved`. Source-bearing entries never satisfy a local comparison. A same-name remote entry does not mask a unique source-less entry.

These are comparisons of declarations. Source-less entries do not encode paths: even `consistent` does not prove that Cargo resolved this directory, selected this dependency edge, used these bytes, verified registry checksums, activated compatible features or produced a reproducible build. Dependency graphs, patches, Cargo configuration, alternate lockfile locations, workspace inheritance, npm lockfiles and full resolver semantics remain unsupported. See the official [Cargo manifest/lockfile distinction](https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html).

Successful comparisons link the lockfile source fingerprint; dependency comparisons also link the target manifest evidence. Existing candidate propagation retains mismatch/unresolved blockers where associated, and every path remains protected. No match grants cleanup permission. Schema 1.5.0 adds the two check kinds; the report validator checks source/subject links and recorded-value consistency, not the original lockfile bytes or Cargo's resolver.


## Explicit selections (v0.7.0)

Use `--cargo-lockfile ABSOLUTE_MANIFEST ABSOLUTE_LOCKFILE` with `--provenance` to choose a shared workspace lockfile or other exact comparison source. Repeat for up to 64 unique manifests. Relative paths, parent traversal, UNC/device paths and duplicate/conflicting manifest selections are rejected before inventory. Paths must match inventoried files; case aliases are not discovered. Selected manifests must be observed Cargo projects. Both roots must already be authorized if files are in separate roots.

A selection replaces adjacent lookup for that manifest. No fallback occurs if its selected lockfile is absent, skipped, unreadable, malformed or unsupported. An unobserved/non-Cargo selected manifest creates a coverage gap and omits all lockfile comparisons, so the selection cannot silently disappear. Report `cargo_lockfiles` retains caller requests even when collection is partial or cancelled. It is configuration evidence, not proof of observation or verified workspace membership.

The same selected path is read and fingerprinted once, including when a root project's adjacent lookup reaches it first. Only explicitly selected paths are cached (at most 64 files, each at most 1 MiB); failures are cached too. Missing selected paths still produce gaps if encountered previously through a default lookup. Per-file and shared read limits remain enforced. Comparisons refer to the original snapshot fingerprint; caching does not create an atomic workspace snapshot or validate later mutations.

Cargo normally shares a workspace-root lockfile across members ([official workspace documentation](https://doc.rust-lang.org/cargo/reference/workspaces.html)). This option lets a caller supply the intended comparison without implementing Cargo's membership discovery. It does not validate membership, exclusions, inheritance, dependency resolution or alternative Cargo configuration. No parent search, scope expansion, lockfile generation or resolver execution is added.
