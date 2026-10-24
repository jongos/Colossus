# Local consistency checks

`--provenance` in version 0.3.0 records `source_hashes` and `checks` under report schema 1.2.0. No additional command or implicit scope expansion is needed. Metadata-only mode leaves these collections empty.

`source_hashes` fingerprints the exact bytes read for manifests, registry records and supported revision metadata. A source fingerprint can exist even when parsing fails. It identifies an observation; it does not identify an author or authenticate a statement. These hashes are separate from explicitly selected `hashes` and never feed duplicate-content groups.

Every check identifies its subject evidence and its supporting evidence. Status is `consistent`, `mismatch` or `unresolved`. An unresolved comparison does not itself mean the filesystem inventory is incomplete; a failed content read, budget refusal or cancellation does create a coverage gap. Candidate records retain blockers and supporting evidence for comparisons associated with their ownership context. A consistent comparison removes no blocker.

## Dependency manifests

For each extracted local/workspace declaration, the collector checks whether the exact inventoried directory target has a parsed manifest of the declaring ecosystem. A match links the target project ID and manifest evidence. A Cargo manifest does not corroborate an npm dependency or vice versa. Missing manifests, file/archive targets and unresolved declarations remain unresolved.

This does not validate dependency names, versions, features, lockfiles, installed contents or active use. It adds evidence to the existing declaration model; it does not claim full package-manager resolution.

## Revision claims

For a registry claim with `source_revision`, the comparison context is the nearest inventoried Git repository containing the claim's resolved artifact target. Nested repositories take precedence. This is a contextual comparison, not proof that this repository generated the artifact.

The collector accepts full nonzero hexadecimal object IDs of 40 or 64 characters. It reads inventoried HEAD bytes again with the bounded content reader. Detached IDs are compared directly; a simple `refs/heads/...` symbolic HEAD resolves to one inventoried loose ref, using the resolved common directory for linked worktrees. Each repository result is reused for other claims during the same run.

Packed refs, symbolic chains, revision expressions, abbreviated IDs and refs outside this conservative syntax remain unresolved. An unresolved common directory cannot fall back to a different branch ref. Ref resolution never opens an uninventoried path or follows a junction. HEAD and ref files each have a 4 KiB limit and share the default 64 MiB optional-content budget. Git's original metadata collector retains its separate per-file budget.

Matching values establish only local consistency. Git object existence and type, repository hash-format configuration, signatures, working-tree cleanliness, actual build inputs, artifact digest binding and reproducibility remain unverified. Do not call a match authenticated provenance or recovery proof. Mismatches are explicit evidence of disagreement, not proof of malicious intent.

This implementation follows the relevant structure of [Git repository layout](https://git-scm.com/docs/gitrepository-layout) and deliberately supports a subset of [Git reference syntax](https://git-scm.com/docs/git-check-ref-format). It does not invoke Git.

## Filesystem and preservation limits

Reads use the same pinned-ancestor, identity/size/mtime checks and write-excluding content handles as explicit hashing. Cancellation emits no partial digest. Windows sharing does not guarantee a snapshot against every existing writable mapping or filesystem filter. Reading may update access metadata according to filesystem policy; preservation checks cover content and last-write time, not every filesystem attribute.

The local suite exercises junction refs, substituted HEAD identities and content budgets using synthetic files. Dedicated-host mount, ReFS, mapped-drive and privilege-enabled symlink validation remains outstanding. No scanner operation writes to source trees, executes builds or changes repository state.
