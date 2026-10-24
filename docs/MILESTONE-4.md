# Milestone 4: dependency versions and offline statement evidence

Milestone 3 is public at [`10f9964`](https://github.com/jongos/Colossus/commit/10f9964dd3d3003f9a82cdbc10775b5c7073824f), with remote main verified after push. Milestone 4 was subsequently committed and pushed as `ed244d104b0f1d38253a6c4fb63cc228af9610ad`. The auditor remains read-only.

## Delivered

- Cargo path-dependency package-name checks, including renamed packages, and explicit version-requirement checks using semver 1.0.28.
- `--statement-file` for explicitly selected offline in-toto Statement v1 subjects, with a strict documented subset and bounded reads.
- Subject-digest comparisons against explicitly selected file hashes. No implicit subject hashing, network fetch, signature verification or predicate execution.
- Separate matching, mismatching and unresolved claims with source fingerprints and supporting evidence. Statement authentication remains `unverified`.
- Descendant statement checks associated with directory candidates; mismatches remain blockers. Multiple name/version checks for a single dependency are preserved.
- Report schema 1.3.0, examples, validation, CLI help and skill guidance updated together.

See [statement format, limits and version semantics](STATEMENTS.md). This milestone creates an evidence-import path; it does not complete authenticated build provenance. A digest match does not establish a trusted builder, verified source, successful build, recoverability or safe removal.

## Validation

**93 tests passed:** 2 unit tests, 26 original integration tests, 28 Milestone 2 tests, 14 Milestone 3 tests and 23 new tests. The ACL case ran; one privilege-dependent symlink test remains excluded because this host previously returned Windows error 1314. Formatting, Clippy with warnings denied, the standalone release build and skill validation passed.

New tests cover Cargo renames, name/version disagreements, prerelease ranges, malformed and inherited versions, independent candidate blockers, digest matches and mismatches, source preservation, explicit selection, no implicit hashing, unsupported names, duplicate digest fields, signed-envelope rejection, absent and unsupported digests, per-file/selection/aggregate bounds, contradictory subjects, junction subjects, hard-link alias selection and descendant candidate propagation.

Complete, content-budget-partial and deadline-cancelled CLI reports returned 0, 2 and 130. All passed schema and cross-record checks. The complete synthetic example contains four projects, two dependency declarations, two artifact registrations, three statement subjects, nine consistency checks and eight source fingerprints. An intentionally forged statement-match result was rejected by the cross-record validator. Historical report examples for schemas 1.0.0, 1.1.0 and 1.2.0 remain valid.

Source file hashes and last-write times were unchanged across CLI runs. Tests used synthetic fixtures only. Example paths are normalized to `C:\synthetic\milestone4`, with report digests recomputed. Independent skill forward-testing correctly identified the Cargo mismatch, refused to treat an unsigned statement as trusted provenance, and retained the investigation-only result. Its reporting findings were corrected and regression-tested.

## Remaining work

Signature verification requires an explicit signer/trust policy and supported signed-envelope implementation; none is inferred from statement contents. Predicate semantics, build execution, object existence, npm version ranges, inherited dependency resolution, features, lockfiles and practical reconstruction remain unverified.

The added live junction tests do not certify every reparse type. Dedicated-host real-mount, ReFS, mapped-drive and privileged-symlink validation remains outstanding, as do non-Windows platforms. No cleanup, quarantine, restoration or deletion capability has been added.
