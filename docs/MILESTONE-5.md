# Milestone 5: offline signature verification

Milestone 4 is public at [`ed244d1`](https://github.com/jongos/Colossus/commit/ed244d104b0f1d38253a6c4fb63cc228af9610ad), with remote main verified after push. Milestone 5 is local v0.5.0 development, not yet committed or pushed. The auditor remains read-only.

## Delivered

- Offline DSSE/Ed25519 signature verification over exact payload bytes and payload type.
- Explicit `--trusted-key LABEL=PUBLIC_HEX` input with no default or repository-derived trust. Public-key policy is validated before scanning and recorded in the report.
- Separate signature status, accepted caller labels and payload SHA256, linked to subject and file-digest evidence.
- Bounded key/signature counts, weak-key rejection, standard/URL-safe base64 handling, strict duplicate-field handling and cooperative cancellation.
- Signature failures and missing trust retained as candidate blockers; verified signatures do not remove existing blockers or protections.
- Schema 1.4.0, signed/untrusted/partial/cancelled examples, CLI help, cross-record validation and skill interpretation guidance.

See [authentication policy and limits](AUTHENTICATION.md). Signature verification establishes agreement with an explicitly supplied public key; it does not establish real-world builder identity, predicate truth, freshness, revocation status, build execution, recovery or deletion safety.

## Validation

**117 tests passed:** 2 unit tests, 26 original integration tests, 28 Milestone 2 tests, 14 Milestone 3 tests, 23 Milestone 4 tests and 24 new tests. The ACL case ran. One privilege-dependent symlink case remains excluded because this host previously returned Windows error 1314. Formatting, Clippy with warnings denied, the standalone release build and skill validation passed.

The new suite verifies a fixed Ed25519 DSSE fixture independently generated with Python cryptography 50.0.0, checks the published DSSE pre-authentication-encoding example, and covers byte tampering, wrong/missing keys, misleading key hints, raw-body signatures, unsupported payload types, duplicate recognized fields, malformed encodings, weak/duplicate keys, signature bounds, duplicate signatures, the any-one-key policy, cancellation after a potential match, source preservation, signed-but-invalid payloads, and candidate protection.

One freshly built test executable initially received Windows Application Control error 4551 before execution. The unchanged executable passed on retry; no security policy was changed. The remainder of the suite, lint and release validation completed successfully.

The complete signed CLI fixture records four projects, two dependencies, two artifact registrations, three statement subjects, nine consistency checks, eight source fingerprints and one verified authentication record. A second run over the same signed file with no supplied key correctly reports `no_trusted_keys` while completing collection. Content-budget-partial and deadline-cancelled runs return 2 and 130; complete signed and untrusted runs return 0. All four reports pass schema and cross-record checks. Historical 1.0.0–1.3.0 examples still validate with their original schemas.

Source hashes and last-write times were preserved across CLI runs. Tests used synthetic fixtures and publicly reproducible test keys only; no production signer was selected or installed. Example paths are normalized to `C:\synthetic\milestone5` and report digests recomputed. Independent skill forward-testing distinguished supplied-key verification from trusted build claims and retained the investigation-only result for equal-content outputs.

## Remaining work

Certificate chains, key discovery, key revocation, transparency logs, replay/freshness checks, signature thresholds and authenticated predicate/build-context verification are not implemented. Lockfile coverage, broader dependency compatibility and practical reconstruction remain follow-on work.

Dedicated-host real-mount, ReFS, mapped-drive and privileged-symlink validation remains outstanding, as do non-Windows platforms. No build command, network fetch, signing operation, cleanup, quarantine, restoration or deletion capability was added to the auditor.
