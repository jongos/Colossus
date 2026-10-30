# Milestone 6: bounded Cargo lockfile evidence

Milestone 5 is committed and public at [`ab1d59e`](https://github.com/jongos/Colossus/commit/ab1d59eb0696b339f853c62f87203a998e78db3c); remote main was verified to match. Milestone 6 is published at [`358bf20`](https://github.com/jongos/Colossus/commit/358bf20655024a1166916fad1915f78e26c531d9), with remote main verified after push. The auditor remains read-only.

## Delivered

- Adjacent inventoried Cargo.lock format 3/4 reads under `--provenance`, using identity-checked handles and the shared content budget.
- Separate comparisons for explicit project versions and declared local dependency target versions, including renamed dependencies.
- Source fingerprint links, explicit mismatch/unresolved outcomes and candidate protection retained.
- Bounded parsing: 1 MiB per lockfile, 10,000 packages, no remote package reads or automatic parent-lockfile discovery.
- Schema 1.5.0, report validator checks, four synthetic examples and skill guidance.

See [lockfile semantics and limits](LOCKFILES.md). A version match is agreement between declarations; it does not prove Cargo resolved that local path, selected a dependency edge or produced a compatible/reproducible build. Workspace lockfile selection, inherited versions, checksums, features, patches and resolver behavior remain unsupported. Authenticated predicate/build-context checks and dedicated-host filesystem validation remain future work.

## Validation

**139 tests passed:** 2 unit, 26 original adversarial, 28 provenance, 14 corroboration, 23 Milestone 4, 24 Milestone 5 and 22 Milestone 6 tests. The ACL test ran. The existing privilege-dependent symlink test remains excluded; real mounts, ReFS, mapped drives and non-Windows platforms are not newly validated.

The new suite covers matching/mismatching versions, renames, remote/local same-name entries, duplicate/ambiguous local entries, v3/v4 formats, unsupported formats, malformed packages/TOML, missing adjacent files, inherited versions, target-name disagreements, disabled collection, total/per-file/package limits, a directory named Cargo.lock, cancellation and evidence/source preservation. An existing dependency-manifest test now counts only its own check kind so new unresolved lockfile observations do not change its intent.

Sandbox restrictions initially prevented several synthetic Git/link fixtures. The same filesystem suite passed with normal local permissions; no security settings were changed. Formatting, Clippy with warnings denied, the standalone release build and skill validation passed.

Complete signed and untrusted CLI runs each produce 12 consistency checks and 9 source fingerprints across four projects. Both exit 0; bounded partial and deadline-cancelled runs exit 2 and 130. All four reports pass schema/cross-record validation. The validator rejects a forged statement match and a lock comparison stripped of source evidence. Content hashes and modification times were preserved. Historical examples continue to validate against their original schemas.

## Installed version

The published v0.5.0 skill is installed at `%USERPROFILE%\.codex\skills\colossus`, fetched from commit `ab1d59e`. The tested v0.5.0 executable is installed at `%USERPROFILE%\.local\bin\colossus.exe`, an existing user PATH directory. A new terminal/app process may be needed to refresh PATH. `colossus --version` reports 0.5.0.

Installed binary SHA256: `c906fe29d0982a7d7ef67e4055bc573c838c8eb6e6b1643cc0fd97e75e12d425`.

The local checkout's v0.6.0 binary is separate; the installed stable skill/executable remain v0.5.0. No production trust keys, scheduled scans, telemetry, cleanup or deletion capability were installed.

The installed skill and executable were subsequently updated to published v0.6.0 while developing Milestone 7; the original v0.5.0 installation was preserved.
