# Milestone 7: explicit shared lockfile selections

Milestone 6 is public at [`358bf20`](https://github.com/jongos/Colossus/commit/358bf20655024a1166916fad1915f78e26c531d9), with remote main verified after push. The installed skill and executable are now published v0.6.0. Milestone 7 is published at [`8fcd294`](https://github.com/jongos/Colossus/commit/8fcd29414e35b58b4962cbfa14980040f5833a36), with remote main verified after push. Colossus remains read-only.

## Delivered

- `--cargo-lockfile ABSOLUTE_MANIFEST ABSOLUTE_LOCKFILE` selects an exact shared or alternative comparison source; requires `--provenance` and at most 64 distinct manifest paths.
- Caller selections are recorded in schema 1.6.0, including cancelled/partial reports, independently from observed fingerprints and comparison results.
- Both files must be in authorized inventory; selected manifests must be observed Cargo projects. No parent search, inferred membership, network fetch or automatic scope expansion occurs.
- Selected lockfiles override adjacent lookup without fallback on failure. Invalid selected manifests omit lockfile comparisons and create a coverage gap.
- Shared selected paths are read/fingerprinted once. Existing identity checks, per-file limits, total content budget and cancellation still apply.
- Validator, human output, CLI help, four synthetic examples and skill guidance cover the new association semantics.

See [selection rules and limitations](LOCKFILES.md). A caller-selected association does not verify Cargo workspace membership, dependency resolution, path identity or build compatibility. It also does not resolve inherited versions. Every candidate remains an investigation with protected paths.

## Validation

**159 tests passed:** 2 unit, 26 original adversarial, 28 provenance, 14 corroboration, 23 Milestone 4, 24 Milestone 5, 22 Milestone 6 and 20 Milestone 7 tests. ACL, hard-link and junction cases ran. The existing privilege-dependent symlink test remains excluded. Real mounts, ReFS, mapped drives and non-Windows platforms remain unvalidated.

New cases cover explicit shared locks, no automatic parent lookup, override semantics, missing/malformed selections with no fallback, out-of-scope files, invalid/non-Cargo manifests, duplicate/conflicting pairs, provenance requirement, relative/UNC/parent paths, selection counts, shared reads, cancelled report configuration, selected directories, alternative filenames/separate authorized roots, source preservation and CLI operands. A missing-file cache edge case found during development has a regression test.

One initial rename fixture was blocked by sandbox permissions. A full run then encountered retained temporary fixture-name collisions; rerunning unchanged tests with normal local permissions in a fresh temporary root passed. No earlier fixtures or security settings were removed or changed.

Formatting, Clippy with warnings denied, the standalone release build and installed/development skill validation passed. Complete signed and untrusted CLI runs each report 12 checks and 9 source fingerprints, exiting 0. Partial and cancelled runs exit 2 and 130 and preserve requested selection metadata. All four schema 1.6.0 reports validate; all 22 current/historical examples validate against their original schemas. The validator rejects a forged selection pointing away from the observed lockfile. Fixture content hashes and last-write times are preserved.

## Installation and next work

Published v0.6.0 is installed at `%USERPROFILE%\.local\bin\colossus.exe` and `%USERPROFILE%\.codex\skills\colossus`; version and source equality were checked. The previous installation is preserved in a local installation backup. A new terminal may be needed to refresh PATH.

The local checkout development binary is v0.7.0; it does not replace the installed published version. Automatic or declared workspace-membership validation, authenticated predicate/build-context checks and dedicated-host filesystem coverage remain future milestones. No build execution, cleanup, quarantine, signing or deletion operation was added.

The installed skill and executable were subsequently updated to published v0.7.0 during Milestone 8 development; v0.6.0 was preserved.
