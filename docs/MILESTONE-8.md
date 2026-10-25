# Milestone 8: literal workspace declaration evidence

Milestone 7 is committed and public at [`8fcd294`](https://github.com/jongos/Colossus/commit/8fcd29414e35b58b4962cbfa14980040f5833a36); remote main was verified after push. The installed skill and executable now match published v0.7.0. Milestone 8 is local v0.8.0 development, uncommitted and unpushed. Colossus remains read-only.

## Delivered

- Bounded Cargo workspace declarations extracted from manifest bytes already read, with no additional content reads.
- A separate `cargo_selected_workspace_membership` check for explicit manifest/lockfile selections.
- Literal member agreement, explicit exclusions, package.workspace pointer conflicts and a member's own workspace table remain visible independently of lockfile version agreement.
- Unsupported globs/fields, missing observations and absent literal membership remain unresolved. No automatic workspace discovery or lockfile reselection occurs.
- Schema 1.7.0, validator checks, human-readable declarations, four synthetic examples and skill interpretation guidance.

See [workspace semantics and limits](WORKSPACES.md). These checks compare declarations; they do not validate actual Cargo membership, resolver state, inheritance, intermediate workspace boundaries or a successful build. Unsupported declarations can have omitted entries, so their retained lists must not be treated as complete. Every candidate remains protected and proposes investigation only.

## Validation

**180 tests passed:** 2 unit, 26 original adversarial, 28 provenance, 14 corroboration, 23 Milestone 4, 24 Milestone 5, 22 Milestone 6, 20 Milestone 7 and 21 Milestone 8 tests. The full run used a fresh synthetic temporary root. ACL, hard-link and junction cases ran. One existing privilege-dependent symlink test remains excluded; real mounts, ReFS, mapped drives and non-Windows platforms remain unvalidated.

New cases cover literal membership, exclusions, absence without inferred nonmembership, member/exclusion globs, malformed fields/pointers, a member's own workspace, matching/conflicting/unresolved package.workspace pointers, ordinary non-workspace projects, alternate lock filenames, root packages, unsupported exclusions, no-selection behavior, per-list and aggregate budgets, candidate blockers despite matching versions, no extra content reads, preservation and cancellation.

Formatting, Clippy with warnings denied, the standalone release build and installed/development skill validation passed. Complete signed and untrusted CLI fixtures each report four projects, three declared relationships, 14 consistency checks and nine source fingerprints, exiting 0. Partial and cancelled runs exit 2 and 130. Source hashes and modification times are preserved. All four schema 1.7.0 reports and all 26 current/historical examples validate. The validator rejects a forged consistent membership result after an exclusion is added or its declaration is marked unsupported.

## Installation

Published v0.7.0 is installed at `C:\Users\jongo\.local\bin\colossus.exe` and `C:\Users\jongo\.codex\skills\colossus`. The skill source and executable hash match the published milestone's local tested build. The previous v0.6.0 installation is preserved under this task's `work/installed-v0.6-backup`. The updated skill is available next turn.

Installed binary SHA256: `8e78c55019514df0fa2c9eb651add967fe45150cb32815f89dba702974b144cf`.

The checkout's development binary is v0.8.0 and remains separate from the installed published version. Workspace inheritance, fuller dependency compatibility, authenticated predicate/build-context checks and dedicated-host filesystem validation remain future work. No cleanup, quarantine, deletion, build execution or signing capability was added.


## Portable survey addition review (2026-10-25)

The skill now bundles a Python 3.10+ resumable metadata survey and its workflow reference. It records bounded inventory/revalidation progress, disjoint allocation summaries, protected investigation candidates and qualified before/after deltas. It has no cleanup executor. Its path checks are not handle-pinned; native macOS/Linux execution remains unvalidated.

Review validation: 20 Python tests passed; one symlink case was skipped because Windows returned privilege error 1314. Skill validation passed. All 26 report examples pass schema/invariant checks. Rust source, Rust tests and Cargo inputs match the previously validated 180-test Milestone 8 build. README wording now distinguishes the Windows-only Rust CLI from the optional portable survey.
