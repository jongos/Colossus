# Portable project storage investigation

The Rust auditor remains the evidence/provenance collector and has no deletion
executor. Its Windows handle-pinned boundary is stronger than this companion's
metadata checks. `skills/colossus/scripts/portable_survey.py` adds a Python 3.10+
standard-library metadata survey for explicitly selected local project roots.
It reads no file contents and never launches project code. It is distributed
inside the skill so installing the whole skill directory includes the tool.

## Why the earlier workflow missed storage

The Rust policy only proposes investigation for `target`, `build`, and `dist`
beside known manifests. That excludes work/release/check-out trees, tool
environments, models, archives, caches, and retained recovery copies. The new
survey reports every observed regular file and disjoint top-level totals;
category names are navigational hints, not evidence of waste. The existing
Rust provenance workflow is still necessary to inspect declarations, inherited
retention holds, dependencies, and explicit duplicate hashes.

The original deadline report is partial but does not have a continuation
frontier. This companion persists pending directories and revalidation progress.
A ten-second observation is never called complete merely because it returned.

## Commands

Use an available Python 3.10+ interpreter (`python` or `python3`) and substitute
explicit authorized absolute paths. No machine-specific defaults are used.
Check the interpreter version first. If Python 3.10+ is unavailable, do not
install it automatically: on Windows use the installed Rust CLI and explicitly
report that resumability/portable summaries are unavailable. On macOS/Linux
report the missing prerequisite and stop this collector; no shell-recursion or
logical-size-as-allocation fallback is permitted. The Rust CLI has no Python
dependency; the companion's additional prerequisite is optional and explicit.

```text
python SKILL_DIR/scripts/portable_survey.py --root ABSOLUTE_PROJECT --seconds 10 --batch-entries 10000 --output ABSOLUTE_NEW_CHECKPOINT
python SKILL_DIR/scripts/portable_survey.py --root ABSOLUTE_PROJECT --resume ABSOLUTE_PRIOR_CHECKPOINT --seconds 10 --output ABSOLUTE_NEXT_CHECKPOINT
python SKILL_DIR/scripts/portable_survey.py --root ABSOLUTE_PROJECT --before ABSOLUTE_BEFORE_CHECKPOINT --output ABSOLUTE_AFTER_CHECKPOINT
```

Repeat `--root` for disjoint authorized scopes, including a recovery location
when relevant. Overlapping roots are rejected. Every output must be new and
outside all roots. Resume repeats the original root arguments; checkpoint paths
cannot extend them. Checkpoints are trusted local working files, not signed
evidence or approval tokens; do not accept third-party checkpoints. Default
maximum inventory is one million entries. Review an entry-limit gap before
raising that limit. Exit 0 means completed collection with no recorded gaps,
2 means partial/gapped, 1 means input/output failure. Ctrl-C during collection
saves an explicitly cancelled partial checkpoint when possible.

`coverage` distinguishes deadline, batch limit, total limit, inventory,
revalidation, pending directories and unknown total size. `issues` separately
records denials, stale directories, unsupported allocation, skipped links,
placeholders, volume boundaries and metadata failures. Denied paths are not
retried on resume. Start a fresh survey after legitimate data changes; do not
erase gaps from an old checkpoint. Existing observations are deduplicated on
resume. A wide directory is re-enumerated to skip prior names, which can become
slow and may require a longer user-approved budget. OS calls are not preemptible.
Summarization/serialization and loading a checkpoint are not deadline bounded.
Frontier reconciliation and resumed-root preflight also run before the timed
traversal loop and are not strictly deadline bounded.
Memory and checkpoint size are proportional to the configured inventory limit.
Failed-path records count toward that limit. Checkpoint format 2 records which
directories were enumerated separately from which were merely observed, so an
interrupted directory discovery cannot lose pending descendants. Resumption
rechecks root metadata/identity and refuses further traversal beneath changed or
unavailable roots. Completed checkpoints cannot be resumed as fresh observations.
Per-entry validation timestamps and the overall validation window are reported:
files checked in an earlier batch can change during a pause. Completion describes
collection coverage, never freshness at finish or an atomic snapshot.

## Allocation and accounting

Windows uses `GetCompressedFileSizeW`, which accounts for sparse/compressed file
allocation; macOS/Linux use `st_blocks * 512`. Unsupported APIs or denied reads
remain unknown, never logical-size substitutes. `(device, inode)` identities
deduplicate hardlinks; missing identity is an explicit gap. Top-level totals
attribute an identity to its first observed alias, so they are disjoint but not
exclusive-ownership totals. Bytes, decimal GB (`10^9`) and GiB (`2^30`) are
distinct. Directory allocation, ADS/resource forks, filesystem snapshots,
reflink/shared blocks and deduplication are not measured as exclusive storage.
Top-level and recovery subtotals carry their own unknown-allocation counts;
known subtotals must not be presented as fully measured allocation. Hardlinks
outside the supplied roots can retain allocation after an in-scope alias is
removed; this is another reason allocation deltas are not reclaimed free space.

Observed symlinks, Windows reparse points/junctions and offline/recall attributes
are skipped without following targets or requesting hydration. Cloud providers
without these metadata signals are not reliably identifiable; use explicit
local roots, not cloud placeholder trees. Windows UNC/device/stream paths are
rejected. Mounted network drives on Windows and network mounts on Unix are not
reliably detected: their exclusion is a scope requirement. Different devices
inside a root are reported and not traversed. Ancestor metadata checks are not
handle-pinned and do not resist concurrent hostile replacement. Use the Rust
auditor on Windows when that assurance is needed; there is no comparable Unix
content/provenance collector in this change.

`--before` compares same-root, same-root-identity surveys. Net allocated reduction
is `before - after`, including retained recovery copies inside that scope. It can
be negative. Any coverage/allocation gap makes the numeric net result unknown.
The recovery category subtotal is explicitly a name hint, not a confirmed backup
inventory. Before/after snapshots are non-atomic and cannot attribute concurrent
changes to cleanup. Actual reclaimed free space remains unknown. Recovery copies
outside scope, compressed copies, hardlinks and retained archives must be
accounted for before reporting savings. A historical original-size statement
cannot substitute for a measured baseline or prove regeneration/restoration.

## Evidence and review gates

All survey entries are protected. Equal-size groups are leads for explicitly
selected content comparison, not duplicate assertions. Matching hashes from the
Rust auditor still do not clear retention: failed runs can be intentionally kept.
Terminal JSON includes issues, comparison results and protected investigation
candidates with observed file counts, category hints, blockers and next evidence.
For each exact target, carry forward manifest/record evidence IDs, owner and
dependency claims, inherited holds, source-of-truth role, active-use uncertainty,
restoration evidence, and reconstruction cost. Missing evidence stays unresolved.
Never classify a checkout as expendable merely because another checkout exists.
Do not execute build scripts, download models, or regenerate data to prove a
recovery method without authority.

No removal command, executable cleanup plan, approval flag, or receipt is added.
Future cleanup must bind approval to exact targets and evidence; recheck identity,
metadata, retention, current use and recovery immediately before execution, reject
stale plans, preserve restoration records, and report before/after/net allocation
with honest uncertainty. A survey checkpoint or manifest digest is not approval.

## Verification

Run `python -m unittest discover -s tests -p test_portable_survey.py -v`.
Fixtures are disposable and do not inspect real projects. Tests cover resumable
budgets, repeated observations, hardlinks, supported symlinks, injected denial,
allocation failures, sparse-shaped files, retained copies, ambiguous equal-size
outputs, output/scope guards and stale-directory detection. Native compressed
files, real ACL denial, cloud provider behavior and macOS/Linux execution still
require platform-specific validation; mock fallback coverage is not an OS test.

## Directory membership verification

Checkpoint format 3 records a SHA-256 digest of sorted immediate child names in addition to directory metadata. Resume and final revalidation compare both, so an added child cannot be hidden solely by an unchanged directory timestamp. Older checkpoints require a fresh survey. Membership collection is limited to 10,000 children and one second per directory check; exceeding either limit produces incomplete coverage, never a complete result. These checks add bounded work outside the entry batch counter. OS calls can still block. Observations remain non-atomic: changes after validation or changes that revert between observations are not detected.

Non-deleting regression command: `python tests/test_survey_membership.py -v`. Its fixtures remain under the repository `work/` directory.
