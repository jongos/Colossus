# Milestone 11: read-only survey checkpoint validation

Local development from main commit `39eaccb`. Milestone 10 receipt diagnostics remain on their separate development branch. This milestone changes only the portable survey and its documentation/tests; it does not change the installed CLI or the deletion executor.

Checkpoint loading now limits input to 64 MiB before JSON parsing, refuses observed links/placeholders and nonregular files, and compares file metadata/identity before, during and after reading. Duplicate JSON keys, non-finite numbers and excessive nesting are rejected. Structural checks validate required fields, row identities/signatures, nonnegative counts, directory membership digests, protected status, normalized scoped paths and resume frontiers. Both `--resume` and `--before` inputs are validated before surveying targets. Format 3 remains supported; malformed older format-3 data may now be refused.

These checks detect malformed evidence and observed changes, not malicious forgery or all concurrent replacements. Reads are bounded but not handle-pinned against ancestor races. JSON memory use can exceed serialized size; OS calls can block. A valid checkpoint is unauthenticated, and reported totals remain claims. No target embedded in a checkpoint is opened during loading. A resume subsequently surveys only the caller's matching explicit roots. Comparison recomputes summaries rather than trusting stored summary/comparison fields.

Checkpoints larger than 64 MiB cannot be resumed or used as comparison inputs; start fresh with smaller disjoint scopes. No automatic migration, target removal, cleanup eligibility, retry or deletion approval is introduced. Exact deletion targets still require fresh explicit human approval.

Validation on Windows/Python 3.12: 14 checkpoint tests plus 4 existing membership tests pass. Tests cover valid completion and partial resume, bounded reads, identity-change refusal, malformed fields/paths/frontiers, duplicate keys, non-finite/deep JSON, discarded stored reports, and CLI refusal before output or survey traversal. Fixtures remain under `work/retained-checkpoint-*` and `work/retained-membership-*`; control content is preserved. No deletion tests ran. Linux/macOS execution and hostile concurrency are not validated by these tests.

Commands:

```text
python tests/test_survey_checkpoint.py -v
python tests/test_survey_membership.py -v
```
