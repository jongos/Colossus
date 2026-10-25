# Milestone 10: read-only cleanup receipt diagnostics

Development branch: 33 receipt tests plus 17 existing refusal tests pass in both debug and optimized builds, with strict lint passing. Installed version remains the validated v0.9.0 milestone. No additional deletion is authorized or performed by this milestone.

`colossus cleanup receipt --receipt ABSOLUTE_RECEIPT` reads only the explicitly selected local receipt, using pinned ancestry, a deny-write handle, a 2 MiB limit and a before/after identity snapshot. It never opens the target paths embedded in a receipt. Output is structured JSON on stdout; exit 0 means internally consistent complete-report claims, exit 2 means internally consistent partial/interrupted claims, and exit 1 means invalid/unreadable input.

The reviewer checks the embedded plan digest, strict event fields, ordered target identities, one intent before each outcome, stop-after-failure semantics, matching totals and free-space arithmetic. Unknown events, contradictory completion, missing measurements, trailing data after a finish marker and invented causal reclaimed amounts are rejected. At most 130 complete events are accepted. A final non-newline fragment is ignored as an interrupted write and its byte count is reported; even a complete JSON finish object without its terminating newline is not accepted as completion.

Per-target states are `unattempted`, `intent_unresolved`, `reported_removed`, `reported_failed` or `outcome_unconfirmed`. `intent_unresolved` may represent deletion that took effect before the outcome was journaled. Never infer that retry is safe from this state. Completion is `complete_reported`, `partial_reported` or `interrupted`.

Receipt consistency is not authenticity, proof of human approval, proof of deletion, preservation verification or current filesystem state. The reviewer explicitly qualifies every result and provides no retry/resume capability. Exact-target human approval and the interactive deletion boundary are unchanged. Read-only diagnostics do not broaden supported deletion types or roots.

Validation uses pure synthetic journal bytes, retained receipt files, a locked-file refusal and CLI argument/exit-code checks. No tests in `cleanup_receipt.rs` invoke the deletion executor. The original 17 refusal tests also run. Successful deletion remains covered by Milestone 9's separately approved run; it is not repeated automatically.

Structured output is described by `schemas/cleanup-receipt-review-v1.schema.json`. Signed negative observations are preserved, large unsigned integer deltas are checked exactly, and floating-point deltas are refused.

## Validation evidence

[Windows run 40232114084](https://github.com/jongos/Colossus/actions/runs/40232114084) passed all 50 non-deleting tests in both build modes, strict Clippy, and compilation (not execution) of the ignored destructive test. The first run caught an internally tagged serde `i128` deserialization limitation; integer parsing and negative/large unsigned/floating-point regression cases now cover it.

The development executable was run locally against the preserved Milestone 9 receipt. It returned `complete_reported`, two reported removals, 134,217,728 allocated bytes and the recorded 134,213,632-byte observed free-space increase. Receipt bytes and modification time stayed unchanged; the output passed the new JSON schema. The deleted targets were on the prior hosted runner and were never opened by this review. The installed v0.9.0 binary remains unchanged. The full historical audit regression suite and new destructive fault-injection tests were not run.
