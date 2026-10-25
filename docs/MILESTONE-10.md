# Milestone 10: read-only cleanup receipt diagnostics

Development draft; validation pending. Installed version remains the validated v0.9.0 milestone. No additional deletion is authorized or performed by this milestone.

`colossus cleanup receipt --receipt ABSOLUTE_RECEIPT` reads only the explicitly selected local receipt, using pinned ancestry, a deny-write handle, a 2 MiB limit and a before/after identity snapshot. It never opens the target paths embedded in a receipt. Output is structured JSON on stdout; exit 0 means internally consistent complete-report claims, exit 2 means internally consistent partial/interrupted claims, and exit 1 means invalid/unreadable input.

The reviewer checks the embedded plan digest, strict event fields, ordered target identities, one intent before each outcome, stop-after-failure semantics, matching totals and free-space arithmetic. Unknown events, contradictory completion, missing measurements, trailing data after a finish marker and invented causal reclaimed amounts are rejected. At most 130 complete events are accepted. A final non-newline fragment is ignored as an interrupted write and its byte count is reported; even a complete JSON finish object without its terminating newline is not accepted as completion.

Per-target states are `unattempted`, `intent_unresolved`, `reported_removed`, `reported_failed` or `outcome_unconfirmed`. `intent_unresolved` may represent deletion that took effect before the outcome was journaled. Never infer that retry is safe from this state. Completion is `complete_reported`, `partial_reported` or `interrupted`.

Receipt consistency is not authenticity, proof of human approval, proof of deletion, preservation verification or current filesystem state. The reviewer explicitly qualifies every result and provides no retry/resume capability. Exact-target human approval and the interactive deletion boundary are unchanged. Read-only diagnostics do not broaden supported deletion types or roots.

Validation uses pure synthetic journal bytes, retained receipt files, a locked-file refusal and CLI argument/exit-code checks. No tests in `cleanup_receipt.rs` invoke the deletion executor. The original 17 refusal tests also run. Successful deletion remains covered by Milestone 9's separately approved run; it is not repeated automatically.
