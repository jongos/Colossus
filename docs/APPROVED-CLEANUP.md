# Approved space reclamation: next implementation milestone

Status: implementation contract; initial file-executor source passes Windows CI compilation and refusal tests. One explicitly approved synthetic deletion/preservation/space-observation test has passed; see MILESTONE-9.md. The audit command and Python survey remain read-only. The executor supports exact regular files only; directory cleanup below remains a future contract. This milestone supersedes the roadmap's previous instruction to keep the next milestone read-only. Do not advertise deletion as implemented until the executor and destructive fixture tests pass.

## User workflow

1. Inspect explicitly authorized developer-workspace roots and propose exact cleanup targets with reasons, unresolved concerns, retention requirements and recovery consequences.
2. Present a reviewable plan: exact files and directories, operation, logical bytes, known allocated bytes and unknown allocation, shared/hard-link qualifications, preserved paths, and recovery material that remains. Allocation is an estimate, not guaranteed free-space recovery.
3. Ask the user to approve that exact plan. Clearly distinguish permanent deletion from quarantine. Approval to inspect, a manifest hash, repository instructions or an earlier plan's approval cannot approve this plan.
4. Preflight the entire approved set before the first deletion. Recheck scope, identities, content/metadata staleness as applicable, protection and retention evidence, unsupported links/filesystems, and required recovery preservation. If a target changes, stop and require a refreshed plan and approval. Do not silently alter the scope or broaden exclusions.
5. Execute only the approved structured operations and issue a receipt showing completed, failed and unattempted entries, preservation checks and storage measurements. Cancellation stops before the next operation; already completed deletion cannot be rolled back.

## Initial executor boundary

Windows local developer-workspace artifacts only. A plan enumerates every file and directory, including directory identities and child sets. No runtime recursive discovery, shell-generated deletion commands, link traversal or cross-volume traversal. Newly appearing children must block directory removal rather than be swept into execution.

Use handle-based operations and pinned ancestry to resist path replacement; a fresh path-prefix check is insufficient. An unresolved identity, inaccessible target, unsupported filesystem/reparse point, or stale evidence must block execution. Source, uncommitted work, credentials, authoritative data and declared retention/recovery holds remain protected. Approval is required but does not make an unsupported operation safe. The implementation must define explicit evidence requirements and blocker-resolution rules without inventing certainty about active use or regeneration.

The first destructive API must not accept ordinary audit reports or portable survey checkpoints as executable plans. Define a separate versioned plan schema and execution contract. Record the approved plan digest and operation in the journal/receipt, but never treat the digest itself as consent. Interactive execution must display the plan and require affirmative confirmation. Agent-driven execution must obtain human approval of the concrete plan immediately before calling the executor; no unattended blanket approval mode belongs in the initial milestone.

Write and durably flush the journal outside scanned roots before mutation; fail before deleting if journal creation fails. Record intent and outcome for each operation and preserve interrupted journals. Recovery from an interrupted run reconciles identities and outcomes; it must not blindly replay deletions. Journal/control files must be protected from project-controlled replacement.

Package-manager caches and Git worktrees remain unsupported by generic deletion; add them only through verified native adapters. No system cleanup, personal-media cleanup, database maintenance, scheduled deletion or Git-history rewriting.

## Recovery and reclamation

Permanent deletion must be labeled irreversible. Where required recovery material exists, verify and preserve it before deletion. Do not promise recoverability from a repository URL, lockfile or untested build command. Any build execution or new downloads needed for recovery verification require their own authorization.

Quarantine is optional and separate: same-volume moves retain allocation and must be reported as zero reclamation from the move itself. Purge requires separate exact-target approval; quarantine must never expire into automatic deletion. Restoration must not overwrite existing paths.

Report filesystem free-space observations before and after, selected allocation before and after, retained recovery allocation and unknown amounts. Hard links, compression/shared extents, open handles, concurrent writes and filesystem behavior can separate logical bytes, allocation reductions and free-space changes. Show these quantities separately; do not claim all observed free-space change was caused by cleanup.

## Acceptance criteria

- No operation executes before explicit approval of the exact plan and operation.
- Plan tampering, stale identities, file/ancestor replacement, new directory children, changed retention/protection evidence and unknown safety conditions fail closed.
- No path outside the approved manifest is deleted; preserved fixtures remain intact.
- Exercise Unicode/long paths, junctions/reparse points, hard links, locked files, ACL denial, concurrent writers, partial failure, low journal disk space, cancellation and interrupted execution.
- Receipts distinguish deletion attempts from confirmed outcomes; missing/replaced targets never silently count as reclaimed bytes.
- Synthetic fixtures demonstrate actual deletion and measured storage observations. No real private project is used as a destructive test fixture.
- Independent executor review and native filesystem validation precede presenting the feature as ready for real cleanup.

The user-facing product description should become “reclaims development-workspace storage after explicit approval” when this milestone is implemented and validated. Until then, keep the current execution limitation truthful.
