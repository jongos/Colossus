# Exact Next.js compiler-cache adapter

This opt-in Windows NTFS adapter is separate from the generic Colossus CLI. Generic refusal rules remain unchanged. No installed executable is replaced. It deletes only the exact files in a reviewed plan; it never discovers additional targets, removes directories, stops runtimes, or runs builds.

## Supported paths and authorization

Within one ordinary Git repository, supported spellings are:
- `.next/cache/.tsbuildinfo`
- `.next/cache/webpack/{client,server,edge-server}-production/{index,NUMBER}.pack[.old]`
- `.next/cache/turbopack/ID/{NUMBER.sst,NUMBER.meta,NUMBER.del,CURRENT,LOG}`

A project may be beneath the repository root. Unknown names, preview/RSC metadata, source, credentials, dependencies, runtime server/static output, hidden project prefixes, path traversal, streams, wildcards, short-name aliases, UNC paths and noncanonical path spellings are refused. Protection applies to the entire absolute target path, including the selected root. Names do not prove that file contents are disposable: operator review must establish cache ownership, independence from sources/dependencies/custom consumers, release of retention obligations, and acceptance of regeneration.

Input CSV must contain exactly one `path` column and 1–512 exact absolute native Windows paths. Every row must qualify; a refused row aborts the plan. Each target is at most 256 MiB and the batch at most 3 GiB. CSV, JSON controls and each policy file are limited to 1 MiB.

Supply a separate review JSON, with no extra fields:
```json
{
  "runtime_independent": true,
  "retention_released": true,
  "regeneration_accepted": true,
  "basis": "Describe the actual ownership, source/dependency independence, retention and regeneration review."
}
```
These declarations are recorded operator evidence, not independent proof. No previous cleanup, digest or environment variable constitutes approval.

## Usage

```powershell
python -B scripts/next_cache_cleanup.py plan --root C:\project --input C:\controls\selected.csv --review C:\controls\review.json --output C:\controls\new-plan.json
python -B scripts/next_cache_cleanup.py execute --input C:\controls\new-plan.json --output C:\controls\new-receipt.jsonl
```

Outputs must be new absolute files outside the selected root. Execution displays the entire plan, requires both stdin and stdout to be terminals, and accepts only `DELETE EXACT_DIGEST`. There is no noninteractive production approval switch. A changed target, ancestry, Git policy, Git executable or plan schema requires a fresh plan and review. Version 1 plans from the earlier local adapter are rejected.

## Safety boundaries

Native handles pin all target ancestors, reject reparse/offline/recall objects, verify canonical native paths and local NTFS, and reject hardlinked/nonregular targets. Targets are opened exclusively; deletion uses their already-validated handles. Git config/index/HEAD, applicable ignore files and the Git executable are held against writing/deletion. Full tracked-path comparison rejects NTFS casing aliases and gitlink ancestry. Targets must be exactly ignored and untracked. Linked worktrees, shared/external Git metadata, nested repositories and config includes are unsupported.

Any `colossus.artifacts.json` in target ancestry is a hold, even if empty. Policy and runtime checks run after approval and before each disposition. All detected Node, NodeJS, Bun, Deno or Next processes are refused, including unrelated processes; unreadable/failed/malformed inventories fail closed. Existing Next runtime locks also refuse execution. No process command lines or environment secrets are recorded.

Control inputs have pinned ancestry and bounded native reads. Outputs use exclusive native create-new handles and pinned ancestry, including throughout the prompt and receipt writes. The journal flushes and fsyncs the approved plan, each intent, each verified outcome and completion. An interruption or receipt failure may leave only an intent, or an empty receipt before approval. Such a receipt is incomplete: inspect it and the exact files; never automatically retry. The selected allocation sum is not a measured or causal free-space gain.

## Dependencies and validation

The earlier adapter imported an untracked `repository_cleanup.py` ZIP workflow. This implementation extracts only the necessary native and bounded Git primitives into `next_cache_native.py` and `next_cache_git.py`, then hardens them. The ZIP workflow, its docs/tests and generic Rust changes are excluded.

The `Next cache adapter safety` workflow runs the adapter suite on GitHub-hosted Windows and the existing generic Rust refusal suite. Adapter tests refuse local/self-hosted execution. All deletion targets are fresh synthetic files beneath that runner's temporary directory. Tests mock terminal input at the test boundary only; production has no CI approval bypass. Coverage includes actual NTFS exclusivity, pinned ancestry, junctions, hardlinks, active Node inventory, stale evidence, approval refusals, holds added during approval, durable intent failures, and exact-selection success preserving adjacent sentinels and directories. Receipts and logs are retained as CI artifacts. No local tests are authorized for this review.

## Remaining limitations

This is bounded validation, not general safety certification. File names and review declarations do not authenticate cache content. Runtime inventory cannot rule out renamed executables, nonstandard consumers or a new process after inventory. Native file locks protect selected objects, not all runtime state. New retention markers or repository state can still race the final recheck; an administrator or hostile concurrent filesystem actor is outside this adapter's supported model. Use only a quiescent repository under operator control.

Recovery is regeneration by a later separately authorized build, not byte-for-byte restoration. No automatic retry, rollback or recovery is provided. The previous 219-file operational cleanup is not general safety certification.
