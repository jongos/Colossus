# Evidence semantics in v0.2.0

Manifest content collection is opt-in with `--provenance`. This reads inventoried `Cargo.toml`, `package.json` and `colossus.artifacts.json` files, excluding `.git` internals. Other content is read only through repeated `--hash-file` selections. Nothing executes a build, package manager, script, recorded command or remote request.

## What the records mean

- `projects`: a valid Cargo/npm manifest exists in this directory, with its declared name when present. This supplies context, not an authenticated owner.
- `dependencies`: declared Cargo path dependencies (normal/dev/build), npm `file:` dependencies, and literal workspace members. Targets resolve only through the authorized inventory. Missing, external, wildcard, reparse and ambiguous paths remain unresolved. Active usage and transitive dependency completeness are not proven. Cargo target-specific, inherited, patched and remote dependency semantics are not evaluated. npm protocols other than `file:` are not local-path adapters.
- `claims`: strict-schema artifact records retain declared owner, generation method, source revision and retention holds. These are untrusted statements. They do not populate the original Artifact fields as verified provenance. Unknown fields such as `approved` or `safe_to_delete` reject that record file.
- `ownership`: nearest-manifest context plus declared dependency users and artifact claims. Directory relationships and holds propagate to descendants. Hard-link identities combine all observed context/claims; no winner is selected. Multiple contexts produce `shared_context`; multiple distinct owner claims produce `conflicting_claims`. Other statuses are `context_only`, `declared_only` and `unresolved`.
- `hashes`: SHA-256 of exact selected regular files. Equal-hash groups include distinct file identities; hard-link aliases are not counted as separate redundant copies. Equality does not establish that either path is unnecessary. No automatic whole-workspace content hashing occurs.

The existing `Artifact.project_owner` remains the containing Git-root observation for compatibility. Use the new records for contextual/claimed ownership, never as an exclusive-ownership verdict. Candidate evidence IDs can now point to source manifest/registry artifacts as well as the candidate itself.

Every candidate still proposes `investigate` and every inventoried path remains protected. Declared retention holds add blockers. Missing ownership records after a limit or cancellation mean unresolved, not no owner. Inventory completeness does not mean dependency completeness; unresolved relationship rows and collector limitations must be read even when metadata coverage is complete.

## Read and resource boundaries

Each read reopens a pinned ancestor chain and checks identity, size and last-write time against inventory. Content handles deny write and delete sharing. Existing ordinary writers therefore block evidence collection; no incomplete hash is emitted. Reads check cancellation between 64 KiB chunks and compare final metadata. This is not an atomic snapshot or a guarantee against writable mappings, unusual filters, timestamp-preserving changes or later mutation.

Additional content budget: 64 MiB total by default (`--max-content-bytes`), 1 MiB per manifest/record, and 32 MiB per selected hash file. Bytes actually read, including cancelled partial reads, count toward the budget. Failed/oversized reads remain gaps. These limits are separate from the existing 16 MiB per-file Git metadata cap.

Provenance is capped at 10,000 combined projects/dependencies/claims. A registry file permits 1,024 records, 4,096-byte text fields and 128 holds per record. Ownership association/output each cap at 100,000 associations and 32 MiB of associated string bytes, with at most 100,000 ownership records. Truncation or cancellation discards the incomplete ownership result and reports a gap. The base inventory still uses memory proportional to its configured entry limit. Policy/report serialization completes after cancellation; there is no hard wall-clock latency promise.

Untrusted strings are JSON-escaped in machine reports and escaped when rendered in the human report, including retention holds. A report can reveal private paths, project names and record claims; it is not uploaded automatically.

## Optional artifact-record format

Colossus reads this format; it does not create or modify a registry. Save records through a separate authorized authoring workflow if desired. Example `colossus.artifacts.json`:

```json
{
  "schema_version": "1.0.0",
  "artifacts": [
    {
      "path": "target",
      "owner": "build-team",
      "generation_method": "cargo build --release",
      "source_revision": "declared-revision-not-verified",
      "retention_holds": ["needed for offline recovery"]
    }
  ]
}
```

The command string is retained as a claim and never executed. Paths are resolved from the record file's parent against inventoried entries only. See [record schema](../schemas/artifact-records-v1.schema.json) and [report schema](../schemas/report-v1.2.schema.json).

Primary references checked for this implementation: [Cargo dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html), [npm package metadata](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/), [Git index format](https://git-scm.com/docs/gitformat-index), [Windows sharing rules](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), [Windows filename rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file), and [drive types](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew).

Milestone 3 adds [source fingerprints and local consistency checks](CORROBORATION.md). HEAD and supported loose branch-ref reads share the optional content budget and have a 4 KiB per-file limit. Historical reports do not contain these fields.
