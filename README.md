# Colossus

An evidence-first developer-workspace auditor: a Rust CLI with a portable Codex/Claude skill. Phase 1 inventories explicitly selected roots and identifies questions worth investigating. It performs no cleanup.

**Status:** experimental Windows-first read-only milestone 6 (v0.6.0). Every candidate remains protected. No file is declared proven disposable. Linux and macOS scanning fail explicitly; they are future work. See [current milestone validation](docs/MILESTONE-6.md), [historical Phase 1 validation](docs/VALIDATION.md), and [limitations](docs/ARCHITECTURE.md) before relying on a report.

## Build and use

With a Rust toolchain and a compatible Windows linker:

```powershell
cargo build --release --locked
.\target\release\colossus.exe audit --root C:\dev\example --format text
.\target\release\colossus.exe audit --root C:\dev\example --root D:\dev\other --format json --output C:\audit-reports\new-audit.json
.\target\release\colossus.exe audit --root C:\dev\example --provenance --format json
.\target\release\colossus.exe audit --root C:\dev\example --hash-file C:\dev\example\export-a.zip --hash-file C:\dev\example\export-b.zip --max-content-bytes 67108864
```

The output parent must already exist outside the scan roots. Existing output files are never overwritten. Without `--output`, reports go to stdout; do not redirect stdout into a scanned root. Standard shell redirection is outside the CLI's protection boundary. A failed write can leave a partial **new** report; the command reports failure and never deletes it automatically.

Options: `--max-entries N` (default 1,000,000), `--max-depth N` (default 128, maximum 256), `--deadline-ms N`, `--quiet`, `--format text|json`. Ctrl-C requests a partial report. Traversal has one worker; progress is printed to stderr every 1,000 entries. Blocking filesystem calls cannot be forcibly cancelled. Exit status: 0 = complete within stated inventory limits; 2 = incomplete; 130 = cancelled; 1 = error. Missing Git index information makes a repository audit incomplete.

The scanner does not install packages, run build scripts, invoke Git, access the network or send telemetry. Repository configuration and README instructions are never executed. The build itself downloads normal Cargo dependencies when not cached.

`--provenance` reads bounded Cargo/npm manifests and optional `colossus.artifacts.json` claim files. It reports project context, declared local/workspace dependencies, shared identities, conflicting owners and retention holds. `--hash-file` reads only exact selected inventoried files. Additional content reads are bounded to 64 MiB total by default, 1 MiB per manifest/record, and 32 MiB per selected file. Git metadata retains its separate 16 MiB per-file cap. Claims, checksums and equal hashes never authorize cleanup. See [evidence semantics and record format](docs/PROVENANCE.md).

## Skill

The same [skill folder](skills/colossus/SKILL.md) works with Codex and Claude Code. Copy it to the appropriate personal skill directory (`~/.codex/skills/colossus` or `~/.claude/skills/colossus`) after building and placing the executable on PATH. The project does not alter agent configuration or install itself automatically.

## Reports and tests

- [Current JSON schema](schemas/report-v1.5.schema.json) and [untrusted artifact-record schema](schemas/artifact-records-v1.schema.json). The original [v1.0 report schema](schemas/report-v1.schema.json) remains for historical reports.
- [Architecture and security boundaries](docs/ARCHITECTURE.md).
- [Validation and performance](docs/VALIDATION.md).
- [Research and roadmap](docs/ROADMAP.md).

```powershell
cargo test --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
python scripts/benchmark.py --binary target/release/colossus.exe --output work/benchmark.json
```

Tests create synthetic disposable directories; they never use private projects. Fixture directories are retained in the OS temporary directory for inspection. Benchmarks and reports belong in ignored `work/`, `reports/` or a user-selected external location. No database is used.

Public source is available for inspection. No redistribution license has been selected yet; publication alone does not grant an open-source license. No competitor implementation code is included.

## Milestone 3

Optional provenance collection now fingerprints observed evidence sources and compares local revision claims and dependency targets with bounded observations. Matching local values remain unauthenticated consistency evidence. See [Milestone 3 validation](docs/MILESTONE-3.md) and [comparison semantics](docs/CORROBORATION.md). The CLI remains read-only.

## Milestone 4

Cargo path dependencies now retain declared package names and version requirements and compare them with target manifests. Explicitly selected offline in-toto statements can be compared with selected file hashes. Neither capability verifies build execution or authenticated provenance. See [statement format and limits](docs/STATEMENTS.md) and [Milestone 4 validation](docs/MILESTONE-4.md).

```powershell
.\target\release\colossus.exe audit --root C:\dev\example --statement-file C:\dev\example\statement.json --hash-file C:\dev\example\build\output.bin --format json
```

## Milestone 5

Offline DSSE/Ed25519 verification accepts only explicitly supplied public keys. Signature status is separate from subject-digest agreement and build claims. No key is trusted by default. See [trust policy and supported envelopes](docs/AUTHENTICATION.md) and [Milestone 5 validation](docs/MILESTONE-5.md).

```powershell
.\target\release\colossus.exe audit --root C:\dev\example --statement-file C:\dev\example\envelope.json --hash-file C:\dev\example\build\output.bin --trusted-key release=PUBLIC_KEY_HEX --format json
```

Replace `PUBLIC_KEY_HEX` with the independently approved 64-character Ed25519 public key. This option does not install or persist trust configuration.

## Milestone 6

With `--provenance`, bounded adjacent Cargo.lock v3/v4 observations compare explicit package versions and declared local dependency targets with source-less lock entries. No resolver or build is run. See [lockfile scope and limits](docs/LOCKFILES.md) and [Milestone 6 validation](docs/MILESTONE-6.md).
