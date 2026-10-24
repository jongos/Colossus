# Colossus

An evidence-first developer-workspace auditor: a Rust CLI with a portable Codex/Claude skill. Phase 1 inventories explicitly selected roots and identifies questions worth investigating. It performs no cleanup.

**Status:** experimental Windows-first Phase 1. Every candidate remains protected. No file is declared proven disposable. Linux and macOS scanning fail explicitly; they are future work. See [validation](docs/VALIDATION.md) for actual tests and measurements, and [limitations](docs/ARCHITECTURE.md) before relying on a report.

## Build and use

With a Rust toolchain and a compatible Windows linker:

```powershell
cargo build --release --locked
.\target\release\colossus.exe audit --root C:\dev\example --format text
.\target\release\colossus.exe audit --root C:\dev\example --root D:\dev\other --format json --output C:\audit-reports\new-audit.json
```

The output parent must already exist outside the scan roots. Existing output files are never overwritten. Without `--output`, reports go to stdout; do not redirect stdout into a scanned root. Standard shell redirection is outside the CLI's protection boundary. A failed write can leave a partial **new** report; the command reports failure and never deletes it automatically.

Options: `--max-entries N` (default 1,000,000), `--max-depth N` (default 128, maximum 256), `--deadline-ms N`, `--quiet`, `--format text|json`. Ctrl-C requests a partial report. Traversal has one worker; progress is printed to stderr every 1,000 entries. Blocking filesystem calls cannot be forcibly cancelled. Exit status: 0 = complete within stated inventory limits; 2 = incomplete; 130 = cancelled; 1 = error. Missing Git index information makes a repository audit incomplete.

The scanner does not install packages, run build scripts, invoke Git, access the network or send telemetry. Repository configuration and README instructions are never executed. The build itself downloads normal Cargo dependencies when not cached.

## Skill

The same [skill folder](skills/colossus/SKILL.md) works with Codex and Claude Code. Copy it to the appropriate personal skill directory (`~/.codex/skills/colossus` or `~/.claude/skills/colossus`) after building and placing the executable on PATH. The project does not alter agent configuration or install itself automatically.

## Reports and tests

- [Versioned JSON schema](schemas/report-v1.schema.json): Artifact, Evidence, Candidate, Plan and reserved Receipt definitions.
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
