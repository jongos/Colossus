#![cfg(windows)]
use colossus_audit::{
    audit,
    model::{CargoLockfileSelection, Report},
    Options,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn put(p: impl AsRef<Path>, s: &str) {
    fs::create_dir_all(p.as_ref().parent().unwrap()).unwrap();
    fs::write(p, s).unwrap();
}
fn setup() -> (PathBuf, Options) {
    let p = std::env::temp_dir().join(format!(
        "colossus-m7-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    put(p.join("Cargo.toml"), "[workspace]\nmembers=['one','two']");
    put(
        p.join("one/Cargo.toml"),
        "[package]\nname='one'\nversion='1.0.0'\n[dependencies]\ntwo={path='../two',version='2'}",
    );
    put(
        p.join("two/Cargo.toml"),
        "[package]\nname='two'\nversion='2.0.0'",
    );
    put(p.join("Cargo.lock"),"version=4\n[[package]]\nname='one'\nversion='1.0.0'\n[[package]]\nname='two'\nversion='2.0.0'");
    let mut o = Options::new(vec![p.clone()]);
    o.provenance = true;
    (p, o)
}
fn bind(o: &mut Options, m: PathBuf, l: PathBuf) {
    o.cargo_lockfiles.push(CargoLockfileSelection {
        manifest_path: m.to_string_lossy().into(),
        lockfile_path: l.to_string_lossy().into(),
    });
}
fn status(r: &Report, name: &str) -> String {
    let p = r
        .provenance
        .projects
        .iter()
        .find(|p| p.declared_name.as_deref() == Some(name))
        .unwrap();
    r.provenance
        .checks
        .iter()
        .find(|c| c.kind == "cargo_lock_package_version" && c.subject_evidence_id == p.evidence_id)
        .unwrap()
        .status
        .clone()
}
#[test]
fn explicit_shared_lock_matches_members() {
    let (p, mut o) = setup();
    for n in ["one", "two"] {
        bind(&mut o, p.join(n).join("Cargo.toml"), p.join("Cargo.lock"));
    }
    let r = audit(&o).unwrap();
    assert_eq!(status(&r, "one"), "consistent");
    assert_eq!(status(&r, "two"), "consistent");
    assert_eq!(r.provenance.cargo_lockfiles.len(), 2);
    assert_eq!(
        r.provenance
            .checks
            .iter()
            .find(|c| c.kind == "cargo_lock_dependency_version")
            .unwrap()
            .status,
        "consistent"
    );
}
#[test]
fn no_selection_does_not_search_parent() {
    let (_, o) = setup();
    assert_eq!(status(&audit(&o).unwrap(), "one"), "unresolved");
}
#[test]
fn selected_lock_overrides_adjacent() {
    let (p, mut o) = setup();
    put(p.join("one/Cargo.lock"), "malformed[");
    bind(&mut o, p.join("one/Cargo.toml"), p.join("Cargo.lock"));
    let r = audit(&o).unwrap();
    assert!(r.complete);
    assert_eq!(status(&r, "one"), "consistent");
    assert!(!r.provenance.source_hashes.iter().any(|h| r
        .artifacts
        .iter()
        .find(|a| a.id == h.artifact_id)
        .unwrap()
        .path
        == p.join("one/Cargo.lock").to_string_lossy()));
}
#[test]
fn missing_selected_lock_never_falls_back() {
    let (p, mut o) = setup();
    fs::copy(p.join("Cargo.lock"), p.join("one/Cargo.lock")).unwrap();
    bind(&mut o, p.join("one/Cargo.toml"), p.join("missing.lock"));
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert_eq!(status(&r, "one"), "unresolved");
}
#[test]
fn malformed_selected_lock_never_falls_back() {
    let (p, mut o) = setup();
    fs::copy(p.join("Cargo.lock"), p.join("one/Cargo.lock")).unwrap();
    put(p.join("other.lock"), "malformed[");
    bind(&mut o, p.join("one/Cargo.toml"), p.join("other.lock"));
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert_eq!(status(&r, "one"), "unresolved");
}
#[test]
fn outside_scope_lock_is_not_read() {
    let (p, mut o) = setup();
    let (out, _) = setup();
    bind(&mut o, p.join("one/Cargo.toml"), out.join("Cargo.lock"));
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert_eq!(status(&r, "one"), "unresolved");
    assert!(!r
        .artifacts
        .iter()
        .any(|a| a.path.starts_with(out.to_str().unwrap())));
}
#[test]
fn invalid_selected_manifest_omits_comparisons() {
    let (p, mut o) = setup();
    bind(&mut o, p.join("missing.toml"), p.join("Cargo.lock"));
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert!(!r
        .provenance
        .checks
        .iter()
        .any(|c| c.kind.starts_with("cargo_lock_")));
}
#[test]
fn npm_manifest_cannot_be_selected() {
    let (p, mut o) = setup();
    put(p.join("package.json"), "{\"name\":\"npm\"}");
    bind(&mut o, p.join("package.json"), p.join("Cargo.lock"));
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert!(!r
        .provenance
        .checks
        .iter()
        .any(|c| c.kind.starts_with("cargo_lock_")));
}
#[test]
fn duplicate_manifest_selection_is_error() {
    let (p, mut o) = setup();
    for _ in 0..2 {
        bind(&mut o, p.join("one/Cargo.toml"), p.join("Cargo.lock"));
    }
    assert!(audit(&o).is_err());
}
#[test]
fn conflicting_selection_is_error() {
    let (p, mut o) = setup();
    bind(&mut o, p.join("one/Cargo.toml"), p.join("Cargo.lock"));
    bind(&mut o, p.join("one/Cargo.toml"), p.join("another.lock"));
    assert!(audit(&o).is_err());
}
#[test]
fn provenance_required() {
    let (p, mut o) = setup();
    bind(&mut o, p.join("one/Cargo.toml"), p.join("Cargo.lock"));
    o.provenance = false;
    assert!(audit(&o).is_err());
}
#[test]
fn relative_unc_and_parent_paths_rejected() {
    for bad in [
        "Cargo.lock",
        r"\\server\share\Cargo.lock",
        r"C:\data\..\Cargo.lock",
        r"C:Cargo.lock",
    ] {
        let (p, mut o) = setup();
        bind(&mut o, p.join("one/Cargo.toml"), PathBuf::from(bad));
        assert!(audit(&o).is_err(), "{bad}");
    }
}
#[test]
fn selection_count_bounded() {
    let (p, mut o) = setup();
    for i in 0..65 {
        bind(
            &mut o,
            p.join(format!("{i}/Cargo.toml")),
            p.join("Cargo.lock"),
        );
    }
    assert!(audit(&o).is_err());
}
#[test]
fn shared_lock_read_and_fingerprinted_once() {
    let (p, mut o) = setup();
    for n in ["one", "two"] {
        bind(&mut o, p.join(n).join("Cargo.toml"), p.join("Cargo.lock"));
    }
    let r = audit(&o).unwrap();
    let a = r
        .artifacts
        .iter()
        .find(|a| a.path == p.join("Cargo.lock").to_string_lossy())
        .unwrap();
    assert_eq!(
        r.provenance
            .source_hashes
            .iter()
            .filter(|h| h.artifact_id == a.id)
            .count(),
        1
    );
    let sum = r
        .provenance
        .source_hashes
        .iter()
        .map(|h| h.bytes)
        .sum::<u64>();
    assert_eq!(r.provenance.bytes_read, sum);
}
#[test]
fn selections_retained_in_cancelled_report() {
    let (p, mut o) = setup();
    bind(&mut o, p.join("one/Cargo.toml"), p.join("Cargo.lock"));
    o.deadline_ms = Some(0);
    let r = audit(&o).unwrap();
    assert!(r.cancelled);
    assert_eq!(r.provenance.cargo_lockfiles.len(), 1);
    assert!(!r
        .provenance
        .checks
        .iter()
        .any(|c| c.kind.starts_with("cargo_lock_")));
}
#[test]
fn selected_directory_is_gap() {
    let (p, mut o) = setup();
    bind(&mut o, p.join("one/Cargo.toml"), p.join("two"));
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert_eq!(status(&r, "one"), "unresolved");
}
#[test]
fn explicit_arbitrary_filename_and_separate_authorized_root() {
    let (p, mut o) = setup();
    let (out, _) = setup();
    fs::rename(out.join("Cargo.lock"), out.join("chosen.lock")).unwrap();
    o.roots.push(out.clone());
    bind(&mut o, p.join("one/Cargo.toml"), out.join("chosen.lock"));
    let r = audit(&o).unwrap();
    let project = r
        .provenance
        .projects
        .iter()
        .find(|x| x.root == p.join("one").to_string_lossy())
        .unwrap();
    assert_eq!(
        r.provenance
            .checks
            .iter()
            .find(|c| c.kind == "cargo_lock_package_version"
                && c.subject_evidence_id == project.evidence_id)
            .unwrap()
            .status,
        "consistent"
    );
}
#[test]
fn sources_remain_unchanged_and_candidates_protected() {
    let (p, mut o) = setup();
    put(p.join("one/target/output.bin"), "keep");
    bind(&mut o, p.join("one/Cargo.toml"), p.join("Cargo.lock"));
    let before = fs::read(p.join("Cargo.lock")).unwrap();
    let modified = fs::metadata(p.join("Cargo.lock"))
        .unwrap()
        .modified()
        .unwrap();
    let r = audit(&o).unwrap();
    assert_eq!(before, fs::read(p.join("Cargo.lock")).unwrap());
    assert_eq!(
        modified,
        fs::metadata(p.join("Cargo.lock"))
            .unwrap()
            .modified()
            .unwrap()
    );
    assert!(r
        .candidates
        .iter()
        .all(|c| c.proposed_operation == "investigate" && !c.blockers.is_empty()));
}
#[test]
fn cli_pair_and_missing_operand() {
    let (p, _) = setup();
    let binary = env!("CARGO_BIN_EXE_colossus");
    let output = Command::new(binary)
        .args(["audit", "--root"])
        .arg(&p)
        .args([
            "--provenance",
            "--quiet",
            "--format",
            "json",
            "--cargo-lockfile",
        ])
        .arg(p.join("one/Cargo.toml"))
        .arg(p.join("Cargo.lock"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let r: Report = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status(&r, "one"), "consistent");
    let bad = Command::new(binary)
        .args(["audit", "--cargo-lockfile"])
        .arg(p.join("one/Cargo.toml"))
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
}

#[test]
fn absent_shared_lock_is_gap_even_when_default_project_was_checked_first() {
    let (p, mut o) = setup();
    let absent = p.join("empty/Cargo.lock");
    put(p.join("empty/Cargo.toml"), "[workspace]\nmembers=[]");
    bind(&mut o, p.join("one/Cargo.toml"), absent);
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert_eq!(status(&r, "one"), "unresolved");
    assert!(r
        .issues
        .iter()
        .any(|i| i.detail.contains("Selected lockfile is not in")));
}
