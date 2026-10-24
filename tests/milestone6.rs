#![cfg(windows)]
use colossus_audit::{audit, model::Report, Options};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn fixture(lock: Option<&str>) -> (PathBuf, Options) {
    let p = std::env::temp_dir().join(format!(
        "colossus-m6-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(p.join("dep")).unwrap();
    fs::write(p.join("Cargo.toml"),"[package]\nname='root'\nversion='1.0.0'\n[dependencies]\nrenamed={path='dep',package='child',version='^2'}").unwrap();
    fs::write(
        p.join("dep/Cargo.toml"),
        "[package]\nname='child'\nversion='2.0.0'",
    )
    .unwrap();
    if let Some(s) = lock {
        fs::write(p.join("Cargo.lock"), s).unwrap();
    }
    let mut o = Options::new(vec![p.clone()]);
    o.provenance = true;
    (p, o)
}
fn lock(root: &str, child: &str) -> String {
    format!("version=4\n[[package]]\nname='root'\nversion='{root}'\n[[package]]\nname='child'\nversion='{child}'\n")
}
fn status(r: &Report, kind: &str) -> String {
    r.provenance
        .checks
        .iter()
        .find(|c| c.kind == kind)
        .unwrap()
        .status
        .clone()
}
fn run(s: &str) -> Report {
    let (_, o) = fixture(Some(s));
    audit(&o).unwrap()
}
#[test]
fn matches_root_and_renamed_local_dependency() {
    let r = run(&lock("1.0.0", "2.0.0"));
    assert_eq!(status(&r, "cargo_lock_package_version"), "consistent");
    assert_eq!(status(&r, "cargo_lock_dependency_version"), "consistent");
}
#[test]
fn differing_versions_are_mismatches() {
    let r = run(&lock("1.1.0", "2.1.0"));
    assert_eq!(status(&r, "cargo_lock_package_version"), "mismatch");
    assert_eq!(status(&r, "cargo_lock_dependency_version"), "mismatch");
}
#[test]
fn missing_adjacent_lockfile_is_unresolved_not_collection_failure() {
    let (_, o) = fixture(None);
    let r = audit(&o).unwrap();
    assert!(r.complete);
    assert_eq!(status(&r, "cargo_lock_package_version"), "unresolved");
}
#[test]
fn remote_entry_cannot_satisfy_local_comparison() {
    let s = lock("1.0.0", "2.0.0") + "source='registry+https://example.invalid'\n";
    assert_eq!(
        status(&run(&s), "cargo_lock_dependency_version"),
        "unresolved"
    );
}
#[test]
fn same_name_remote_entry_does_not_mask_local_entry() {
    let s = lock("1.0.0", "2.0.0")
        + "[[package]]\nname='child'\nversion='7.0.0'\nsource='registry+https://example.invalid'\n";
    assert_eq!(
        status(&run(&s), "cargo_lock_dependency_version"),
        "consistent"
    );
}
#[test]
fn duplicate_local_identity_is_ambiguous() {
    let s = lock("1.0.0", "2.0.0") + "[[package]]\nname='child'\nversion='2.0.0'\n";
    assert_eq!(
        status(&run(&s), "cargo_lock_dependency_version"),
        "unresolved"
    );
}
#[test]
fn multiple_local_versions_are_ambiguous() {
    let s = lock("1.0.0", "2.0.0") + "[[package]]\nname='child'\nversion='3.0.0'\n";
    assert_eq!(
        status(&run(&s), "cargo_lock_dependency_version"),
        "unresolved"
    );
}
#[test]
fn supports_v3() {
    assert_eq!(
        status(
            &run(&lock("1.0.0", "2.0.0").replacen("version=4", "version=3", 1)),
            "cargo_lock_package_version"
        ),
        "consistent"
    );
}
#[test]
fn unknown_or_absent_format_is_gap() {
    for s in [
        "version=9\npackage=[]",
        "package=[]",
        "version='4'\npackage=[]",
    ] {
        let r = run(s);
        assert!(!r.complete);
        assert_eq!(status(&r, "cargo_lock_package_version"), "unresolved");
    }
}
#[test]
fn malformed_packages_reject_entire_observation() {
    for tail in [
        "[[package]]\nname='bad'\nversion='nope'",
        "[[package]]\nname='bad'\nversion='1.0.0'\nsource=42",
        "[[package]]\nname='bad'\nversion='1.0.0'\nsource=''",
        "[[package]]\nversion='1.0.0'",
    ] {
        let r = run(&(lock("1.0.0", "2.0.0") + tail));
        assert!(!r.complete);
        assert_eq!(status(&r, "cargo_lock_package_version"), "unresolved");
    }
}
#[test]
fn duplicate_toml_fields_are_gap() {
    let r = run("version=4\nversion=3\npackage=[]");
    assert!(!r.complete);
}
#[test]
fn no_implicit_parent_lockfile_lookup() {
    let (p, o) = fixture(Some(&lock("1.0.0", "2.0.0")));
    let r = audit(&o).unwrap();
    let child = r
        .provenance
        .projects
        .iter()
        .find(|x| x.root == p.join("dep").to_string_lossy())
        .unwrap();
    assert_eq!(
        r.provenance
            .checks
            .iter()
            .find(|c| c.kind == "cargo_lock_package_version"
                && c.subject_evidence_id == child.evidence_id)
            .unwrap()
            .status,
        "unresolved"
    );
}
#[test]
fn target_name_mismatch_remains_unresolved() {
    let (p, o) = fixture(Some(&lock("1.0.0", "2.0.0")));
    fs::write(
        p.join("dep/Cargo.toml"),
        "[package]\nname='other'\nversion='2.0.0'",
    )
    .unwrap();
    assert_eq!(
        status(&audit(&o).unwrap(), "cargo_lock_dependency_version"),
        "unresolved"
    );
}
#[test]
fn inherited_version_remains_unresolved() {
    let (p, o) = fixture(Some(&lock("1.0.0", "2.0.0")));
    fs::write(
        p.join("dep/Cargo.toml"),
        "[package]\nname='child'\nversion.workspace=true",
    )
    .unwrap();
    assert_eq!(
        status(&audit(&o).unwrap(), "cargo_lock_dependency_version"),
        "unresolved"
    );
}
#[test]
fn disabled_provenance_does_not_read_lockfile() {
    let (_, mut o) = fixture(Some("malformed["));
    o.provenance = false;
    let r = audit(&o).unwrap();
    assert!(r.complete);
    assert!(r.provenance.source_hashes.is_empty());
    assert!(r.provenance.checks.is_empty());
}
#[test]
fn shared_content_budget_blocks_lockfile_read() {
    let (p, mut o) = fixture(Some(&lock("1.0.0", "2.0.0")));
    o.max_content_bytes = fs::metadata(p.join("Cargo.toml")).unwrap().len()
        + fs::metadata(p.join("dep/Cargo.toml")).unwrap().len();
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert_eq!(status(&r, "cargo_lock_package_version"), "unresolved");
    assert!(!r.provenance.source_hashes.iter().any(|h| r
        .artifacts
        .iter()
        .find(|a| a.id == h.artifact_id)
        .unwrap()
        .path
        .ends_with("Cargo.lock")));
}
#[test]
fn oversize_lockfile_is_not_read() {
    let s = "#".to_owned() + &"x".repeat(1024 * 1024);
    let r = run(&s);
    assert!(!r.complete);
    assert_eq!(status(&r, "cargo_lock_package_version"), "unresolved");
}
#[test]
fn package_count_is_bounded() {
    let s = "version=4\n".to_owned() + &"[[package]]\nname='a'\nversion='1.0.0'\n".repeat(10001);
    let r = run(&s);
    assert!(!r.complete);
    assert_eq!(status(&r, "cargo_lock_package_version"), "unresolved");
}
#[test]
fn directory_named_lockfile_is_not_read() {
    let (p, o) = fixture(None);
    fs::create_dir(p.join("Cargo.lock")).unwrap();
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert_eq!(status(&r, "cargo_lock_package_version"), "unresolved");
}
#[test]
fn evidence_is_linked_and_sources_preserved() {
    let (p, o) = fixture(Some(&lock("1.0.0", "2.0.0")));
    let before = fs::read(p.join("Cargo.lock")).unwrap();
    let time = fs::metadata(p.join("Cargo.lock"))
        .unwrap()
        .modified()
        .unwrap();
    let r = audit(&o).unwrap();
    let a = r
        .artifacts
        .iter()
        .find(|a| a.path == p.join("Cargo.lock").to_string_lossy())
        .unwrap();
    let h = r
        .provenance
        .source_hashes
        .iter()
        .find(|h| h.artifact_id == a.id)
        .unwrap();
    for c in r
        .provenance
        .checks
        .iter()
        .filter(|c| c.kind.starts_with("cargo_lock_") && c.status == "consistent")
    {
        assert!(c.supporting_evidence_ids.contains(&h.evidence_id));
    }
    assert_eq!(before, fs::read(p.join("Cargo.lock")).unwrap());
    assert_eq!(
        time,
        fs::metadata(p.join("Cargo.lock"))
            .unwrap()
            .modified()
            .unwrap()
    );
    assert!(r
        .candidates
        .iter()
        .all(|c| c.proposed_operation == "investigate"));
    assert!(r
        .artifacts
        .iter()
        .all(|a| r.plan.protected_paths.contains(&a.path)));
}
#[test]
fn prerelease_is_not_release() {
    assert_eq!(
        status(
            &run(&lock("1.0.0-rc.1", "2.0.0")),
            "cargo_lock_package_version"
        ),
        "mismatch"
    );
}
#[test]
fn cancelled_collection_has_no_lockfile_success() {
    let (_, mut o) = fixture(Some(&lock("1.0.0", "2.0.0")));
    o.deadline_ms = Some(0);
    let r = audit(&o).unwrap();
    assert!(r.cancelled);
    assert!(!r
        .provenance
        .checks
        .iter()
        .any(|c| c.kind.starts_with("cargo_lock_") && c.status == "consistent"));
}
