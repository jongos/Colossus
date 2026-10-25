#![cfg(windows)]
use colossus_audit::{
    audit,
    model::{CargoLockfileSelection, Report},
    Options,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn put(p: impl AsRef<Path>, s: &str) {
    fs::create_dir_all(p.as_ref().parent().unwrap()).unwrap();
    fs::write(p, s).unwrap();
}
fn setup() -> (PathBuf, Options) {
    let p = std::env::temp_dir().join(format!(
        "colossus-m8-{}-{}",
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
fn membership(r: &Report) -> &str {
    &r.provenance
        .checks
        .iter()
        .find(|c| c.kind == "cargo_selected_workspace_membership")
        .unwrap()
        .status
}
fn chosen() -> (PathBuf, Options) {
    let (p, mut o) = setup();
    bind(&mut o, p.join("one/Cargo.toml"), p.join("Cargo.lock"));
    (p, o)
}
#[test]
fn literal_member_agrees() {
    let (_, o) = chosen();
    let r = audit(&o).unwrap();
    assert_eq!(membership(&r), "consistent");
    assert_eq!(r.provenance.cargo_workspaces.len(), 3);
}
#[test]
fn exclusion_conflicts_with_selection() {
    let (p, o) = chosen();
    put(
        p.join("Cargo.toml"),
        "[workspace]\nmembers=['one','two']\nexclude=['one']",
    );
    assert_eq!(membership(&audit(&o).unwrap()), "mismatch");
}
#[test]
fn absence_is_not_proof_of_nonmembership() {
    let (p, o) = chosen();
    put(p.join("Cargo.toml"), "[workspace]\nmembers=['two']");
    assert_eq!(membership(&audit(&o).unwrap()), "unresolved");
}
#[test]
fn member_glob_is_unsupported() {
    let (p, o) = chosen();
    put(p.join("Cargo.toml"), "[workspace]\nmembers=['*','one']");
    assert_eq!(membership(&audit(&o).unwrap()), "unresolved");
}
#[test]
fn exclusion_glob_prevents_success() {
    let (p, o) = chosen();
    put(
        p.join("Cargo.toml"),
        "[workspace]\nmembers=['one']\nexclude=['o*']",
    );
    assert_eq!(membership(&audit(&o).unwrap()), "unresolved");
}
#[test]
fn malformed_members_prevent_success() {
    let (p, o) = chosen();
    put(p.join("Cargo.toml"), "[workspace]\nmembers=42");
    assert_eq!(membership(&audit(&o).unwrap()), "unresolved");
}
#[test]
fn own_workspace_conflicts() {
    let (p, o) = chosen();
    put(
        p.join("one/Cargo.toml"),
        "[package]\nname='one'\nversion='1.0.0'\n[workspace]",
    );
    assert_eq!(membership(&audit(&o).unwrap()), "mismatch");
}
#[test]
fn matching_explicit_package_workspace() {
    let (p, o) = chosen();
    put(
        p.join("one/Cargo.toml"),
        "[package]\nname='one'\nversion='1.0.0'\nworkspace='..'",
    );
    assert_eq!(membership(&audit(&o).unwrap()), "consistent");
}
#[test]
fn conflicting_explicit_package_workspace() {
    let (p, o) = chosen();
    put(
        p.join("one/Cargo.toml"),
        "[package]\nname='one'\nversion='1.0.0'\nworkspace='../two'",
    );
    assert_eq!(membership(&audit(&o).unwrap()), "mismatch");
}
#[test]
fn missing_pointer_stays_unresolved() {
    let (p, o) = chosen();
    put(
        p.join("one/Cargo.toml"),
        "[package]\nname='one'\nversion='1.0.0'\nworkspace='../absent'",
    );
    assert_eq!(membership(&audit(&o).unwrap()), "unresolved");
}
#[test]
fn malformed_pointer_stays_unresolved() {
    let (p, o) = chosen();
    put(
        p.join("one/Cargo.toml"),
        "[package]\nname='one'\nversion='1.0.0'\nworkspace=42",
    );
    assert_eq!(membership(&audit(&o).unwrap()), "unresolved");
}
#[test]
fn ordinary_adjacent_lock_does_not_imply_workspace() {
    let (p, o) = chosen();
    put(
        p.join("Cargo.toml"),
        "[package]\nname='root'\nversion='1.0.0'",
    );
    assert_eq!(membership(&audit(&o).unwrap()), "unresolved");
}
#[test]
fn alternative_filename_is_not_workspace_root_evidence() {
    let (p, mut o) = setup();
    fs::copy(p.join("Cargo.lock"), p.join("custom.lock")).unwrap();
    bind(&mut o, p.join("one/Cargo.toml"), p.join("custom.lock"));
    assert_eq!(membership(&audit(&o).unwrap()), "unresolved");
}
#[test]
fn workspace_root_package_agrees() {
    let (p, mut o) = setup();
    put(
        p.join("Cargo.toml"),
        "[package]\nname='root'\nversion='1.0.0'\n[workspace]\nmembers=['one']",
    );
    bind(&mut o, p.join("Cargo.toml"), p.join("Cargo.lock"));
    assert_eq!(membership(&audit(&o).unwrap()), "consistent");
}
#[test]
fn unobserved_exclusion_is_uncertainty() {
    let (p, o) = chosen();
    put(
        p.join("Cargo.toml"),
        "[workspace]\nmembers=['one']\nexclude=['absent']",
    );
    assert_eq!(membership(&audit(&o).unwrap()), "unresolved");
}
#[test]
fn no_selection_means_no_membership_check() {
    let (_, o) = setup();
    let r = audit(&o).unwrap();
    assert!(!r
        .provenance
        .checks
        .iter()
        .any(|c| c.kind == "cargo_selected_workspace_membership"));
}
#[test]
fn list_bounds_remain_unresolved() {
    let (p, o) = chosen();
    let members = std::iter::repeat_n("'one'", 1025)
        .collect::<Vec<_>>()
        .join(",");
    put(
        p.join("Cargo.toml"),
        &format!("[workspace]\nmembers=[{members}]"),
    );
    let r = audit(&o).unwrap();
    assert_eq!(membership(&r), "unresolved");
    assert!(r
        .provenance
        .cargo_workspaces
        .iter()
        .all(|w| w.members.len() <= 1024));
}
#[test]
fn lock_version_match_does_not_override_membership_conflict() {
    let (p, o) = chosen();
    put(
        p.join("Cargo.toml"),
        "[workspace]\nmembers=['one']\nexclude=['one']",
    );
    put(p.join("one/target/build.bin"), "keep");
    let r = audit(&o).unwrap();
    assert_eq!(membership(&r), "mismatch");
    let member = r
        .provenance
        .projects
        .iter()
        .find(|p| p.declared_name.as_deref() == Some("one"))
        .unwrap();
    assert_eq!(
        r.provenance
            .checks
            .iter()
            .find(|c| c.kind == "cargo_lock_package_version"
                && c.subject_evidence_id == member.evidence_id)
            .unwrap()
            .status,
        "consistent"
    );
    assert!(r.candidates.iter().any(|c| c
        .blockers
        .iter()
        .any(|b| b.contains("cargo_selected_workspace_membership"))));
    assert!(r
        .candidates
        .iter()
        .all(|c| c.proposed_operation == "investigate"));
}
#[test]
fn membership_adds_no_content_reads_and_preserves_sources() {
    let (p, mut o) = setup();
    let plain = audit(&o).unwrap();
    let before = fs::read(p.join("Cargo.toml")).unwrap();
    let time = fs::metadata(p.join("Cargo.toml"))
        .unwrap()
        .modified()
        .unwrap();
    bind(&mut o, p.join("one/Cargo.toml"), p.join("Cargo.lock"));
    let r = audit(&o).unwrap();
    assert_eq!(plain.provenance.bytes_read, r.provenance.bytes_read);
    assert_eq!(before, fs::read(p.join("Cargo.toml")).unwrap());
    assert_eq!(
        time,
        fs::metadata(p.join("Cargo.toml"))
            .unwrap()
            .modified()
            .unwrap()
    );
}
#[test]
fn cancellation_does_not_claim_membership() {
    let (_, mut o) = chosen();
    o.deadline_ms = Some(0);
    let r = audit(&o).unwrap();
    assert!(r.cancelled);
    assert!(r.provenance.cargo_workspaces.is_empty());
    assert!(!r
        .provenance
        .checks
        .iter()
        .any(|c| c.kind == "cargo_selected_workspace_membership"));
}
#[test]
fn aggregate_declaration_budget_omits_record_with_explicit_gap() {
    let (_, o) = setup();
    let mut r = audit(&o).unwrap();
    let project = r.provenance.projects[0].clone();
    let count = r.provenance.cargo_workspaces.len();
    let mut remaining = 1;
    colossus_audit::workspaces::record(
        &mut r,
        &project.id,
        &project.evidence_id,
        &serde_json::json!({"workspace":{"members":["one","two"]}}),
        &mut remaining,
    );
    assert_eq!(remaining, 1);
    assert_eq!(r.provenance.cargo_workspaces.len(), count);
    assert!(!r.complete);
    assert!(r
        .issues
        .iter()
        .any(|i| i.detail.contains("workspace declaration path budget")));
}
