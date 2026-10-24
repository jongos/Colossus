#![cfg(windows)]
use colossus_audit::{audit, content::Budget, corroboration, model::Report, Options};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
const REV: &str = "1111111111111111111111111111111111111111";
fn fixture() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "colossus-m3-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&p).unwrap();
    p
}
fn put(p: impl AsRef<Path>, text: &str) {
    fs::create_dir_all(p.as_ref().parent().unwrap()).unwrap();
    fs::write(p, text).unwrap();
}
fn scan(p: &Path) -> Report {
    let mut o = Options::new(vec![p.to_path_buf()]);
    o.provenance = true;
    audit(&o).unwrap()
}
fn registry(p: &Path, rev: &str) {
    put(p.join("colossus.artifacts.json"), &serde_json::json!({"schema_version":"1.0.0","artifacts":[{"path":"target","source_revision":rev}]}).to_string());
    fs::create_dir_all(p.join("target")).unwrap();
}
fn status(r: &Report) -> &str {
    &r.provenance
        .checks
        .iter()
        .find(|c| c.kind == "source_revision")
        .unwrap()
        .status
}
#[test]
fn fingerprints_bind_exact_manifest_bytes_without_selecting_duplicate_candidates() {
    let p = fixture();
    let bytes = "{\"name\":\"test\"}\n";
    put(p.join("package.json"), bytes);
    let r = scan(&p);
    assert_eq!(r.provenance.source_hashes.len(), 1);
    assert_eq!(
        r.provenance.source_hashes[0].sha256,
        format!("{:x}", Sha256::digest(bytes.as_bytes()))
    );
    assert_eq!(r.provenance.bytes_read, bytes.len() as u64);
    assert!(r.provenance.hashes.is_empty());
    assert!(r.provenance.duplicate_groups.is_empty());
}
#[test]
fn detached_revision_match_does_not_authorize_removal() {
    let p = fixture();
    put(p.join("package.json"), "{}");
    registry(&p, REV);
    put(p.join(".git/HEAD"), REV);
    let r = scan(&p);
    assert_eq!(status(&r), "consistent");
    assert!(r
        .candidates
        .iter()
        .all(|c| c.proposed_operation == "investigate" && c.recovery_method.is_none()));
    assert!(!r.candidates.is_empty());
    let check = &r.provenance.checks[0];
    assert_eq!(check.supporting_evidence_ids.len(), 1);
}
#[test]
fn mismatching_revision_is_explicit() {
    let p = fixture();
    put(p.join("package.json"), "{}");
    registry(&p, REV);
    put(p.join(".git/HEAD"), &"2".repeat(40));
    let r = scan(&p);
    assert_eq!(status(&r), "mismatch");
    assert!(r.candidates.iter().any(|c| c
        .blockers
        .iter()
        .any(|b| b.contains("source_revision comparison: mismatch"))));
}
#[test]
fn loose_branch_reads_head_and_ref_once_for_multiple_claims() {
    let p = fixture();
    registry(&p, REV);
    put(p.join(".git/HEAD"), "ref: refs/heads/main\n");
    put(p.join(".git/refs/heads/main"), REV);
    put(p.join("colossus.artifacts.json"),&serde_json::json!({"schema_version":"1.0.0","artifacts":[{"path":"target","source_revision":REV},{"path":"target","source_revision":REV}]}).to_string());
    let r = scan(&p);
    assert_eq!(r.provenance.checks.len(), 2);
    assert!(r.provenance.checks.iter().all(|c| c.status == "consistent"));
    assert_eq!(r.provenance.source_hashes.len(), 3);
}
#[test]
fn packed_refs_and_symbolic_chains_stay_unresolved() {
    let p = fixture();
    registry(&p, REV);
    put(p.join(".git/HEAD"), "ref: refs/heads/main");
    put(
        p.join(".git/packed-refs"),
        &format!("{REV} refs/heads/main\n"),
    );
    assert_eq!(status(&scan(&p)), "unresolved");
    put(p.join(".git/refs/heads/main"), "ref: refs/heads/other");
    put(p.join(".git/refs/heads/other"), REV);
    assert_eq!(status(&scan(&p)), "unresolved");
}
#[test]
fn hostile_ref_claims_never_expand_content_reads() {
    let p = fixture();
    registry(&p, REV);
    put(p.join("outside"), REV);
    for reference in [
        "refs/heads/../../outside",
        "refs/heads/main:stream",
        "refs/heads/main.lock",
        "refs/heads/CON",
        "refs/heads//main",
        "refs/heads/main\nFORGED",
    ] {
        put(p.join(".git/HEAD"), &format!("ref: {reference}"));
        let r = scan(&p);
        assert_eq!(status(&r), "unresolved");
        assert_eq!(r.provenance.source_hashes.len(), 2);
    }
}
#[test]
fn abbreviations_and_zero_ids_are_not_revision_matches() {
    let p = fixture();
    put(p.join(".git/HEAD"), REV);
    for rev in ["1111111".to_string(), "0".repeat(40), "HEAD".into()] {
        registry(&p, &rev);
        let r = scan(&p);
        assert_eq!(status(&r), "unresolved");
        assert_eq!(r.provenance.source_hashes.len(), 1);
    }
}
#[test]
fn nearest_nested_repository_is_the_explicit_comparison_context() {
    let p = fixture();
    put(p.join(".git/HEAD"), REV);
    registry(&p, REV);
    put(p.join("target/.git/HEAD"), &"2".repeat(40));
    assert_eq!(status(&scan(&p)), "mismatch");
}
#[test]
fn linked_worktree_branch_uses_inventoried_common_directory() {
    let p = fixture();
    registry(&p, REV);
    put(p.join(".git"), "gitdir: metadata/worktree");
    put(p.join("metadata/worktree/HEAD"), "ref: refs/heads/main");
    put(p.join("metadata/worktree/commondir"), "..");
    put(p.join("metadata/refs/heads/main"), REV);
    assert_eq!(status(&scan(&p)), "consistent");
    put(p.join("metadata/worktree/commondir"), "../../absent");
    put(p.join("metadata/worktree/refs/heads/main"), REV);
    assert_eq!(status(&scan(&p)), "unresolved");
}
#[test]
fn read_budget_failure_yields_no_revision_match() {
    let p = fixture();
    registry(&p, REV);
    put(p.join(".git/HEAD"), REV);
    let mut o = Options::new(vec![p.clone()]);
    o.provenance = true;
    o.max_content_bytes = fs::metadata(p.join("colossus.artifacts.json"))
        .unwrap()
        .len();
    let r = audit(&o).unwrap();
    assert_eq!(status(&r), "unresolved");
    assert!(!r.complete);
    assert!(r.issues.iter().any(|i| i.code == "corroboration_gap"));
}
#[test]
fn dependencies_require_same_ecosystem_manifest_at_exact_target() {
    let p = fixture();
    put(
        p.join("package.json"),
        r#"{"dependencies":{"a":"file:good","b":"file:wrong","c":"file:empty","d":"file:archive.tgz"}}"#,
    );
    put(p.join("good/package.json"), r#"{"name":"a"}"#);
    put(p.join("wrong/Cargo.toml"), "[package]\nname='b'");
    fs::create_dir(p.join("empty")).unwrap();
    put(p.join("archive.tgz"), "opaque");
    let r = scan(&p);
    assert_eq!(
        r.provenance
            .checks
            .iter()
            .filter(|c| c.kind == "dependency_manifest" && c.status == "consistent")
            .count(),
        1
    );
    assert_eq!(
        r.provenance
            .checks
            .iter()
            .filter(|c| c.kind == "dependency_manifest" && c.status == "unresolved")
            .count(),
        3
    );
}
#[test]
fn junction_ref_directory_is_not_followed() {
    let p = fixture();
    let outside = fixture();
    registry(&p, REV);
    put(p.join(".git/HEAD"), "ref: refs/heads/main");
    put(outside.join("heads/main"), REV);
    assert!(Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(p.join(".git").join("refs"))
        .arg(&outside)
        .output()
        .unwrap()
        .status
        .success());
    let r = scan(&p);
    assert_eq!(status(&r), "unresolved");
    assert!(!r
        .artifacts
        .iter()
        .any(|a| Path::new(&a.path).starts_with(&outside)));
}
#[test]
fn cancellation_stops_corroboration_before_reading_sources() {
    let p = fixture();
    registry(&p, REV);
    put(p.join(".git/HEAD"), REV);
    let mut r = scan(&p);
    r.provenance.checks.clear();
    r.provenance.source_hashes.clear();
    let map: BTreeMap<_, _> = r
        .artifacts
        .iter()
        .map(|a| (PathBuf::from(&a.path), a.clone()))
        .collect();
    let mut budget = Budget::new(10000);
    corroboration::collect(&mut r, &map, &mut budget, &|| true);
    assert_eq!(budget.read, 0);
    assert!(r.provenance.checks.is_empty());
}
#[test]
fn changed_head_identity_is_not_reused_by_corroboration() {
    let p = fixture();
    registry(&p, REV);
    put(p.join(".git/HEAD"), REV);
    let mut r = scan(&p);
    r.provenance.checks.clear();
    let map: BTreeMap<_, _> = r
        .artifacts
        .iter()
        .map(|a| (PathBuf::from(&a.path), a.clone()))
        .collect();
    fs::rename(p.join(".git/HEAD"), p.join(".git/old-head")).unwrap();
    put(p.join(".git/HEAD"), REV);
    corroboration::collect(&mut r, &map, &mut Budget::new(10000), &|| false);
    assert_eq!(status(&r), "unresolved");
    assert!(!r.complete);
}
