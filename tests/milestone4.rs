#![cfg(windows)]
use colossus_audit::{audit, model::Report, Options};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
const HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
fn fixture() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "colossus-m4-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&p).unwrap();
    p
}
fn put(p: impl AsRef<Path>, s: &str) {
    fs::create_dir_all(p.as_ref().parent().unwrap()).unwrap();
    fs::write(p, s).unwrap();
}
fn statement(name: &str, digest: &str) -> Value {
    json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":name,"digest":{"sha256":digest}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"externalParameters":{"command":"do not execute"}}}})
}
fn setup() -> (PathBuf, Options) {
    let p = fixture();
    put(p.join("artifact.bin"), "abc");
    put(
        p.join("statement.json"),
        &statement("artifact.bin", HASH).to_string(),
    );
    let mut o = Options::new(vec![p.clone()]);
    o.statement_files.push(p.join("statement.json"));
    o.hash_files.push(p.join("artifact.bin"));
    (p, o)
}
fn check<'a>(r: &'a Report, kind: &str) -> &'a str {
    &r.provenance
        .checks
        .iter()
        .find(|c| c.kind == kind)
        .unwrap()
        .status
}
fn cargo(requirement: &str, version: &str, name: &str) -> Report {
    let p = fixture();
    put(p.join("Cargo.toml"),&format!("[package]\nname='root'\nversion='1.0.0'\n[dependencies]\nalias={{path='dep',package='actual',version='{requirement}'}}"));
    put(
        p.join("dep/Cargo.toml"),
        &format!("[package]\nname='{name}'\nversion='{version}'"),
    );
    let mut o = Options::new(vec![p]);
    o.provenance = true;
    audit(&o).unwrap()
}
#[test]
fn cargo_rename_and_compatible_range_match() {
    let r = cargo("^1.2", "1.5.0", "actual");
    assert_eq!(check(&r, "cargo_package_name"), "consistent");
    assert_eq!(check(&r, "cargo_version_requirement"), "consistent");
}
#[test]
fn cargo_name_and_version_mismatches_are_independent() {
    let r = cargo("~1.2", "2.0.0", "wrong");
    assert_eq!(check(&r, "cargo_package_name"), "mismatch");
    assert_eq!(check(&r, "cargo_version_requirement"), "mismatch");
    assert_eq!(check(&r, "dependency_manifest"), "consistent");
}
#[test]
fn cargo_prereleases_follow_explicit_range_semantics() {
    assert_eq!(
        check(
            &cargo("^1.2", "1.3.0-beta.1", "actual"),
            "cargo_version_requirement"
        ),
        "mismatch"
    );
    assert_eq!(
        check(
            &cargo(">=1.3.0-beta.1, <2", "1.3.0-beta.2", "actual"),
            "cargo_version_requirement"
        ),
        "consistent"
    );
}
#[test]
fn malformed_versions_never_match() {
    for (req, ver) in [("latest", "1.0.0"), ("^1", "not-a-version")] {
        assert_eq!(
            check(&cargo(req, ver, "actual"), "cargo_version_requirement"),
            "unresolved"
        );
    }
}
#[test]
fn inherited_and_missing_versions_stay_unresolved() {
    let p = fixture();
    put(
        p.join("Cargo.toml"),
        "[package]\nname='a'\n[dependencies]\nb={path='b',version='1'}",
    );
    put(
        p.join("b/Cargo.toml"),
        "[package]\nname='b'\nversion.workspace=true",
    );
    let mut o = Options::new(vec![p.clone()]);
    o.provenance = true;
    assert_eq!(
        check(&audit(&o).unwrap(), "cargo_version_requirement"),
        "unresolved"
    );
    put(
        p.join("Cargo.toml"),
        "[package]\nname='a'\n[dependencies]\nb={path='b'}",
    );
    put(
        p.join("b/Cargo.toml"),
        "[package]\nname='b'\nversion='1.0.0'",
    );
    assert_eq!(
        check(&audit(&o).unwrap(), "cargo_version_requirement"),
        "unresolved"
    );
}
#[test]
fn statement_digest_match_is_unauthenticated_and_source_preserving() {
    let (p, o) = setup();
    let before = fs::metadata(p.join("artifact.bin"))
        .unwrap()
        .modified()
        .unwrap();
    let r = audit(&o).unwrap();
    assert_eq!(check(&r, "statement_digest"), "consistent");
    assert!(!r.provenance.enabled);
    assert_eq!(
        r.provenance.statement_subjects[0].authentication,
        "unverified"
    );
    assert_eq!(fs::read(p.join("artifact.bin")).unwrap(), b"abc");
    assert_eq!(
        before,
        fs::metadata(p.join("artifact.bin"))
            .unwrap()
            .modified()
            .unwrap()
    );
    assert_eq!(r.provenance.source_hashes.len(), 1);
}
#[test]
fn statement_digest_mismatch_is_explicit() {
    let (p, o) = setup();
    put(p.join("artifact.bin"), "different");
    assert_eq!(check(&audit(&o).unwrap(), "statement_digest"), "mismatch");
}
#[test]
fn statement_does_not_implicitly_hash_target() {
    let (p, mut o) = setup();
    o.hash_files.clear();
    let r = audit(&o).unwrap();
    assert_eq!(check(&r, "statement_digest"), "unresolved");
    assert!(r.provenance.hashes.is_empty());
    assert_eq!(
        r.provenance.bytes_read,
        fs::metadata(p.join("statement.json")).unwrap().len()
    );
}
#[test]
fn statements_are_not_automatically_discovered() {
    let (_, mut o) = setup();
    o.statement_files.clear();
    o.hash_files.clear();
    o.provenance = true;
    let r = audit(&o).unwrap();
    assert!(r.provenance.statement_subjects.is_empty());
    assert_eq!(r.provenance.bytes_read, 0);
}
#[test]
fn statement_selection_must_be_in_inventory() {
    let (p, mut o) = setup();
    let outside = fixture();
    put(
        outside.join("statement.json"),
        &statement("artifact.bin", HASH).to_string(),
    );
    o.statement_files = vec![outside.join("statement.json")];
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert!(r.provenance.statement_subjects.is_empty());
    assert_eq!(r.provenance.bytes_read, 3);
    assert!(p.exists());
}
#[test]
fn unsafe_subject_names_never_resolve_even_when_target_is_in_inventory() {
    let (p, o) = setup();
    for name in [
        "../artifact.bin",
        "artifact.bin:stream",
        "file:///artifact.bin",
        "./artifact.bin",
        "a/../artifact.bin",
        "C:/artifact.bin",
    ] {
        put(p.join("statement.json"), &statement(name, HASH).to_string());
        let r = audit(&o).unwrap();
        assert_eq!(check(&r, "statement_digest"), "unresolved");
        assert!(r.provenance.statement_subjects[0]
            .target_artifact_id
            .is_none());
    }
}
#[test]
fn signature_envelopes_and_duplicate_digests_are_rejected() {
    let (p, o) = setup();
    for value in [
        r#"{"payload":"opaque","signatures":[]}"#.to_string(),
        statement("artifact.bin", HASH).to_string().replace(
            &format!("\"sha256\":\"{HASH}\""),
            &format!("\"sha256\":\"{HASH}\",\"sha256\":\"{HASH}\""),
        ),
    ] {
        put(p.join("statement.json"), &value);
        let r = audit(&o).unwrap();
        assert!(!r.complete);
        assert!(r.provenance.statement_subjects.is_empty());
    }
}
#[test]
fn unsupported_digest_and_oversized_subject_list_fail_closed() {
    let (p, o) = setup();
    let mut s = statement("artifact.bin", HASH);
    s["subject"][0]["digest"] = json!({"sha512":"abc"});
    put(p.join("statement.json"), &s.to_string());
    assert!(audit(&o).unwrap().provenance.statement_subjects.is_empty());
    s = statement("artifact.bin", HASH);
    s["subject"] = json!(vec![s["subject"][0].clone(); 1025]);
    put(p.join("statement.json"), &s.to_string());
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert!(r.provenance.statement_subjects.is_empty());
}
#[test]
fn statement_budget_and_duplicate_selection_are_bounded() {
    let (p, mut o) = setup();
    o.statement_files.push(p.join("statement.json"));
    let r = audit(&o).unwrap();
    assert_eq!(r.provenance.statement_subjects.len(), 1);
    o.max_content_bytes = 3;
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert_eq!(r.provenance.bytes_read, 3);
    assert!(r.provenance.statement_subjects.is_empty());
}
#[test]
fn junction_subject_does_not_escape_inventory() {
    let (p, o) = setup();
    let outside = fixture();
    put(outside.join("artifact.bin"), "abc");
    assert!(Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(p.join("link"))
        .arg(&outside)
        .output()
        .unwrap()
        .status
        .success());
    put(
        p.join("statement.json"),
        &statement("link/artifact.bin", HASH).to_string(),
    );
    let r = audit(&o).unwrap();
    assert_eq!(check(&r, "statement_digest"), "unresolved");
}
#[test]
fn same_content_hardlink_is_not_an_implicitly_selected_subject() {
    let (p, o) = setup();
    fs::hard_link(p.join("artifact.bin"), p.join("alias.bin")).unwrap();
    put(
        p.join("statement.json"),
        &statement("alias.bin", HASH).to_string(),
    );
    assert_eq!(check(&audit(&o).unwrap(), "statement_digest"), "unresolved");
}

#[test]
fn selected_statement_count_stops_at_32() {
    let (p, mut o) = setup();
    o.statement_files.clear();
    for i in 0..33 {
        let file = p.join(format!("statement-{i}.json"));
        put(&file, &statement("artifact.bin", HASH).to_string());
        o.statement_files.push(file);
    }
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert_eq!(r.provenance.statement_subjects.len(), 32);
    assert!(r.issues.iter().any(|i| i.detail.contains("limit (32)")));
}
#[test]
fn oversized_statement_is_refused_before_content_read() {
    let (p, o) = setup();
    put(p.join("statement.json"), &" ".repeat(1024 * 1024 + 1));
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert_eq!(r.provenance.bytes_read, 3);
    assert!(r.provenance.statement_subjects.is_empty());
}
#[test]
fn aggregate_subject_count_is_bounded() {
    let (p, mut o) = setup();
    o.statement_files.clear();
    let mut s = statement("artifact.bin", HASH);
    s["subject"] = json!(vec![s["subject"][0].clone(); 1024]);
    for i in 0..10 {
        let file = p.join(format!("statement-{i}.json"));
        put(&file, &s.to_string());
        o.statement_files.push(file);
    }
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert_eq!(r.provenance.statement_subjects.len(), 9216);
    assert!(r.issues.iter().any(|i| i.detail.contains("subject budget")));
}
#[test]
fn contradictory_subject_digests_remain_separate() {
    let (p, o) = setup();
    let mut s = statement("artifact.bin", HASH);
    let mut other = s["subject"][0].clone();
    other["digest"]["sha256"] = json!("0".repeat(64));
    s["subject"].as_array_mut().unwrap().push(other);
    put(p.join("statement.json"), &s.to_string());
    let r = audit(&o).unwrap();
    assert_eq!(r.provenance.statement_subjects.len(), 2);
    assert_eq!(
        r.provenance
            .checks
            .iter()
            .filter(|c| c.status == "consistent")
            .count(),
        1
    );
    assert_eq!(
        r.provenance
            .checks
            .iter()
            .filter(|c| c.status == "mismatch")
            .count(),
        1
    );
}
#[test]
fn missing_digest_is_unresolved_even_when_target_hash_exists() {
    let (p, o) = setup();
    let mut s = statement("artifact.bin", HASH);
    s["subject"][0]["digest"] = json!({});
    put(p.join("statement.json"), &s.to_string());
    assert_eq!(check(&audit(&o).unwrap(), "statement_digest"), "unresolved");
}
#[test]
fn candidate_retains_both_name_and_version_blockers() {
    let p = fixture();
    put(
        p.join("Cargo.toml"),
        "[package]\nname='root'\n[dependencies]\nactual={path='dep',version='1'}",
    );
    put(
        p.join("dep/Cargo.toml"),
        "[package]\nname='wrong'\nversion='2.0.0'",
    );
    fs::create_dir(p.join("dep/target")).unwrap();
    let mut o = Options::new(vec![p]);
    o.provenance = true;
    let r = audit(&o).unwrap();
    let c = &r.candidates[0];
    assert!(c
        .blockers
        .iter()
        .any(|b| b.contains("cargo_package_name comparison: mismatch")));
    assert!(c
        .blockers
        .iter()
        .any(|b| b.contains("cargo_version_requirement comparison: mismatch")));
}

#[test]
fn descendant_statement_mismatch_reaches_directory_candidate() {
    let p = fixture();
    put(p.join("package.json"), "{}");
    put(p.join("build/out.bin"), "abc");
    put(
        p.join("statement.json"),
        &statement("build/out.bin", &"0".repeat(64)).to_string(),
    );
    let mut o = Options::new(vec![p.clone()]);
    o.statement_files.push(p.join("statement.json"));
    o.hash_files.push(p.join("build/out.bin"));
    let r = audit(&o).unwrap();
    let subject = &r.provenance.statement_subjects[0];
    let c = &r.candidates[0];
    assert!(c.evidence_ids.contains(&subject.evidence_id));
    assert!(c
        .blockers
        .iter()
        .any(|b| b.contains("statement_digest comparison: mismatch")));
    assert_eq!(c.proposed_operation, "investigate");
}
