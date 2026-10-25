#![cfg(windows)]
//! These tests must never perform a successful deletion. Fixtures are retained.
use colossus_audit::cleanup;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
fn fixture() -> (PathBuf, PathBuf) {
    let p = std::env::temp_dir().join(format!(
        "colossus-cleanup-refusal-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&p).unwrap();
    let f = p.join("artifact.bin");
    fs::write(&f, b"synthetic disposable bytes").unwrap();
    (p, f)
}
fn make(p: &std::path::Path, f: PathBuf) -> cleanup::Plan {
    cleanup::plan(
        p,
        &[f],
        "synthetic fixture".into(),
        "synthetic; no recovery needed".into(),
        &AtomicBool::new(false),
    )
    .unwrap()
}
#[test]
fn plan_is_read_only() {
    let (p, f) = fixture();
    let bytes = fs::read(&f).unwrap();
    let time = fs::metadata(&f).unwrap().modified().unwrap();
    let plan = make(&p, f.clone());
    assert_eq!(plan.operation, "permanent-delete-files");
    assert_eq!(plan.targets.len(), 1);
    assert_eq!(bytes, fs::read(&f).unwrap());
    assert_eq!(time, fs::metadata(&f).unwrap().modified().unwrap());
    assert!(cleanup::review(&plan).contains(&format!("{:?}", f.to_str().unwrap())));
}
#[test]
fn declined_approval_never_deletes() {
    let (p, f) = fixture();
    let plan = make(&p, f.clone());
    let receipt = p.with_extension("receipt.jsonl");
    let asked = AtomicBool::new(false);
    assert!(
        cleanup::execute(&plan, &receipt, &AtomicBool::new(false), |_| {
            asked.store(true, Ordering::Relaxed);
            Ok(false)
        })
        .is_err()
    );
    assert!(asked.load(Ordering::Relaxed));
    assert!(f.exists());
    assert!(!receipt.exists());
}
#[test]
fn changed_content_rejected_before_approval() {
    let (p, f) = fixture();
    let plan = make(&p, f.clone());
    fs::write(&f, b"changed").unwrap();
    assert!(cleanup::execute(
        &plan,
        &p.with_extension("receipt.jsonl"),
        &AtomicBool::new(false),
        |_| panic!("stale plan asked for approval")
    )
    .is_err());
    assert_eq!(fs::read(&f).unwrap(), b"changed");
}
#[test]
fn tampered_plan_rejected() {
    let (p, f) = fixture();
    let mut plan = make(&p, f.clone());
    plan.reason = "tampered".into();
    assert!(cleanup::execute(
        &plan,
        &p.with_extension("receipt.jsonl"),
        &AtomicBool::new(false),
        |_| panic!("tampered plan asked for approval")
    )
    .is_err());
    assert!(f.exists());
}
#[test]
fn directory_refused() {
    let (p, _) = fixture();
    let dir = p.join("nested.bin");
    fs::create_dir(&dir).unwrap();
    assert!(cleanup::plan(&p, &[dir], "x".into(), "x".into(), &AtomicBool::new(false)).is_err());
}
#[test]
fn source_file_refused() {
    let (p, _) = fixture();
    let f = p.join("main.rs");
    fs::write(&f, b"source").unwrap();
    assert!(cleanup::plan(
        &p,
        std::slice::from_ref(&f),
        "x".into(),
        "x".into(),
        &AtomicBool::new(false)
    )
    .is_err());
    assert!(f.exists());
}
#[test]
fn repository_scope_refused() {
    let (p, f) = fixture();
    fs::create_dir(p.join(".git")).unwrap();
    assert!(cleanup::plan(
        &p,
        std::slice::from_ref(&f),
        "x".into(),
        "x".into(),
        &AtomicBool::new(false)
    )
    .is_err());
    assert!(f.exists());
}
#[test]
fn retention_registry_refused() {
    let (p, f) = fixture();
    fs::write(p.join("colossus.artifacts.json"), "{}").unwrap();
    assert!(cleanup::plan(
        &p,
        std::slice::from_ref(&f),
        "x".into(),
        "x".into(),
        &AtomicBool::new(false)
    )
    .is_err());
    assert!(f.exists());
}
#[test]
fn retention_added_after_plan_blocks_before_approval() {
    let (p, f) = fixture();
    let plan = make(&p, f.clone());
    fs::write(p.join("colossus.artifacts.json"), "{}").unwrap();
    assert!(cleanup::execute(
        &plan,
        &p.with_extension("receipt.jsonl"),
        &AtomicBool::new(false),
        |_| panic!("retention gap ignored")
    )
    .is_err());
    assert!(f.exists());
}
#[test]
fn outside_root_refused() {
    let (p, _) = fixture();
    let (_, outside) = fixture();
    assert!(cleanup::plan(
        &p,
        std::slice::from_ref(&outside),
        "x".into(),
        "x".into(),
        &AtomicBool::new(false)
    )
    .is_err());
    assert!(outside.exists());
}
#[test]
fn hardlinks_refused() {
    let (p, f) = fixture();
    fs::hard_link(&f, p.join("alias.bin")).unwrap();
    assert!(cleanup::plan(
        &p,
        std::slice::from_ref(&f),
        "x".into(),
        "x".into(),
        &AtomicBool::new(false)
    )
    .is_err());
    assert!(f.exists());
}
#[test]
fn all_targets_preflight_before_approval() {
    let (p, f) = fixture();
    let second = p.join("second.bin");
    fs::write(&second, b"second").unwrap();
    let plan = cleanup::plan(
        &p,
        &[f.clone(), second.clone()],
        "x".into(),
        "x".into(),
        &AtomicBool::new(false),
    )
    .unwrap();
    fs::write(&second, b"changed").unwrap();
    assert!(cleanup::execute(
        &plan,
        &p.with_extension("receipt.jsonl"),
        &AtomicBool::new(false),
        |_| panic!("partial preflight")
    )
    .is_err());
    assert!(f.exists());
    assert!(second.exists());
}
#[test]
fn cancellation_prevents_approval_and_deletion() {
    let (p, f) = fixture();
    let plan = make(&p, f.clone());
    assert!(cleanup::execute(
        &plan,
        &p.with_extension("receipt.jsonl"),
        &AtomicBool::new(true),
        |_| panic!("cancel ignored")
    )
    .is_err());
    assert!(f.exists());
}
#[test]
fn plan_output_cannot_enter_target_root() {
    let (p, f) = fixture();
    let plan = make(&p, f.clone());
    assert!(cleanup::save(&p.join("plan.json"), &plan).is_err());
    assert!(!p.join("plan.json").exists());
    assert!(f.exists());
}
#[test]
fn plan_output_does_not_overwrite() {
    let (p, f) = fixture();
    let plan = make(&p, f);
    let output = p.with_extension("plan.json");
    cleanup::save(&output, &plan).unwrap();
    let bytes = fs::read(&output).unwrap();
    assert!(cleanup::save(&output, &plan).is_err());
    assert_eq!(bytes, fs::read(&output).unwrap());
}
#[test]
fn persisted_plan_round_trip() {
    let (p, f) = fixture();
    let plan = make(&p, f);
    let output = p.with_extension("plan.json");
    cleanup::save(&output, &plan).unwrap();
    let loaded = cleanup::load(&output).unwrap();
    assert_eq!(loaded.digest, plan.digest);
    assert_eq!(loaded.targets, plan.targets);
}
#[test]
fn piped_confirmation_is_refused() {
    let output = Command::new(env!("CARGO_BIN_EXE_colossus"))
        .args([
            "cleanup",
            "execute",
            "--plan",
            "not-a-plan",
            "--receipt",
            "not-a-receipt",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("interactive terminal"));
}
