#![cfg(windows)]
//! Run ONLY after the human approves the exact external synthetic plan and digest.
//! No fixture creation, replacement, cleanup, or automatic approval is performed by default.
use colossus_audit::cleanup;
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};
#[test]
#[ignore = "requires explicit human approval of the exact pre-created synthetic plan and digest"]
fn human_approved_synthetic_reclamation() {
    let plan_path = PathBuf::from(
        std::env::var("COLOSSUS_TEST_APPROVED_PLAN").expect("human-approved plan required"),
    );
    let digest = std::env::var("COLOSSUS_TEST_APPROVED_DIGEST")
        .expect("exact human-approved digest required");
    let receipt = PathBuf::from(
        std::env::var("COLOSSUS_TEST_RECEIPT").expect("new external receipt path required"),
    );
    let p = cleanup::load(&plan_path).unwrap();
    assert_eq!(p.digest, digest);
    assert_eq!(p.targets.len(), 2);
    assert!(p.root.contains("colossus-approved-synthetic"));
    let names: Vec<_> = p
        .targets
        .iter()
        .map(|t| {
            std::path::Path::new(&t.path)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
        })
        .collect();
    assert_eq!(names, vec!["delete-a.bin", "delete-b.bin"]);
    let preserved = PathBuf::from(&p.root).join("preserve.bin");
    let bytes = fs::read(&preserved).unwrap();
    let modified = fs::metadata(&preserved).unwrap().modified().unwrap();
    let ok = cleanup::execute(&p, &receipt, &AtomicBool::new(false), |displayed| {
        assert_eq!(displayed.digest, digest);
        Ok(true)
    })
    .unwrap();
    assert!(ok);
    assert!(p
        .targets
        .iter()
        .all(|t| !std::path::Path::new(&t.path).exists()));
    assert_eq!(bytes, fs::read(&preserved).unwrap());
    assert_eq!(
        modified,
        fs::metadata(&preserved).unwrap().modified().unwrap()
    );
    let rows: Vec<serde_json::Value> = fs::read_to_string(&receipt)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.iter().filter(|r| r["event"] == "removed").count(), 2);
    let end = rows.last().unwrap();
    assert_eq!(end["complete"], true);
    assert_eq!(end["removed_files"], 2);
    assert!(end["free_bytes_after"].is_u64());
    assert!(end["causal_reclaimed_bytes"].is_null());
    assert!(cleanup::execute(
        &p,
        &receipt.with_extension("retry.jsonl"),
        &AtomicBool::new(false),
        |_| panic!("stale plan must not request approval")
    )
    .is_err());
}
