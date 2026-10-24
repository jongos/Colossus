#![cfg(windows)]
use colossus_audit::{audit, content, git, model::Report, platform, report, Options};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
#[test]
fn hostile_retention_holds_cannot_control_the_terminal() {
    let p = fixture();
    fs::create_dir(p.join("target")).unwrap();
    put(
        p.join("Cargo.toml"),
        "[package]\nname='demo'\nversion='0.1.0'",
    );
    put(
        p.join("colossus.artifacts.json"),
        r#"{"schema_version":"1.0.0","artifacts":[{"path":"target","retention_holds":["\u001b[2J\r\nFORGED SUCCESS"]}]}"#,
    );
    let r = audit(&options(&p)).unwrap();
    let text = report::human(&r);
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains('\r'));
    assert!(text.contains("FORGED SUCCESS"));
}
#[test]
fn ownership_fanout_has_an_explicit_budget() {
    let p = fixture();
    for i in 0..100 {
        put(p.join(format!("file-{i}")), "a");
    }
    let records: Vec<_> = (0..1000)
        .map(|i| serde_json::json!({"path":".","owner":format!("owner-{i}")}))
        .collect();
    put(
        p.join("colossus.artifacts.json"),
        &serde_json::json!({"schema_version":"1.0.0","artifacts":records}).to_string(),
    );
    let r = audit(&options(&p)).unwrap();
    assert!(!r.complete);
    assert!(r.provenance.ownership.is_empty());
    assert!(r
        .issues
        .iter()
        .any(|i| i.detail.contains("association budget")));
}
#[test]
fn declared_relationship_count_is_bounded() {
    let p = fixture();
    fs::create_dir(p.join("member")).unwrap();
    put(
        p.join("package.json"),
        &serde_json::json!({"workspaces":vec!["member";10020]}).to_string(),
    );
    let r = audit(&options(&p)).unwrap();
    assert!(!r.complete);
    assert!(r.provenance.dependencies.len() < 10000);
    assert!(r.issues.iter().any(|i| i.detail.contains("record budget")));
}
#[test]
fn content_reader_holds_a_write_excluding_handle() {
    let p = fixture();
    put(p.join("file"), "abc");
    let r = audit(&Options::new(vec![p.clone()])).unwrap();
    let a = r.artifacts.iter().find(|a| a.kind == "file").unwrap();
    let calls = AtomicUsize::new(0);
    let mut budget = content::Budget::new(100);
    budget
        .hash(a, 100, &|| {
            if calls.fetch_add(1, Ordering::Relaxed) == 1 {
                assert!(fs::OpenOptions::new()
                    .write(true)
                    .open(p.join("file"))
                    .is_err());
            }
            false
        })
        .unwrap();
    assert_eq!(fs::read(p.join("file")).unwrap(), b"abc");
}
#[test]
fn hash_does_not_read_alternate_streams() {
    let p = fixture();
    put(p.join("file"), "abc");
    put(p.join("file:private"), "opaque alternate stream");
    let mut o = Options::new(vec![p.clone()]);
    o.hash_files.push(p.join("file"));
    let r = audit(&o).unwrap();
    assert_eq!(r.provenance.bytes_read, 3);
    assert_eq!(
        fs::read(p.join("file:private")).unwrap(),
        b"opaque alternate stream"
    );
}
#[test]
fn content_reader_rejects_a_new_junction_in_an_ancestor() {
    let p = fixture();
    fs::create_dir(p.join("dir")).unwrap();
    put(p.join("dir/file"), "abc");
    let r = audit(&Options::new(vec![p.clone()])).unwrap();
    let a = r.artifacts.iter().find(|a| a.kind == "file").unwrap();
    let outside = fixture();
    put(outside.join("file"), "abc");
    fs::rename(p.join("dir"), p.join("old")).unwrap();
    assert!(Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(p.join("dir"))
        .arg(&outside)
        .output()
        .unwrap()
        .status
        .success());
    let mut budget = content::Budget::new(100);
    assert!(budget.hash(a, 100, &|| false).is_err());
    assert_eq!(budget.read, 0);
}
#[test]
fn per_file_hash_cap_is_enforced_even_with_large_total_budget() {
    let p = fixture();
    fs::File::create(p.join("large"))
        .unwrap()
        .set_len(32 * 1024 * 1024 + 1)
        .unwrap();
    let mut o = Options::new(vec![p.clone()]);
    o.hash_files.push(p.join("large"));
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert!(r.provenance.hashes.is_empty());
    assert_eq!(r.provenance.bytes_read, 0);
}
fn fixture() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "colossus-provenance-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&p).unwrap();
    p
}
fn put(p: impl AsRef<Path>, text: &str) {
    fs::write(p, text).unwrap();
}
fn options(root: &Path) -> Options {
    let mut o = Options::new(vec![root.into()]);
    o.provenance = true;
    o
}
fn id(r: &Report, p: &Path) -> String {
    r.artifacts
        .iter()
        .find(|a| Path::new(&a.path) == p)
        .unwrap()
        .id
        .clone()
}
fn git_cmd(p: &Path, args: &[&str]) {
    assert!(Command::new("git")
        .arg("-C")
        .arg(p)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "NUL")
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn manifest_content_is_opt_in() {
    let p = fixture();
    put(p.join("package.json"), "not valid JSON");
    let r = audit(&Options::new(vec![p.clone()])).unwrap();
    assert!(r.complete);
    assert_eq!(r.provenance.bytes_read, 0);
    let r = audit(&options(&p)).unwrap();
    assert!(!r.complete);
    assert!(r.issues.iter().any(|i| i.code == "provenance_gap"));
}
#[test]
fn package_manifest_gives_context_without_executing_scripts() {
    let p = fixture();
    fs::create_dir(p.join("dist")).unwrap();
    put(
        p.join("package.json"),
        r#"{"name":"demo","scripts":{"build":"echo dangerous > marker"}}"#,
    );
    put(p.join("dist/source.js"), "unique source");
    let r = audit(&options(&p)).unwrap();
    assert!(r.complete);
    assert_eq!(
        r.provenance.projects[0].declared_name.as_deref(),
        Some("demo")
    );
    assert!(!p.join("marker").exists());
    let owner = r
        .provenance
        .ownership
        .iter()
        .find(|o| o.artifact_id == id(&r, &p.join("dist")))
        .unwrap();
    assert_eq!(owner.status, "context_only");
    assert!(r
        .candidates
        .iter()
        .all(|c| c.proposed_operation == "investigate"));
    assert!(r.artifacts.iter().all(|a| a.generation_method.is_none()));
    assert_eq!(r.artifacts.len(), r.plan.protected_paths.len());
}
#[test]
fn cargo_and_npm_shared_path_dependencies_propagate_to_contents() {
    let p = fixture();
    for d in ["rust", "web", "shared"] {
        fs::create_dir(p.join(d)).unwrap();
    }
    put(
        p.join("rust/Cargo.toml"),
        "[package]\nname='rust-app'\nversion='0.1.0'\n[dependencies]\nshared={path='../shared'}\n",
    );
    put(
        p.join("web/package.json"),
        r#"{"name":"web","dependencies":{"shared":"file:../shared"}}"#,
    );
    put(p.join("shared/asset"), "only copy");
    let r = audit(&options(&p)).unwrap();
    assert_eq!(r.provenance.dependencies.len(), 2);
    assert!(r
        .provenance
        .dependencies
        .iter()
        .all(|d| d.target_artifact_id.is_some()));
    for path in [p.join("shared"), p.join("shared/asset")] {
        let owner = r
            .provenance
            .ownership
            .iter()
            .find(|o| o.artifact_id == id(&r, &path))
            .unwrap();
        assert_eq!(owner.status, "shared_context");
        assert_eq!(owner.project_ids.len(), 2);
    }
}
#[test]
fn workspaces_preserve_unresolved_globs() {
    let p = fixture();
    fs::create_dir(p.join("member")).unwrap();
    put(
        p.join("Cargo.toml"),
        "[workspace]\nmembers=['member','packages/*']\n",
    );
    let r = audit(&options(&p)).unwrap();
    assert_eq!(r.provenance.dependencies.len(), 2);
    assert!(r.provenance.dependencies[0].target_artifact_id.is_some());
    assert!(r.provenance.dependencies[1].target_artifact_id.is_none());
}
#[test]
fn external_dependencies_do_not_expand_scope() {
    let p = fixture();
    let outside = fixture();
    put(outside.join("private"), "never read");
    let claim = outside.to_string_lossy().replace('\\', "/");
    put(
        p.join("package.json"),
        &format!(r#"{{"dependencies":{{"external":"file:{claim}"}}}}"#),
    );
    let r = audit(&options(&p)).unwrap();
    assert!(r.provenance.dependencies[0].target_artifact_id.is_none());
    assert!(!r.artifacts.iter().any(|a| a.path.ends_with("private")));
}
#[test]
fn forged_approval_is_rejected_as_unknown_registry_field() {
    let p = fixture();
    put(
        p.join("colossus.artifacts.json"),
        r#"{"schema_version":"1.0.0","artifacts":[{"path":"target","owner":"admin","approved":true}]}"#,
    );
    let r = audit(&options(&p)).unwrap();
    assert!(!r.complete);
    assert!(r.provenance.claims.is_empty());
}
#[test]
fn conflicting_registry_claims_and_parent_holds_remain_blockers() {
    let p = fixture();
    fs::create_dir(p.join("target")).unwrap();
    put(
        p.join("Cargo.toml"),
        "[package]\nname='demo'\nversion='0.1.0'",
    );
    put(
        p.join("colossus.artifacts.json"),
        r#"{"schema_version":"1.0.0","artifacts":[{"path":".","owner":"team-a","generation_method":"cargo build","source_revision":"forged","retention_holds":["submitted upload"]},{"path":"target","owner":"team-b"}]}"#,
    );
    let r = audit(&options(&p)).unwrap();
    assert_eq!(r.provenance.claims.len(), 2);
    let c = &r.candidates[0];
    assert!(c.blockers.iter().any(|b| b.contains("conflicting_claims")));
    assert!(c.blockers.iter().any(|b| b.contains("submitted upload")));
    assert!(r
        .artifacts
        .iter()
        .all(|a| a.generation_method.is_none() && a.originating_task.is_none()));
    assert!(c.recovery_method.is_none());
}
#[test]
fn hard_link_aliases_retain_both_project_contexts() {
    let p = fixture();
    for d in ["a", "b"] {
        fs::create_dir(p.join(d)).unwrap();
        put(
            p.join(d).join("package.json"),
            &format!(r#"{{"name":"{d}"}}"#),
        );
    }
    put(p.join("a/asset"), "shared");
    fs::hard_link(p.join("a/asset"), p.join("b/asset")).unwrap();
    let r = audit(&options(&p)).unwrap();
    for path in [p.join("a/asset"), p.join("b/asset")] {
        assert_eq!(
            r.provenance
                .ownership
                .iter()
                .find(|o| o.artifact_id == id(&r, &path))
                .unwrap()
                .status,
            "shared_context"
        );
    }
}
#[test]
fn explicit_hashes_group_equal_content_but_not_aliases() {
    let p = fixture();
    put(p.join("a"), "abc");
    put(p.join("b"), "abc");
    fs::hard_link(p.join("a"), p.join("alias")).unwrap();
    put(p.join("secret"), "not selected");
    let mut o = Options::new(vec![p.clone()]);
    o.hash_files = vec![p.join("a"), p.join("alias"), p.join("b")];
    let r = audit(&o).unwrap();
    assert!(r.complete);
    assert_eq!(r.provenance.hashes.len(), 3);
    assert_eq!(
        r.provenance.hashes[0].sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(r.provenance.bytes_read, 9);
    assert_eq!(r.provenance.duplicate_groups.len(), 1);
    assert_eq!(r.provenance.duplicate_groups[0].len(), 2);
    assert!(r.candidates.is_empty());
}
#[test]
fn hash_scope_and_byte_limit_fail_closed() {
    let p = fixture();
    let outside = fixture();
    put(p.join("file"), "1234");
    put(outside.join("private"), "not authorized");
    let mut o = Options::new(vec![p.clone()]);
    o.hash_files = vec![p.join("file"), outside.join("private")];
    o.max_content_bytes = 3;
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert!(r.provenance.hashes.is_empty());
    assert_eq!(r.provenance.bytes_read, 0);
    assert_eq!(
        r.issues
            .iter()
            .filter(|i| i.code == "provenance_gap")
            .count(),
        2
    );
}
#[test]
fn writer_handle_prevents_content_evidence() {
    use std::os::windows::fs::OpenOptionsExt;
    let p = fixture();
    put(p.join("file"), "abc");
    let _writer = fs::OpenOptions::new()
        .write(true)
        .share_mode(7)
        .open(p.join("file"))
        .unwrap();
    let mut o = Options::new(vec![p.clone()]);
    o.hash_files.push(p.join("file"));
    let r = audit(&o).unwrap();
    assert!(r.provenance.hashes.is_empty());
    assert!(!r.complete);
}
#[test]
fn cancelled_hash_never_returns_a_partial_digest() {
    let p = fixture();
    fs::write(p.join("file"), vec![3u8; 200_000]).unwrap();
    let r = audit(&Options::new(vec![p.clone()])).unwrap();
    let a = r.artifacts.iter().find(|a| a.kind == "file").unwrap();
    let calls = AtomicUsize::new(0);
    let mut budget = content::Budget::new(300_000);
    assert!(budget
        .hash(a, 300_000, &|| calls.fetch_add(1, Ordering::Relaxed) >= 2)
        .is_err());
    assert!(budget.read <= 65536);
    assert!(budget.remaining >= 234464);
}
#[test]
fn changed_content_identity_is_rejected_before_hash() {
    let p = fixture();
    put(p.join("file"), "before");
    let r = audit(&Options::new(vec![p.clone()])).unwrap();
    let a = r.artifacts.iter().find(|a| a.kind == "file").unwrap();
    fs::rename(p.join("file"), p.join("old")).unwrap();
    put(p.join("file"), "before");
    let mut budget = content::Budget::new(100);
    assert!(budget.hash(a, 100, &|| false).is_err());
    assert_eq!(budget.read, 0);
}
#[test]
fn missing_manifest_and_large_metadata_remain_unresolved() {
    let p = fixture();
    fs::write(p.join("package.json"), vec![b' '; 1024 * 1024 + 1]).unwrap();
    let r = audit(&options(&p)).unwrap();
    assert!(!r.complete);
    assert!(r.provenance.projects.is_empty());
    assert_eq!(r.provenance.bytes_read, 0);
}
#[test]
fn git_checksum_corruption_is_not_tracking_evidence() {
    let p = fixture();
    git_cmd(&p, &["init", "-q"]);
    put(p.join("source"), "abc");
    git_cmd(&p, &["add", "source"]);
    let mut index = fs::read(p.join(".git/index")).unwrap();
    assert!(git::parse_index(&index).is_ok());
    index[12] ^= 1;
    assert!(git::parse_index(&index).unwrap_err().contains("checksum"));
    fs::write(p.join(".git/index"), index).unwrap();
    let r = audit(&Options::new(vec![p])).unwrap();
    assert!(r.repositories[0].index_checksum.is_none());
    assert!(r.repositories[0].index_entries.is_none());
}
#[test]
fn relative_gitdir_and_commondir_resolve_only_in_inventory() {
    let p = fixture();
    fs::create_dir(p.join("repo")).unwrap();
    fs::create_dir(p.join("linked")).unwrap();
    let repo = p.join("repo");
    git_cmd(&repo, &["init", "-q"]);
    put(repo.join("source"), "abc");
    git_cmd(&repo, &["add", "source"]);
    fs::create_dir_all(repo.join(".git/worktrees/linked")).unwrap();
    fs::copy(
        repo.join(".git/index"),
        repo.join(".git/worktrees/linked/index"),
    )
    .unwrap();
    put(
        repo.join(".git/worktrees/linked/HEAD"),
        "ref: refs/heads/main",
    );
    put(repo.join(".git/worktrees/linked/commondir"), "../..");
    put(
        p.join("linked/.git"),
        "gitdir: ../repo/.git/worktrees/linked",
    );
    let r = audit(&Options::new(vec![p.clone()])).unwrap();
    let linked = r
        .repositories
        .iter()
        .find(|x| x.kind == "linked_worktree_or_submodule")
        .unwrap();
    assert!(linked.resolved_gitdir.is_some());
    assert_eq!(
        linked.resolved_common_dir.as_deref(),
        repo.join(".git").to_str()
    );
    let r = audit(&Options::new(vec![p.join("linked")])).unwrap();
    assert!(r.repositories[0].resolved_gitdir.is_none());
}
#[test]
fn junction_cannot_redirect_dependency_or_content_reads() {
    let p = fixture();
    let outside = fixture();
    put(outside.join("private"), "outside");
    assert!(Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(p.join("link"))
        .arg(&outside)
        .output()
        .unwrap()
        .status
        .success());
    put(
        p.join("package.json"),
        r#"{"dependencies":{"x":"file:link","y":"file:link/../package.json"}}"#,
    );
    let mut o = options(&p);
    o.hash_files.push(p.join("link/private"));
    let r = audit(&o).unwrap();
    assert!(r
        .provenance
        .dependencies
        .iter()
        .all(|d| d.target_artifact_id.is_none()));
    assert!(r.provenance.hashes.is_empty());
}
#[test]
fn windows_special_names_are_rejected_before_output_creation() {
    let p = fixture();
    let r = audit(&Options::new(vec![p.clone()])).unwrap();
    let output = fixture();
    for name in [
        "CON",
        "nul.txt",
        "COM1",
        "LPT9.log",
        "COM¹",
        "file:stream",
        "report.",
        "report ",
    ] {
        assert!(report::write_new(&output.join(name), b"x", &r).is_err());
    }
}
#[test]
fn unc_device_and_drive_relative_roots_are_rejected() {
    for path in [
        r"\\server\share\root",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1",
        r"C:relative",
    ] {
        assert!(platform::pin(Path::new(path)).is_err());
    }
}
#[test]
fn output_junction_and_case_alias_cannot_write_into_source() {
    let p = fixture();
    let out = fixture();
    let r = audit(&Options::new(vec![p.clone()])).unwrap();
    assert!(Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(out.join("link"))
        .arg(&p)
        .output()
        .unwrap()
        .status
        .success());
    assert!(report::write_new(&out.join("link/report.json"), b"x", &r).is_err());
    assert!(report::write_new(
        &PathBuf::from(p.to_string_lossy().to_uppercase()).join("report.json"),
        b"x",
        &r
    )
    .is_err());
}
#[test]
fn registry_path_resolution_does_not_open_uninventoried_paths() {
    let p = fixture();
    put(p.join("file"), "abc");
    let r = audit(&Options::new(vec![p.clone()])).unwrap();
    let map: BTreeMap<_, _> = r
        .artifacts
        .iter()
        .map(|a| (PathBuf::from(&a.path), a.clone()))
        .collect();
    for claim in ["absent/../file", "file:stream", "../outside", "file/child"] {
        assert!(content::resolve(&p, claim, &map).is_err());
    }
}
