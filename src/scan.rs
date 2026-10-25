use crate::{git, model::*, platform, provenance};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub struct Options {
    pub roots: Vec<PathBuf>,
    pub cancel: Arc<AtomicBool>,
    pub max_entries: usize,
    pub max_depth: usize,
    pub deadline_ms: Option<u64>,
    pub progress: bool,
    pub provenance: bool,
    pub hash_files: Vec<PathBuf>,
    pub statement_files: Vec<PathBuf>,
    pub trusted_keys: Vec<TrustedKey>,
    pub cargo_lockfiles: Vec<CargoLockfileSelection>,
    pub max_content_bytes: u64,
}
impl Options {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            cancel: Arc::new(AtomicBool::new(false)),
            max_entries: 1_000_000,
            max_depth: 128,
            deadline_ms: None,
            progress: false,
            provenance: false,
            hash_files: vec![],
            statement_files: vec![],
            trusted_keys: vec![],
            cargo_lockfiles: vec![],
            max_content_bytes: 64 * 1024 * 1024,
        }
    }
}
struct Scanner<'a> {
    options: &'a Options,
    report: Report,
    seen: BTreeSet<String>,
    start: Instant,
    bounded: bool,
}
impl Scanner<'_> {
    fn issue(&mut self, path: &Path, code: &str, detail: impl ToString) {
        self.report.issues.push(Issue {
            path: path.to_string_lossy().into_owned(),
            code: code.into(),
            detail: detail.to_string(),
        });
        self.report.complete = false;
    }
    fn stopped(&mut self) -> bool {
        if self.options.cancel.load(Ordering::Relaxed)
            || self
                .options
                .deadline_ms
                .is_some_and(|m| self.start.elapsed() >= Duration::from_millis(m))
        {
            self.report.cancelled = true;
            self.report.complete = false;
            return true;
        }
        if self.report.artifacts.len() >= self.options.max_entries {
            if !self.bounded {
                self.issue(Path::new(""), "entry_limit", "maximum entry count reached");
                self.bounded = true;
            }
            return true;
        }
        false
    }
    fn visit(&mut self, path: &Path, volume: u64, owner: Option<String>, depth: usize) {
        if self.stopped() {
            return;
        }
        if depth > self.options.max_depth {
            self.issue(path, "depth_limit", "maximum traversal depth reached");
            return;
        }
        let file = match platform::open(path, false) {
            Ok(f) => f,
            Err(e) => {
                self.issue(path, "inaccessible", e);
                return;
            }
        };
        let before = match platform::stat(&file) {
            Ok(s) => s,
            Err(e) => {
                self.issue(path, "metadata_unavailable", e);
                return;
            }
        };
        if before.volume != volume {
            self.issue(
                path,
                "filesystem_boundary",
                "different volume; not traversed",
            );
            return;
        }
        let path_text = match path.to_str() {
            Some(s) => s.to_owned(),
            None => {
                self.issue(
                    path,
                    "unrepresentable_path",
                    "non-Unicode path; exact JSON representation unavailable",
                );
                return;
            }
        };
        let is_new = self.seen.insert(before.identity.clone());
        let id = format!("a{}", self.report.artifacts.len());
        self.report.artifacts.push(Artifact {
            id: id.clone(),
            path: path_text.clone(),
            identity: before.identity.clone(),
            kind: if before.reparse {
                "reparse"
            } else if before.directory {
                "directory"
            } else {
                "file"
            }
            .into(),
            project_owner: owner.clone(),
            logical_bytes: if before.directory || before.reparse {
                0
            } else {
                before.logical
            },
            allocated_bytes: if before.directory || before.reparse {
                None
            } else {
                before.allocated
            },
            modified_filetime: before.modified,
            hard_links: before.links,
            counted: is_new && !before.directory && !before.reparse,
            originating_task: None,
            generation_method: None,
            dependencies: None,
            retention_holds: vec!["ownership, dependency and recovery review required".into()],
        });
        if self.options.progress && self.report.artifacts.len().is_multiple_of(1000) {
            eprintln!(
                "colossus: {} entries inspected",
                self.report.artifacts.len()
            );
        }
        if before.reparse {
            self.issue(
                path,
                "reparse_skipped",
                "link/junction/reparse point; target was not inspected",
            );
            return;
        }
        if !is_new {
            if before.directory {
                self.issue(
                    path,
                    "duplicate_directory",
                    "already inspected filesystem identity",
                );
            }
            return;
        }
        if !before.directory {
            return;
        }
        let mut children = Vec::new();
        match fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries {
                    if self.stopped() {
                        return;
                    }
                    match entry {
                        Ok(e) => children.push(e.path()),
                        Err(e) => self.issue(path, "directory_entry_error", e),
                    }
                    if children.len()
                        > self
                            .options
                            .max_entries
                            .saturating_sub(self.report.artifacts.len())
                    {
                        self.issue(
                            path,
                            "directory_width_limit",
                            "directory exceeds remaining entry budget; partial sorted listing only",
                        );
                        break;
                    }
                }
            }
            Err(e) => {
                self.issue(path, "inaccessible", e);
                return;
            }
        }
        children.sort();
        let repo = children
            .iter()
            .any(|p| p.file_name().is_some_and(|s| s == ".git"));
        let owner = if repo { Some(path_text) } else { owner };
        self.report.artifacts.last_mut().unwrap().project_owner = owner.clone();
        for child in children {
            self.visit(&child, volume, owner.clone(), depth + 1);
            if self.stopped() {
                break;
            }
        }
        match platform::stat(&file) {
            Ok(after) if after == before => {}
            Ok(_) => self.issue(
                path,
                "changed_during_scan",
                "directory metadata changed; snapshot is incomplete",
            ),
            Err(e) => self.issue(path, "revalidation_failed", e),
        }
    }
}

pub fn audit(options: &Options) -> Result<Report, String> {
    audit_observed(options, |_| {})
}
fn audit_observed(
    options: &Options,
    after_inventory: impl FnOnce(&Report),
) -> Result<Report, String> {
    if !cfg!(windows) {
        return Err(
            "Phase 1 supports local Windows filesystems only; this platform is unsupported".into(),
        );
    }
    if options.roots.is_empty() || options.max_entries == 0 || options.max_depth > 256 {
        return Err("supply at least one root, a positive entry budget and depth <= 256".into());
    }
    crate::authentication::validate_keys(&options.trusted_keys)?;
    crate::lockfiles::validate_selections(&options.cargo_lockfiles, options.provenance)?;
    if !options.trusted_keys.is_empty() && options.statement_files.is_empty() {
        return Err("trusted keys require explicitly selected statement files".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let roots: Vec<_> = options
        .roots
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let mut s = Scanner { options, seen: BTreeSet::new(), start: Instant::now(), bounded: false, report: Report {
        schema_version:"1.7.0".into(),tool_version:env!("CARGO_PKG_VERSION").into(),timestamp_unix:now,
        complete:true,cancelled:false,inventory_coverage:"metadata only".into(),roots:roots.clone(),root_identities:vec![],artifacts:vec![],evidence:vec![],candidates:vec![],repositories:vec![],issues:vec![],
        totals:Totals{logical_bytes:0,allocated_known_bytes:0,allocated_unknown_files:0,unique_files:0,hard_link_aliases:0},
        provenance:Provenance::default(),
        plan:Plan{schema_version:"1.7.0".into(),roots,candidate_scope:vec![],protected_paths:vec![],required_approval:"No executable operations. A future exact manifest requires separate approval.".into(),manifest_digest:String::new()},
        limitations: vec!["Windows local drives only; network shares, alternate data streams and directory allocation are excluded.".into(),
            "Not an atomic filesystem snapshot. Concurrent same-size writes with preserved timestamps can escape detection.".into(),
            "Open handles temporarily deny rename/deletion; scans can fail when other handles deny sharing.".into(),
            "No process-reference, exclusive ownership, executed-build provenance or recovery verification. Optional declarations and hashes remain evidence only.".into(),
            "File reads may affect access timestamps through OS policy; no source content, last-write time, Git or configuration writes are requested.".into(),
            "Allocated sizes are filesystem-reported per-file allocation, not promised reclaimable space; deduplication/compression/shared extents can differ.".into(),
            "Concurrency is bounded to one worker. Cancellation is checked between operations; a blocked filesystem call cannot be interrupted.".into()] } };
    s.report.provenance.trusted_keys = options.trusted_keys.clone();
    s.report.provenance.cargo_lockfiles = options.cargo_lockfiles.clone();
    // Pin every accepted root for the entire audit, including bounded Git reads.
    let mut pinned = Vec::new();
    let mut root_ids = BTreeSet::new();
    for root in &options.roots {
        match platform::pin(root) {
            Ok(p) if p.stat.directory => {
                if root_ids.insert(p.stat.identity.clone()) {
                    pinned.push(p);
                } else {
                    s.issue(
                        root,
                        "duplicate_root",
                        "duplicate root identity; scanned once",
                    );
                }
            }
            Ok(_) => s.issue(root, "invalid_root", "root must be a directory"),
            Err(e) => s.issue(root, "invalid_root", e),
        }
    }
    pinned.sort_by(|a, b| a.path.cmp(&b.path));
    s.report.root_identities = pinned.iter().map(|p| p.stat.identity.clone()).collect();
    for root in &pinned {
        s.visit(&root.path, root.stat.volume, None, 0);
    }
    if s.report.cancelled {
        s.issue(
            Path::new(""),
            "cancelled",
            "audit interrupted; results are partial",
        );
    }
    after_inventory(&s.report);
    let start = s.start;
    if !s.report.cancelled {
        git::collect(&mut s.report, &|| {
            options.cancel.load(Ordering::Relaxed)
                || options
                    .deadline_ms
                    .is_some_and(|m| start.elapsed() >= Duration::from_millis(m))
        });
    }
    if options.provenance || !options.hash_files.is_empty() || !options.statement_files.is_empty() {
        s.report.inventory_coverage =
            "metadata plus explicitly requested bounded content evidence".into();
        provenance::collect(
            &mut s.report,
            options.provenance,
            &options.hash_files,
            &options.statement_files,
            options.max_content_bytes,
            &|| {
                options.cancel.load(Ordering::Relaxed)
                    || options
                        .deadline_ms
                        .is_some_and(|m| start.elapsed() >= Duration::from_millis(m))
            },
        );
    }
    // Revalidate inventoried entries after evidence collection. Pinning each chain prevents
    // a renamed ancestor or inserted junction from redirecting this read outside scope.
    for index in 0..s.report.artifacts.len() {
        if options.cancel.load(Ordering::Relaxed)
            || options
                .deadline_ms
                .is_some_and(|m| s.start.elapsed() >= Duration::from_millis(m))
        {
            s.report.cancelled = true;
            s.report.complete = false;
            break;
        }
        let a = &s.report.artifacts[index];
        if a.kind == "reparse" {
            continue;
        }
        let path = PathBuf::from(&a.path);
        let result = platform::pin(&path);
        match result {
            Ok(p)
                if p.stat.identity == a.identity
                    && p.stat.modified == a.modified_filetime
                    && (a.kind != "file" || p.stat.logical == a.logical_bytes) => {}
            Ok(_) => s.issue(
                &path,
                "changed_during_scan",
                "identity, size or last-write time changed; totals are observed partial values",
            ),
            Err(e) => s.issue(&path, "revalidation_failed", e),
        }
    }
    if options.cancel.load(Ordering::Relaxed) {
        s.report.cancelled = true;
        s.report.complete = false;
    }
    if s.report.cancelled && !s.report.issues.iter().any(|i| i.code == "cancelled") {
        s.issue(
            Path::new(""),
            "cancelled",
            "audit interrupted during evidence/revalidation; partial report",
        );
    }
    classify(&mut s.report);
    provenance::attach_candidates(&mut s.report);
    for a in &s.report.artifacts {
        if a.kind == "file" {
            if a.counted {
                s.report.totals.unique_files += 1;
                s.report.totals.logical_bytes = s
                    .report
                    .totals
                    .logical_bytes
                    .saturating_add(a.logical_bytes);
                match a.allocated_bytes {
                    Some(b) => {
                        s.report.totals.allocated_known_bytes =
                            s.report.totals.allocated_known_bytes.saturating_add(b)
                    }
                    None => s.report.totals.allocated_unknown_files += 1,
                }
            } else {
                s.report.totals.hard_link_aliases += 1;
            }
        }
    }
    crate::report::seal(&mut s.report)?;
    Ok(s.report)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn mutation_during_audit_is_reported() {
        let p = std::env::temp_dir().join(format!("colossus-mutation-{}", std::process::id()));
        fs::create_dir(&p).unwrap();
        fs::write(p.join("file"), b"before").unwrap();
        let r = audit_observed(&Options::new(vec![p.clone()]), |_| {
            fs::write(p.join("file"), b"changed during audit").unwrap()
        })
        .unwrap();
        assert!(!r.complete);
        assert!(r.issues.iter().any(|i| i.code == "changed_during_scan"));
    }
    #[test]
    fn filesystem_identity_mismatch_stops_before_descending() {
        let p = std::env::temp_dir().join(format!("colossus-volume-{}", std::process::id()));
        fs::create_dir(&p).unwrap();
        fs::write(p.join("unvisited"), b"fixture").unwrap();
        let options = Options::new(vec![p.clone()]);
        let mut report = audit(&options).unwrap();
        report.artifacts.clear();
        let pin = platform::pin(&p).unwrap();
        let mut scanner = Scanner {
            options: &options,
            report,
            seen: BTreeSet::new(),
            start: Instant::now(),
            bounded: false,
        };
        scanner.visit(&p, pin.stat.volume ^ 1, None, 0);
        assert!(scanner.report.artifacts.is_empty());
        assert!(scanner
            .report
            .issues
            .iter()
            .any(|i| i.code == "filesystem_boundary"));
    }
}

fn classify(r: &mut Report) {
    let paths: BTreeMap<_, _> = r
        .artifacts
        .iter()
        .map(|a| (PathBuf::from(&a.path), a))
        .collect();
    for a in &r.artifacts {
        let p = Path::new(&a.path);
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let manifest = p.parent().and_then(|parent| {
            ["Cargo.toml", "package.json", "CMakeLists.txt"]
                .iter()
                .find_map(|n| {
                    let path = parent.join(n);
                    paths.get(&path).filter(|a| a.kind == "file").map(|_| path)
                })
        });
        if let Some(manifest) = manifest.filter(|_| {
            a.kind == "directory"
                && matches!(name, "target" | "dist" | "build")
                && !p.components().any(|c| c.as_os_str() == ".git")
        }) {
            let eid = format!("e{}", r.evidence.len());
            r.evidence.push(Evidence{id:eid.clone(),artifact_id:a.id.clone(),observation:format!("Directory named {name}; sibling manifest exists at {}",manifest.display()),
                source:"filesystem metadata".into(),timestamp_unix:r.timestamp_unix,collector_version:env!("CARGO_PKG_VERSION").into(),
                limitations:vec!["Name and manifest presence do not establish generated contents, ownership or disposability.".into()]});
            r.candidates.push(Candidate {
                artifact_id: a.id.clone(),
                classification: "review_needed".into(),
                proposed_operation: "investigate".into(),
                evidence_ids: vec![eid],
                blockers: vec![
                    "contents may include source or unique assets".into(),
                    "active dependencies and retention holds unresolved".into(),
                    "recovery and generation method unverified".into(),
                    if r.complete {
                        "read-only observations do not authorize mutation".into()
                    } else {
                        "incomplete inspection".into()
                    },
                ],
                recovery_method: None,
                reconstruction_cost: None,
            });
            r.plan.candidate_scope.push(a.path.clone());
        }
        // Review candidates remain protected from mutation too.
        r.plan.protected_paths.push(a.path.clone());
    }
}
