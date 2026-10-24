use crate::{model::Report, platform};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

/// Digest binds the entire evidence report (excluding its own digest), not approval.
pub fn seal(report: &mut Report) -> Result<(), String> {
    report.plan.manifest_digest.clear();
    let data = serde_json::to_vec(report).map_err(|e| e.to_string())?;
    report.plan.manifest_digest = format!("sha256:{:x}", Sha256::digest(data));
    Ok(())
}
pub fn human(r: &Report) -> String {
    let mut s=format!("Colossus {} — read-only audit\nCoverage: {}{}\nRoots: {}\nFiles: {} unique; {} hard-link aliases\nLogical bytes: {}\nKnown allocated bytes: {}; unknown files: {}\nRepositories: {}\nReview candidates: {}; eligible for deletion: 0\nIssues: {}\nManifest: {}\n",
        r.tool_version,if r.complete{"complete within stated limits"}else{"INCOMPLETE"},if r.cancelled{" (cancelled)"}else{""},r.roots.len(),r.totals.unique_files,r.totals.hard_link_aliases,r.totals.logical_bytes,
        r.totals.allocated_known_bytes,r.totals.allocated_unknown_files,r.repositories.len(),r.candidates.len(),r.issues.len(),r.plan.manifest_digest);
    for c in &r.candidates {
        let path = r
            .artifacts
            .iter()
            .find(|a| a.id == c.artifact_id)
            .map(|a| a.path.as_str())
            .unwrap_or("unknown");
        s.push_str(&format!("\nREVIEW {:?}\n", path));
        for id in &c.evidence_ids {
            if let Some(e) = r.evidence.iter().find(|e| &e.id == id) {
                s.push_str(&format!("  Evidence {id}: {:?}\n", e.observation));
            }
        }
        for b in &c.blockers {
            s.push_str(&format!("  Blocker: {b:?}\n"));
        }
    }
    s.push_str(&format!("\nProvenance: {}; content bytes read: {}\nProjects: {}; local/workspace declarations: {}; artifact claims: {}\nSelected-file hashes: {}; equal-hash groups: {} (not cleanup authority)\n",
        if r.provenance.enabled {"opt-in declarations"}else{"manifest collection disabled"},r.provenance.bytes_read,r.provenance.projects.len(),r.provenance.dependencies.len(),r.provenance.claims.len(),r.provenance.hashes.len(),r.provenance.duplicate_groups.len()));
    for owner in r
        .provenance
        .ownership
        .iter()
        .filter(|o| matches!(o.status.as_str(), "shared_context" | "conflicting_claims"))
    {
        s.push_str(&format!(
            "Ownership {:?}: {}; projects {:?}; claims {:?}; evidence {:?}\n",
            owner.artifact_id,
            owner.status,
            owner.project_ids,
            owner.declared_owners,
            owner.evidence_ids
        ));
    }
    for dep in &r.provenance.dependencies {
        s.push_str(&format!(
            "Dependency {:?} -> {:?}: {:?}; evidence {}\n",
            dep.project_id, dep.declared_path, dep.resolution, dep.evidence_id
        ));
    }
    for hash in &r.provenance.hashes {
        s.push_str(&format!(
            "Hash {}: {}; {} bytes; evidence {}\n",
            hash.artifact_id, hash.sha256, hash.bytes, hash.evidence_id
        ));
    }
    for check in &r.provenance.checks {
        s.push_str(&format!(
            "Check {} for {}: {}; observed {:?}; supporting {:?}; {:?}\n",
            check.kind,
            check.subject_evidence_id,
            check.status,
            check.observed_value,
            check.supporting_evidence_ids,
            check.detail
        ));
    }
    s.push_str(&format!(
        "Evidence-source fingerprints: {} (not authentication)\n",
        r.provenance.source_hashes.len()
    ));
    for limitation in &r.provenance.limitations {
        s.push_str(&format!("- {limitation}\n"));
    }
    for i in &r.issues {
        s.push_str(&format!("\n{} {:?}: {:?}\n", i.code, i.path, i.detail));
    }
    for repo in &r.repositories {
        s.push_str(&format!(
            "\nGit {:?}: {}; possibly modified {}; untracked/ignored {}\n",
            repo.path,
            repo.kind,
            repo.possibly_modified.len(),
            repo.untracked.len()
        ));
        for l in &repo.limitations {
            s.push_str(&format!("  {l}\n"));
        }
    }
    s.push_str("\nLimitations:\n");
    for l in &r.limitations {
        s.push_str(&format!("- {l}\n"));
    }
    s
}
pub fn write_new(path: &Path, data: &[u8], report: &Report) -> io::Result<()> {
    platform::validate_components(path)?;
    let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing or unsupported output filename",
        )
    })?;
    if name.contains(':') || name.ends_with('.') || name.ends_with(' ') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "alternate streams and ambiguous Windows filenames are not supported",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "output needs an absolute existing parent",
        )
    })?;
    let pin = platform::pin(parent)?;
    if !pin.stat.directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output parent is not a directory",
        ));
    }
    // Identity-based ancestor comparison blocks aliases and case variants as well as lexical nesting.
    let mut root_ids: Vec<_> = report
        .artifacts
        .iter()
        .filter(|a| a.kind == "directory")
        .map(|a| a.identity.clone())
        .collect();
    root_ids.extend(report.root_identities.iter().cloned());
    for h in &pin.handles {
        if root_ids.contains(&platform::stat(h)?.identity) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "report output must be outside scanned roots",
            ));
        }
    }
    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing output filename",
        ));
    }
    // create_new refuses an existing file, hard link, or reparse point. Never truncate.
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    write_checked(&mut file, data)
}
pub fn write_checked(writer: &mut impl Write, data: &[u8]) -> io::Result<()> {
    writer.write_all(data)?;
    writer.flush()
}
