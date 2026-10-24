//! Claims and observed relationships are evidence, never deletion authority.
use crate::{
    content::{self, Budget},
    model::*,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
const MANIFEST_LIMIT: u64 = 1024 * 1024;
const MAX_RECORDS: usize = 10_000;
const MAX_ASSOCIATIONS: usize = 100_000;
type Associations = (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>);
fn records_full(r: &Report) -> bool {
    r.provenance.projects.len() + r.provenance.dependencies.len() + r.provenance.claims.len()
        >= MAX_RECORDS
}
fn association_cost(entry: &Associations) -> (usize, usize) {
    (
        entry.0.len() + entry.1.len() + entry.2.len(),
        entry
            .0
            .iter()
            .chain(&entry.1)
            .chain(&entry.2)
            .map(String::len)
            .sum(),
    )
}
fn charge(entry: &Associations, links: &mut usize, bytes: &mut usize) -> Result<(), String> {
    let (n, b) = association_cost(entry);
    if n > *links || b > *bytes {
        return Err("ownership association budget exceeded; ownership remains unresolved".into());
    }
    *links -= n;
    *bytes -= b;
    Ok(())
}

pub(crate) fn evidence(
    r: &mut Report,
    a: &Artifact,
    observation: String,
    limitations: &[&str],
) -> String {
    let id = format!("e{}", r.evidence.len());
    r.evidence.push(Evidence {
        id: id.clone(),
        artifact_id: a.id.clone(),
        observation,
        source: a.path.clone(),
        timestamp_unix: r.timestamp_unix,
        collector_version: env!("CARGO_PKG_VERSION").into(),
        limitations: limitations.iter().map(|s| s.to_string()).collect(),
    });
    id
}
pub(crate) fn gap(r: &mut Report, path: &str, detail: String) {
    r.complete = false;
    r.issues.push(Issue {
        path: path.into(),
        code: "provenance_gap".into(),
        detail,
    });
}
fn bounded_name(s: Option<&str>) -> Option<String> {
    s.filter(|s| s.len() <= 1024).map(str::to_owned)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema_version: String,
    artifacts: Vec<Record>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    path: String,
    owner: Option<String>,
    generation_method: Option<String>,
    source_revision: Option<String>,
    #[serde(default)]
    retention_holds: Vec<String>,
}

pub fn collect(
    r: &mut Report,
    enabled: bool,
    hash_paths: &[PathBuf],
    statement_paths: &[PathBuf],
    max_bytes: u64,
    stop: &dyn Fn() -> bool,
) {
    r.provenance.enabled = enabled;
    r.provenance.limitations=vec!["Manifest and registry declarations are untrusted; no build, process use, exclusive ownership or recovery is verified.".into(),
        "Only Cargo/npm direct path declarations and literal workspace members are extracted; conditional, inherited, patched, remote and glob relationships are incomplete.".into(),
        "Hashes cover explicitly selected regular files only. Matching digests do not establish that either copy is unnecessary.".into()];
    let artifacts: BTreeMap<_, _> = r
        .artifacts
        .iter()
        .map(|a| (PathBuf::from(&a.path), a.clone()))
        .collect();
    let mut budget = Budget::new(max_bytes);
    if enabled {
        for (path, a) in &artifacts {
            if records_full(r) || r.provenance.source_hashes.len() >= MAX_RECORDS {
                gap(
                    r,
                    "",
                    "provenance record or source fingerprint budget reached".into(),
                );
                break;
            }
            if stop() {
                r.cancelled = true;
                r.complete = false;
                break;
            }
            if a.kind != "file" || path.components().any(|p| p.as_os_str() == ".git") {
                continue;
            }
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !matches!(
                name,
                "Cargo.toml" | "package.json" | "colossus.artifacts.json"
            ) {
                continue;
            }
            let bytes = match budget.read(a, MANIFEST_LIMIT, stop) {
                Ok(b) => b,
                Err(e) => {
                    gap(r, &a.path, e);
                    continue;
                }
            };
            fingerprint(r, a, &bytes);
            if name == "colossus.artifacts.json" {
                match registry(r, a, &bytes, &artifacts, stop) {
                    Ok(()) => {}
                    Err(e) => gap(r, &a.path, e),
                };
                continue;
            }
            let value: Result<Value, String> = if name == "Cargo.toml" {
                std::str::from_utf8(&bytes)
                    .map_err(|_| "manifest is not UTF-8".into())
                    .and_then(|s| {
                        s.parse::<toml::Value>()
                            .map_err(|_| "malformed TOML manifest".into())
                    })
                    .and_then(|v| {
                        serde_json::to_value(v).map_err(|_| "unsupported TOML value".into())
                    })
            } else {
                serde_json::from_slice(&bytes).map_err(|_| "malformed JSON manifest".into())
            };
            let value = match value {
                Ok(v) if v.is_object() => v,
                _ => {
                    gap(r, &a.path, "manifest must be a valid object/table".into());
                    continue;
                }
            };
            let root = path.parent().unwrap();
            let ecosystem = if name == "Cargo.toml" { "cargo" } else { "npm" };
            let declared_name = if ecosystem == "cargo" {
                bounded_name(value.pointer("/package/name").and_then(Value::as_str))
            } else {
                bounded_name(value.get("name").and_then(Value::as_str))
            };
            let eid=evidence(r,a,format!("Parsed {ecosystem} manifest; declared project name {declared_name:?}"),&["Manifest association is contextual evidence, not exclusive ownership or build provenance."]);
            let pid = format!("p{}", r.provenance.projects.len());
            r.provenance.projects.push(Project {
                id: pid.clone(),
                root: root.to_string_lossy().into_owned(),
                manifest_artifact_id: a.id.clone(),
                ecosystem: ecosystem.into(),
                declared_version: bounded_name(if ecosystem == "cargo" {
                    value.pointer("/package/version").and_then(Value::as_str)
                } else {
                    value.get("version").and_then(Value::as_str)
                }),
                declared_name,
                evidence_id: eid,
            });
            let sections = if ecosystem == "cargo" {
                vec!["dependencies", "dev-dependencies", "build-dependencies"]
            } else {
                vec![
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                ]
            };
            for section in sections {
                if let Some(deps) = value.get(section).and_then(Value::as_object) {
                    for (dep_name, spec) in deps {
                        if records_full(r) {
                            gap(r, &a.path, "provenance record budget reached".into());
                            break;
                        }
                        if stop() {
                            r.cancelled = true;
                            r.complete = false;
                            break;
                        }
                        let claim = if ecosystem == "cargo" {
                            spec.get("path").and_then(Value::as_str)
                        } else {
                            spec.as_str().and_then(|s| s.strip_prefix("file:"))
                        };
                        if let Some(claim) = claim {
                            dependency(r, &pid, a, root, claim, "local_dependency", &artifacts);
                            if ecosystem == "cargo" {
                                let dep = r.provenance.dependencies.last_mut().unwrap();
                                dep.declared_package =
                                    bounded_name(if spec.get("package").is_some() {
                                        spec.get("package").and_then(Value::as_str)
                                    } else {
                                        Some(dep_name.as_str())
                                    });
                                dep.declared_version_requirement =
                                    bounded_name(spec.get("version").and_then(Value::as_str));
                            }
                        }
                    }
                }
            }
            let members = if ecosystem == "cargo" {
                value.pointer("/workspace/members")
            } else {
                value.get("workspaces").and_then(|v| {
                    if v.is_array() {
                        Some(v)
                    } else {
                        v.get("packages")
                    }
                })
            };
            if let Some(members) = members.and_then(Value::as_array) {
                for claim in members {
                    if records_full(r) {
                        gap(r, &a.path, "provenance record budget reached".into());
                        break;
                    }
                    if stop() {
                        r.cancelled = true;
                        r.complete = false;
                        break;
                    }
                    if let Some(claim) = claim.as_str() {
                        dependency(r, &pid, a, root, claim, "workspace_member", &artifacts);
                    }
                }
            }
        }
    }
    let mut selected = BTreeSet::new();
    for path in hash_paths {
        if stop() {
            r.cancelled = true;
            r.complete = false;
            break;
        }
        if !selected.insert(path.clone()) {
            continue;
        }
        let a = match artifacts.get(path) {
            Some(a) => a,
            None => {
                gap(
                    r,
                    &path.to_string_lossy(),
                    "hash selection is not an exact inventoried path".into(),
                );
                continue;
            }
        };
        match budget.hash(a, 32 * 1024 * 1024, stop) {
            Ok(hash) => {
                let eid=evidence(r,a,format!("SHA-256 {hash}; {} bytes read",a.logical_bytes),&["Content equality does not establish disposability; point-in-time observation only."]);
                r.provenance.hashes.push(ContentHash {
                    artifact_id: a.id.clone(),
                    sha256: hash,
                    bytes: a.logical_bytes,
                    evidence_id: eid,
                });
            }
            Err(e) => gap(r, &a.path, e),
        }
    }
    if enabled {
        crate::corroboration::collect(r, &artifacts, &mut budget, stop);
        crate::lockfiles::collect(r, &artifacts, &mut budget, stop);
    }
    crate::statements::collect(r, &artifacts, statement_paths, &mut budget, stop);
    if stop() {
        r.cancelled = true;
        r.complete = false;
    }
    r.provenance.bytes_read = budget.read;
    if enabled {
        match ownership(r, &artifacts, stop) {
            Ok(owners) => r.provenance.ownership = owners,
            Err(e) => gap(r, "", e),
        };
        if stop() {
            r.cancelled = true;
            r.complete = false;
        }
    }
    let by_id: BTreeMap<_, _> = r.artifacts.iter().map(|a| (a.id.clone(), a)).collect();
    let mut hashes: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for h in &r.provenance.hashes {
        hashes.entry(h.sha256.clone()).or_default().insert(
            by_id[&h.artifact_id].identity.clone(),
            h.artifact_id.clone(),
        );
    }
    r.provenance.duplicate_groups = hashes
        .into_values()
        .filter(|g| g.len() > 1)
        .map(|g| g.into_values().collect())
        .collect();
}

fn dependency(
    r: &mut Report,
    pid: &str,
    a: &Artifact,
    root: &Path,
    claim: &str,
    relationship: &str,
    artifacts: &BTreeMap<PathBuf, Artifact>,
) {
    let (target, resolution) = match content::resolve(root, claim, artifacts) {
        Ok(path) => (
            Some(artifacts[&path].id.clone()),
            "inventoried_target_only".to_string(),
        ),
        Err(e) => (None, e),
    };
    let eid=evidence(r,a,format!("Declared {relationship}: {claim:?}; {resolution}"),&["Declared relationship does not prove active use, completeness, ownership or recoverability."]);
    r.provenance.dependencies.push(Dependency {
        declared_package: None,
        declared_version_requirement: None,
        project_id: pid.into(),
        declared_path: claim.into(),
        relationship: relationship.into(),
        target_artifact_id: target,
        resolution,
        evidence_id: eid,
    });
}
fn registry(
    r: &mut Report,
    a: &Artifact,
    bytes: &[u8],
    artifacts: &BTreeMap<PathBuf, Artifact>,
    stop: &dyn Fn() -> bool,
) -> Result<(), String> {
    let registry: Registry = serde_json::from_slice(bytes)
        .map_err(|_| "invalid artifact record schema; unknown fields are rejected")?;
    if registry.schema_version != "1.0.0" || registry.artifacts.len() > 1024 {
        return Err("unsupported registry version or record count".into());
    }
    for record in &registry.artifacts {
        if record.path.len() > 4096
            || [
                &record.owner,
                &record.generation_method,
                &record.source_revision,
            ]
            .iter()
            .any(|s| s.as_ref().is_some_and(|s| s.len() > 4096))
            || record.retention_holds.len() > 128
            || record.retention_holds.iter().any(|s| s.len() > 4096)
        {
            return Err("artifact record exceeds field bounds".into());
        }
    }
    for record in registry.artifacts {
        if stop() {
            return Err("cancelled during registration parsing".into());
        }
        if records_full(r) {
            return Err("provenance record budget reached".into());
        }
        let (target, resolution) = match content::resolve(
            Path::new(&a.path).parent().unwrap(),
            &record.path,
            artifacts,
        ) {
            Ok(p) => (
                Some(artifacts[&p].id.clone()),
                "inventoried_target_only".into(),
            ),
            Err(e) => (None, e),
        };
        let eid=evidence(r,a,format!("Artifact registration claim for {:?}; owner {:?}; generation {:?}; revision {:?}; holds {:?}",record.path,record.owner,record.generation_method,record.source_revision,record.retention_holds),&["Registration is untrusted, unauthenticated evidence; never authorization or proof of reproducibility."]);
        r.provenance.claims.push(ArtifactClaim {
            record_artifact_id: a.id.clone(),
            target_artifact_id: target,
            declared_path: record.path,
            declared_owner: record.owner,
            declared_generation_method: record.generation_method,
            declared_source_revision: record.source_revision,
            retention_holds: record.retention_holds,
            resolution,
            evidence_id: eid,
        });
    }
    Ok(())
}

fn ownership(
    r: &Report,
    artifacts: &BTreeMap<PathBuf, Artifact>,
    stop: &dyn Fn() -> bool,
) -> Result<Vec<Ownership>, String> {
    if stop() {
        return Err("cancelled before ownership association".into());
    }
    if artifacts.len() > 100_000 {
        return Err("ownership record budget exceeded; ownership remains unresolved".into());
    }
    let mut links = MAX_ASSOCIATIONS;
    let mut bytes = 32 * 1024 * 1024;
    // A nearest-manifest association is context; dependency users and hard-link aliases add claimants.
    let mut roots: BTreeMap<PathBuf, Vec<&Project>> = BTreeMap::new();
    for p in &r.provenance.projects {
        roots.entry(PathBuf::from(&p.root)).or_default().push(p);
    }
    let ids: BTreeMap<_, _> = artifacts.values().map(|a| (a.id.clone(), a)).collect();
    let mut dependencies: BTreeMap<PathBuf, Vec<&Dependency>> = BTreeMap::new();
    for dep in &r.provenance.dependencies {
        if let Some(id) = &dep.target_artifact_id {
            dependencies
                .entry(PathBuf::from(&ids[id].path))
                .or_default()
                .push(dep);
        }
    }
    let mut claims: BTreeMap<PathBuf, Vec<&ArtifactClaim>> = BTreeMap::new();
    for claim in &r.provenance.claims {
        if let Some(id) = &claim.target_artifact_id {
            claims
                .entry(PathBuf::from(&ids[id].path))
                .or_default()
                .push(claim);
        }
    }
    let mut direct: BTreeMap<String, Associations> = BTreeMap::new();
    for a in artifacts.values() {
        if stop() {
            return Err("cancelled during ownership association".into());
        }
        let entry = direct.entry(a.id.clone()).or_default();
        if !Path::new(&a.path)
            .components()
            .any(|c| c.as_os_str() == ".git")
        {
            for parent in Path::new(&a.path).ancestors() {
                if let Some(projects) = roots.get(parent) {
                    for p in projects {
                        entry.0.insert(p.id.clone());
                        entry.2.insert(p.evidence_id.clone());
                    }
                    break;
                }
            }
        }
        for parent in Path::new(&a.path).ancestors() {
            if let Some(deps) = dependencies.get(parent) {
                for dep in deps {
                    entry.0.insert(dep.project_id.clone());
                    entry.2.insert(dep.evidence_id.clone());
                }
            }
            if let Some(records) = claims.get(parent) {
                for claim in records {
                    if let Some(owner) = &claim.declared_owner {
                        entry.1.insert(owner.clone());
                    }
                    entry.2.insert(claim.evidence_id.clone());
                }
            }
        }
        charge(entry, &mut links, &mut bytes)?;
    }
    // Shared file identities retain every observed contextual project/claim, never pick a winner.
    let mut shared: BTreeMap<String, Associations> = BTreeMap::new();
    for (id, entry) in &direct {
        if stop() {
            return Err("cancelled during shared-identity association".into());
        }
        let target = shared.entry(ids[id].identity.clone()).or_default();
        target.0.extend(entry.0.iter().cloned());
        target.1.extend(entry.1.iter().cloned());
        target.2.extend(entry.2.iter().cloned());
    }
    let mut out = Vec::new();
    let mut links = MAX_ASSOCIATIONS;
    let mut bytes = 32 * 1024 * 1024;
    for a in &r.artifacts {
        if stop() {
            return Err("cancelled during ownership output".into());
        }
        let entry = &shared[&a.identity];
        charge(entry, &mut links, &mut bytes)?;
        out.push(Ownership {
            artifact_id: a.id.clone(),
            project_ids: entry.0.iter().cloned().collect(),
            declared_owners: entry.1.iter().cloned().collect(),
            status: if entry.1.len() > 1 {
                "conflicting_claims"
            } else if entry.0.len() > 1 {
                "shared_context"
            } else if !entry.1.is_empty() {
                "declared_only"
            } else if !entry.0.is_empty() {
                "context_only"
            } else {
                "unresolved"
            }
            .into(),
            evidence_ids: entry.2.iter().cloned().collect(),
        });
    }
    Ok(out)
}

pub fn attach_candidates(r: &mut Report) {
    let paths: BTreeMap<_, _> = r
        .artifacts
        .iter()
        .map(|a| (a.id.as_str(), PathBuf::from(&a.path)))
        .collect();
    let candidates: BTreeMap<_, _> = r
        .candidates
        .iter()
        .map(|c| (paths[c.artifact_id.as_str()].clone(), c.artifact_id.clone()))
        .collect();
    let mut statement_links: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut links = 0usize;
    let mut truncated = false;
    'subjects: for subject in &r.provenance.statement_subjects {
        let Some(target) = subject
            .target_artifact_id
            .as_deref()
            .and_then(|id| paths.get(id))
        else {
            continue;
        };
        for parent in target.ancestors() {
            if let Some(candidate) = candidates.get(parent) {
                if links >= MAX_ASSOCIATIONS {
                    truncated = true;
                    break 'subjects;
                }
                statement_links
                    .entry(candidate.clone())
                    .or_default()
                    .push(subject.evidence_id.clone());
                links += 1;
            }
        }
    }
    if truncated {
        gap(
            r,
            "",
            "statement-to-candidate association budget exceeded; inspect statement checks directly"
                .into(),
        );
    }

    let owners: BTreeMap<_, _> = r
        .provenance
        .ownership
        .iter()
        .map(|o| (&o.artifact_id, o))
        .collect();
    let statement_subjects: BTreeMap<_, _> = r
        .provenance
        .statement_subjects
        .iter()
        .map(|s| (&s.evidence_id, s))
        .collect();
    let claims: BTreeMap<_, _> = r
        .provenance
        .claims
        .iter()
        .map(|c| (&c.evidence_id, c))
        .collect();
    let mut checks: BTreeMap<&String, Vec<&ConsistencyCheck>> = BTreeMap::new();
    for check in &r.provenance.checks {
        checks
            .entry(&check.subject_evidence_id)
            .or_default()
            .push(check);
    }
    for c in &mut r.candidates {
        if let Some(ids) = statement_links.get(&c.artifact_id) {
            c.evidence_ids.extend(ids.iter().cloned());
        }
        if let Some(owner) = owners.get(&c.artifact_id) {
            c.evidence_ids.extend(owner.evidence_ids.clone());
            if matches!(
                owner.status.as_str(),
                "shared_context" | "conflicting_claims"
            ) {
                c.blockers
                    .push(format!("ownership evidence: {}", owner.status));
            }
        }
        for claim in c.evidence_ids.iter().filter_map(|e| claims.get(e)) {
            for hold in &claim.retention_holds {
                c.blockers
                    .push(format!("declared retention hold (unverified): {hold}"));
            }
        }
        let mut supporting = Vec::new();
        for id in &c.evidence_ids {
            if let Some(subject) = statement_subjects.get(id) {
                if subject.authentication != "verified_with_supplied_key" {
                    c.blockers.push(format!(
                        "statement signature: {} (subject {})",
                        subject.authentication, subject.evidence_id
                    ));
                }
            }
            if let Some(items) = checks.get(id) {
                for check in items {
                    supporting.extend(check.supporting_evidence_ids.iter().cloned());
                    if check.status != "consistent" {
                        c.blockers.push(format!(
                            "{} comparison: {} (subject {})",
                            check.kind, check.status, check.subject_evidence_id
                        ));
                    }
                }
            }
        }
        c.evidence_ids.extend(supporting);
        c.evidence_ids.sort();
        c.evidence_ids.dedup();
    }
}

pub(crate) fn fingerprint(r: &mut Report, a: &Artifact, bytes: &[u8]) -> String {
    let sha256 = format!("{:x}", Sha256::digest(bytes));
    let eid = evidence(
        r,
        a,
        format!("Evidence source SHA-256 {sha256}; {} bytes", bytes.len()),
        &["Fingerprint of observed bytes only; not authentication or a build attestation."],
    );
    r.provenance.source_hashes.push(ContentHash {
        artifact_id: a.id.clone(),
        sha256,
        bytes: bytes.len() as u64,
        evidence_id: eid.clone(),
    });
    eid
}
