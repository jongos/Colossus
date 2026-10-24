//! Compare bounded observations without upgrading local consistency to trust.
use crate::{
    content::{self, Budget},
    model::*,
    provenance::fingerprint,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

type Revision = (Option<String>, Vec<String>, String);

fn object_id(s: &str) -> Option<String> {
    if matches!(s.len(), 40 | 64)
        && s.bytes().all(|b| b.is_ascii_hexdigit())
        && s.bytes().any(|b| b != b'0')
    {
        Some(s.to_ascii_lowercase())
    } else {
        None
    }
}

// Deliberately supports only simple loose branch refs, not every valid Git ref.
fn branch_ref(s: &str) -> bool {
    s.starts_with("refs/heads/")
        && s.len() <= 1024
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
        && s.split('/').all(|p| {
            !p.is_empty() && !p.starts_with('.') && !p.ends_with('.') && !p.ends_with(".lock")
        })
}

fn read_source(
    r: &mut Report,
    path: &Path,
    artifacts: &BTreeMap<PathBuf, Artifact>,
    budget: &mut Budget,
    stop: &dyn Fn() -> bool,
    ids: &mut Vec<String>,
) -> Result<String, String> {
    let a = artifacts
        .get(path)
        .ok_or("revision metadata is not inventoried")?;
    let bytes = budget.read(a, 4096, stop).inspect_err(|e| {
        r.complete = false;
        r.issues.push(Issue {
            path: a.path.clone(),
            code: "corroboration_gap".into(),
            detail: e.clone(),
        });
    })?;
    ids.push(fingerprint(r, a, &bytes));
    String::from_utf8(bytes)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_owned())
        .map_err(|_| "revision metadata is not UTF-8".into())
}

fn revision(
    r: &mut Report,
    repo: &Repository,
    artifacts: &BTreeMap<PathBuf, Artifact>,
    budget: &mut Budget,
    stop: &dyn Fn() -> bool,
) -> Revision {
    let mut ids = Vec::new();
    let result = (|| -> Result<String, String> {
        let dir = Path::new(repo.resolved_gitdir.as_deref().ok_or("gitdir unresolved")?);
        let head = read_source(r, &dir.join("HEAD"), artifacts, budget, stop, &mut ids)?;
        if let Some(id) = object_id(&head) {
            return Ok(id);
        }
        let name = head.strip_prefix("ref: ").filter(|s| branch_ref(s)).ok_or(
            "unsupported HEAD; only full object IDs or simple loose branch refs are supported",
        )?;
        let base = if artifacts.contains_key(&dir.join("commondir")) {
            Path::new(
                repo.resolved_common_dir
                    .as_deref()
                    .ok_or("common directory unresolved")?,
            )
        } else {
            dir
        };
        let target = content::resolve(base, name, artifacts)?;
        let value = read_source(r, &target, artifacts, budget, stop, &mut ids)?;
        object_id(&value).ok_or(
            "loose ref is not a full object ID; symbolic chains and packed refs are unsupported"
                .into(),
        )
    })();
    match result {
        Ok(id) => (Some(id), ids, "Compared with local HEAD metadata; object existence, signatures, build inputs and working-tree content are unverified.".into()),
        Err(e) => (None, ids, e),
    }
}

pub fn collect(
    r: &mut Report,
    artifacts: &BTreeMap<PathBuf, Artifact>,
    budget: &mut Budget,
    stop: &dyn Fn() -> bool,
) {
    let by_id: BTreeMap<_, _> = artifacts.values().map(|a| (a.id.as_str(), a)).collect();
    let projects: BTreeMap<_, _> = r
        .provenance
        .projects
        .iter()
        .map(|p| (p.id.clone(), p.clone()))
        .collect();
    let by_root: BTreeMap<_, _> = projects
        .values()
        .map(|p| ((PathBuf::from(&p.root), p.ecosystem.clone()), p))
        .collect();
    for dep in r.provenance.dependencies.clone() {
        if stop() {
            return;
        }
        let project = &projects[&dep.project_id];
        let target = dep
            .target_artifact_id
            .as_deref()
            .and_then(|id| by_id.get(id));
        let matched = target
            .filter(|a| a.kind == "directory")
            .and_then(|a| by_root.get(&(PathBuf::from(&a.path), project.ecosystem.clone())));
        let (status, observed_value, supporting, detail) = match matched {
            Some(p) => ("consistent", Some(p.id.clone()), vec![p.evidence_id.clone()], "Target has a parsed manifest of the declaring ecosystem. This manifest-presence check alone does not verify name or version compatibility; consult separate Cargo checks where present. Features, lockfiles and active use remain unverified."),
            None => ("unresolved", None, vec![], "No parsed manifest of the declaring ecosystem at this exact target directory; archives, unsupported declarations and missing targets remain unresolved."),
        };
        if project.ecosystem == "cargo" && dep.relationship == "local_dependency" {
            let target = matched.copied();
            let name = target.and_then(|p| p.declared_name.clone());
            let version = target.and_then(|p| p.declared_version.clone());
            let supporting = target
                .map(|p| vec![p.evidence_id.clone()])
                .unwrap_or_default();
            let name_status = match (&dep.declared_package, &name) {
                (Some(a), Some(b)) if a == b => "consistent",
                (Some(_), Some(_)) => "mismatch",
                _ => "unresolved",
            };
            let version_status = match (
                dep.declared_version_requirement
                    .as_deref()
                    .and_then(|s| semver::VersionReq::parse(s).ok()),
                version
                    .as_deref()
                    .and_then(|s| semver::Version::parse(s).ok()),
            ) {
                (Some(req), Some(version)) if req.matches(&version) => "consistent",
                (Some(_), Some(_)) => "mismatch",
                _ => "unresolved",
            };
            for (kind, status, observed_value, detail) in [
                ("cargo_package_name", name_status, name, "Compared declared Cargo package name (including package rename) with target manifest; active use remains unverified."),
                ("cargo_version_requirement", version_status, version, "Compared an explicit Cargo requirement with the target's declared version using Cargo-style semver. Absent, invalid and inherited versions remain unresolved; features, lockfiles and build compatibility are unverified."),
            ] {
                r.provenance.checks.push(ConsistencyCheck {kind:kind.into(),subject_evidence_id:dep.evidence_id.clone(),status:status.into(),observed_value,supporting_evidence_ids:supporting.clone(),detail:detail.into()});
            }
        }
        r.provenance.checks.push(ConsistencyCheck {
            kind: "dependency_manifest".into(),
            subject_evidence_id: dep.evidence_id,
            status: status.into(),
            observed_value,
            supporting_evidence_ids: supporting,
            detail: detail.into(),
        });
    }
    let repos: BTreeMap<_, _> = r
        .repositories
        .iter()
        .map(|repo| (PathBuf::from(&repo.path), repo.clone()))
        .collect();
    let mut cache: BTreeMap<String, Revision> = BTreeMap::new();
    for claim in r.provenance.claims.clone() {
        if stop() {
            return;
        }
        let Some(declared) = claim.declared_source_revision.as_deref() else {
            continue;
        };
        let target = claim
            .target_artifact_id
            .as_deref()
            .and_then(|id| by_id.get(id));
        // The comparison is explicitly to the target's nearest repository context.
        let repo = target.and_then(|a| Path::new(&a.path).ancestors().find_map(|p| repos.get(p)));
        let expected = object_id(declared);
        let observation = if expected.is_none() {
            (None, vec![], "Declared revision is not a full nonzero object ID; abbreviations and revision expressions are unsupported.".into())
        } else if let Some(repo) = repo {
            if !cache.contains_key(&repo.path) {
                let value = revision(r, repo, artifacts, budget, stop);
                cache.insert(repo.path.clone(), value);
            }
            cache[&repo.path].clone()
        } else {
            (
                None,
                vec![],
                "Target has no inventoried repository context.".into(),
            )
        };
        if stop() {
            return;
        }
        let status = match (&expected, &observation.0) {
            (Some(a), Some(b)) if a == b => "consistent",
            (Some(_), Some(_)) => "mismatch",
            _ => "unresolved",
        };
        r.provenance.checks.push(ConsistencyCheck {
            kind: "source_revision".into(),
            subject_evidence_id: claim.evidence_id,
            status: status.into(),
            observed_value: observation.0,
            supporting_evidence_ids: observation.1,
            detail: observation.2,
        });
    }
}
