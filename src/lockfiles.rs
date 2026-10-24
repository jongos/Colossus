//! Bounded comparisons with adjacent Cargo.lock declarations, never resolver execution.
use crate::{
    content::Budget,
    model::*,
    provenance::{fingerprint, gap},
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const LIMIT: u64 = 1024 * 1024;
const PACKAGES: usize = 10_000;
struct Lock {
    local: BTreeMap<String, Vec<String>>,
}
fn parse(bytes: &[u8], stop: &dyn Fn() -> bool) -> Result<Lock, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "lockfile is not UTF-8")?;
    let value = text
        .parse::<toml::Value>()
        .map_err(|_| "malformed Cargo.lock TOML")?;
    if !matches!(
        value.get("version").and_then(toml::Value::as_integer),
        Some(3 | 4)
    ) {
        return Err("only explicit Cargo.lock format versions 3 and 4 are supported".into());
    }
    let packages = value
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or("missing lockfile package array")?;
    if packages.len() > PACKAGES {
        return Err("lockfile package limit exceeded".into());
    }
    let mut local = BTreeMap::<String, Vec<String>>::new();
    for p in packages {
        if stop() {
            return Err("cancelled while parsing lockfile packages".into());
        }
        let name = p
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 1024)
            .ok_or("invalid lockfile package name")?;
        let version = p
            .get("version")
            .and_then(toml::Value::as_str)
            .filter(|s| s.len() <= 1024)
            .ok_or("invalid lockfile package version")?;
        semver::Version::parse(version).map_err(|_| "invalid lockfile package semantic version")?;
        match p.get("source") {
            None => {
                local
                    .entry(name.to_owned())
                    .or_default()
                    .push(version.to_owned());
            }
            Some(toml::Value::String(s)) if !s.is_empty() && s.len() <= 4096 => {}
            _ => return Err("invalid lockfile package source".into()),
        }
    }
    Ok(Lock { local })
}
fn compare(
    lock: Option<&Lock>,
    name: Option<&str>,
    version: Option<&str>,
) -> (&'static str, Option<String>, &'static str) {
    let Some(lock) = lock else {
        return (
            "unresolved",
            None,
            "No supported adjacent lockfile observation.",
        );
    };
    let (Some(name), Some(version)) = (name, version) else {
        return ("unresolved",None,"Manifest package name or explicit version is unavailable; inherited versions are unsupported.");
    };
    let Ok(expected) = semver::Version::parse(version) else {
        return ("unresolved", None, "Manifest package version is invalid.");
    };
    let Some(entries) = lock.local.get(name) else {
        return ("unresolved",None,"No source-less lockfile package with the declared name; absence does not prove incompatibility.");
    };
    if entries.len() != 1 {
        return (
            "unresolved",
            None,
            "Multiple source-less lockfile entries have this name; package identity is ambiguous.",
        );
    }
    let actual = semver::Version::parse(&entries[0]).expect("validated package version");
    (if actual==expected {"consistent"} else {"mismatch"}, Some(entries[0].clone()), "Compared explicit manifest version to one source-less lockfile entry by name. This does not establish path identity, dependency resolution, checksums, features, active use or build compatibility.")
}
pub fn collect(
    r: &mut Report,
    artifacts: &BTreeMap<PathBuf, Artifact>,
    budget: &mut Budget,
    stop: &dyn Fn() -> bool,
) {
    let projects = r.provenance.projects.clone();
    let by_root: BTreeMap<_, _> = projects
        .iter()
        .filter(|p| p.ecosystem == "cargo")
        .map(|p| (PathBuf::from(&p.root), p))
        .collect();
    let by_id: BTreeMap<_, _> = artifacts.values().map(|a| (a.id.as_str(), a)).collect();
    let mut deps = BTreeMap::<&str, Vec<_>>::new();
    for d in &r.provenance.dependencies {
        deps.entry(&d.project_id).or_default().push(d.clone());
    }
    // Own the dependency lists so report evidence can be appended below.
    let deps: BTreeMap<String, Vec<Dependency>> =
        deps.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    for project in projects.iter().filter(|p| p.ecosystem == "cargo") {
        if stop() {
            return;
        }
        let path = Path::new(&project.root).join("Cargo.lock");
        let mut support = Vec::new();
        let lock = if let Some(a) = artifacts.get(&path) {
            if r.provenance.source_hashes.len() >= 10_000 {
                gap(
                    r,
                    &a.path,
                    "source fingerprint budget reached before lockfile read".into(),
                );
                None
            } else {
                match budget.read(a, LIMIT, stop) {
                    Ok(bytes) => {
                        support.push(fingerprint(r, a, &bytes));
                        match parse(&bytes, stop) {
                            Ok(lock) => Some(lock),
                            Err(e) => {
                                gap(r, &a.path, e);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        gap(r, &a.path, e);
                        None
                    }
                }
            }
        } else {
            None
        };
        if stop() {
            return;
        }
        let (status, observed_value, detail) = compare(
            lock.as_ref(),
            project.declared_name.as_deref(),
            project.declared_version.as_deref(),
        );
        r.provenance.checks.push(ConsistencyCheck {
            kind: "cargo_lock_package_version".into(),
            subject_evidence_id: project.evidence_id.clone(),
            status: status.into(),
            observed_value,
            supporting_evidence_ids: support.clone(),
            detail: detail.into(),
        });
        for dep in deps.get(&project.id).into_iter().flatten() {
            if stop() {
                return;
            }
            // Workspace membership is not a package dependency declaration.
            if dep.declared_package.is_none() {
                continue;
            }
            let target = dep
                .target_artifact_id
                .as_deref()
                .and_then(|id| by_id.get(id))
                .and_then(|a| by_root.get(&PathBuf::from(&a.path)));
            let mut ids = support.clone();
            if let Some(p) = target {
                ids.push(p.evidence_id.clone());
            }
            let (status, observed_value, detail) = if target
                .and_then(|p| p.declared_name.as_deref())
                != dep.declared_package.as_deref()
            {
                ("unresolved",None,"Dependency target manifest is absent or its name disagrees with the declaration.")
            } else {
                compare(
                    lock.as_ref(),
                    dep.declared_package.as_deref(),
                    target.and_then(|p| p.declared_version.as_deref()),
                )
            };
            r.provenance.checks.push(ConsistencyCheck {
                kind: "cargo_lock_dependency_version".into(),
                subject_evidence_id: dep.evidence_id.clone(),
                status: status.into(),
                observed_value,
                supporting_evidence_ids: ids,
                detail: detail.into(),
            });
        }
    }
}
