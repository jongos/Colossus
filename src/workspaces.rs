//! Compare explicit lockfile associations with bounded literal workspace declarations.
use crate::{content, model::*, provenance::gap};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
fn literal(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 1024
        && !Path::new(s).is_absolute()
        && !s.contains(['*', '?', '[', ']', '{', '}', ':'])
}
fn paths(v: Option<&Value>, supported: &mut bool) -> Vec<String> {
    let Some(v) = v else { return vec![] };
    let Some(a) = v.as_array() else {
        *supported = false;
        return vec![];
    };
    if a.len() > 1024 {
        *supported = false;
        return vec![];
    }
    a.iter()
        .filter_map(|v| match v.as_str() {
            Some(s) if literal(s) => Some(s.to_owned()),
            _ => {
                *supported = false;
                None
            }
        })
        .collect()
}
pub fn record(
    r: &mut Report,
    project_id: &str,
    evidence_id: &str,
    value: &Value,
    remaining: &mut usize,
) {
    let mut supported = true;
    let workspace = value.get("workspace");
    let has_workspace = workspace.is_some_and(Value::is_object);
    if workspace.is_some() && !has_workspace {
        supported = false;
    }
    let members = paths(workspace.and_then(|w| w.get("members")), &mut supported);
    let exclude = paths(workspace.and_then(|w| w.get("exclude")), &mut supported);
    let package_workspace = match value.pointer("/package/workspace") {
        None => None,
        Some(v) => match v.as_str() {
            Some(s) if literal(s) => Some(s.to_owned()),
            _ => {
                supported = false;
                None
            }
        },
    };
    let cost = members.len() + exclude.len();
    if cost > *remaining {
        gap(
            r,
            "",
            "workspace declaration path budget reached; declaration omitted".into(),
        );
        return;
    }
    *remaining -= cost;
    r.provenance
        .cargo_workspaces
        .push(CargoWorkspaceDeclaration {
            project_id: project_id.into(),
            evidence_id: evidence_id.into(),
            has_workspace,
            members,
            exclude,
            package_workspace,
            supported,
        });
}
pub fn collect(r: &mut Report, artifacts: &BTreeMap<PathBuf, Artifact>, stop: &dyn Fn() -> bool) {
    let projects = r.provenance.projects.clone();
    let declarations: BTreeMap<_, _> = r
        .provenance
        .cargo_workspaces
        .iter()
        .map(|w| (w.project_id.as_str(), w))
        .collect();
    let by_id: BTreeMap<_, _> = artifacts.values().map(|a| (a.id.as_str(), a)).collect();
    let by_manifest: BTreeMap<_, _> = projects
        .iter()
        .filter(|p| p.ecosystem == "cargo")
        .filter_map(|p| {
            by_id
                .get(p.manifest_artifact_id.as_str())
                .map(|a| (PathBuf::from(&a.path), p))
        })
        .collect();
    let mut checks = Vec::new();
    for selection in &r.provenance.cargo_lockfiles {
        if stop() {
            break;
        }
        let Some(member) = by_manifest.get(&PathBuf::from(&selection.manifest_path)) else {
            continue;
        };
        let lock = Path::new(&selection.lockfile_path);
        let root = lock
            .parent()
            .and_then(|p| by_manifest.get(&p.join("Cargo.toml")));
        let mut support = Vec::new();
        if let Some(root) = root {
            support.push(root.evidence_id.clone());
        }
        let (status, detail) = (|| {
            if lock.file_name().and_then(|s| s.to_str()) != Some("Cargo.lock") {
                return ("unresolved","Selected filename is not Cargo.lock; no workspace-root association is inferred.");
            }
            let Some(root) = root else {
                return (
                    "unresolved",
                    "No observed Cargo manifest beside the selected lockfile.",
                );
            };
            let (Some(w), Some(m)) = (
                declarations.get(root.id.as_str()),
                declarations.get(member.id.as_str()),
            ) else {
                return (
                    "unresolved",
                    "Workspace declaration unavailable within collection limits.",
                );
            };
            if !w.supported || !m.supported {
                return ("unresolved","Unsupported workspace paths or field types; globs and malformed declarations are not interpreted.");
            }
            if !w.has_workspace {
                return (
                    "unresolved",
                    "Selected lockfile has no observed workspace table beside it.",
                );
            }
            if member.id != root.id && m.has_workspace {
                return (
                    "mismatch",
                    "Selected member declares its own workspace table.",
                );
            }
            if let Some(pointer) = &m.package_workspace {
                match content::resolve(Path::new(&member.root), pointer, artifacts) {
                    Ok(p) if p == Path::new(&root.root) => {}
                    Ok(_) => {
                        return (
                            "mismatch",
                            "Member package.workspace points to a different inventoried location.",
                        )
                    }
                    Err(_) => {
                        return (
                            "unresolved",
                            "Member package.workspace cannot be resolved within inventory.",
                        )
                    }
                }
            }
            let target = PathBuf::from(&member.root);
            let mut unresolved = false;
            for excluded in &w.exclude {
                if stop() {
                    return ("unresolved", "Cancelled workspace comparison.");
                }
                match content::resolve(Path::new(&root.root), excluded, artifacts) {
                    Ok(p) if p == target => {
                        return (
                            "mismatch",
                            "Workspace explicitly excludes the selected member path.",
                        )
                    }
                    Ok(_) => {}
                    Err(_) => unresolved = true,
                }
            }
            if unresolved {
                return (
                    "unresolved",
                    "At least one exclusion path lacks supported inventory evidence.",
                );
            }
            if member.id == root.id && member.declared_name.is_some() {
                return ("consistent","Selected package is the observed workspace root package; declaration agreement only.");
            }
            for entry in &w.members {
                if stop() {
                    return ("unresolved", "Cancelled workspace comparison.");
                }
                if content::resolve(Path::new(&root.root), entry, artifacts)
                    .ok()
                    .as_ref()
                    == Some(&target)
                {
                    return ("consistent","Literal workspace member path agrees with the selected manifest; Cargo membership, resolver state and build execution remain unverified.");
                }
            }
            ("unresolved","No supported literal membership declaration matches; implicit path-dependency membership is not inferred.")
        })();
        if stop() {
            break;
        }
        checks.push(ConsistencyCheck {
            kind: "cargo_selected_workspace_membership".into(),
            subject_evidence_id: member.evidence_id.clone(),
            status: status.into(),
            observed_value: root.map(|p| p.id.clone()),
            supporting_evidence_ids: support,
            detail: detail.into(),
        });
    }
    r.provenance.checks.extend(checks);
}
