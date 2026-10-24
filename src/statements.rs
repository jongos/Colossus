//! Explicitly selected statement subjects; signature results do not verify predicates.
use crate::{
    content::{self, Budget},
    model::*,
    provenance::{evidence, fingerprint, gap},
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    #[serde(rename = "_type")]
    kind: String,
    subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Subject {
    name: String,
    digest: Digests,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Digests {
    sha256: Option<String>,
}

fn parse(bytes: &[u8]) -> Result<Statement, String> {
    let s: Statement = serde_json::from_slice(bytes).map_err(|_| {
        "unsupported statement structure; expected the documented Statement v1 subset"
    })?;
    if s.kind != "https://in-toto.io/Statement/v1"
        || s.subject.is_empty()
        || s.subject.len() > 1024
        || s.predicate_type.len() > 4096
        || !s.predicate_type.contains(':')
        || !s.predicate.is_object()
    {
        return Err("unsupported statement version, predicate or subject count".into());
    }
    if s.subject.iter().any(|v| {
        v.name.len() > 4096
            || v.name.is_empty()
            || v.digest
                .sha256
                .as_ref()
                .is_some_and(|d| d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()))
    }) {
        return Err("subject name or SHA256 is invalid or exceeds bounds".into());
    }
    Ok(s)
}

pub fn collect(
    r: &mut Report,
    artifacts: &BTreeMap<PathBuf, Artifact>,
    paths: &[PathBuf],
    budget: &mut Budget,
    stop: &dyn Fn() -> bool,
) {
    let hashes: BTreeMap<_, _> = r
        .provenance
        .hashes
        .iter()
        .map(|h| (h.artifact_id.clone(), h.clone()))
        .collect();
    let mut seen = BTreeSet::new();
    for path in paths {
        if stop() {
            return;
        }
        if !seen.insert(path.clone()) {
            continue;
        }
        if seen.len() > 32 {
            gap(r, "", "selected statement limit (32) exceeded".into());
            break;
        }
        let Some(a) = artifacts.get(path) else {
            gap(
                r,
                &path.to_string_lossy(),
                "statement is not an exact inventoried path".into(),
            );
            continue;
        };
        let bytes = match budget.read(a, 1024 * 1024, stop) {
            Ok(b) => b,
            Err(e) => {
                gap(r, &a.path, e);
                continue;
            }
        };
        let source_id = fingerprint(r, a, &bytes);
        let decoded = match crate::authentication::inspect(&bytes, &r.provenance.trusted_keys, stop)
        {
            Ok(value) => value,
            Err(e) => {
                gap(r, &a.path, e);
                continue;
            }
        };
        // Parse the same decoded bytes whose DSSE signature was checked.
        let statement = match parse(&decoded.payload) {
            Ok(s) => s,
            Err(e) => {
                gap(r, &a.path, e);
                continue;
            }
        };
        if r.provenance.statement_subjects.len() + statement.subject.len() > 10_000 {
            gap(
                r,
                &a.path,
                "statement subject budget (10000) exceeded".into(),
            );
            break;
        }
        let auth_eid=evidence(r,a,format!("Statement authentication: {}; accepted caller labels {:?}; payload SHA256 {}",decoded.status,decoded.accepted_key_ids,decoded.payload_sha256),&["Caller-supplied public keys only; key ownership, revocation, freshness, predicate truth and build execution are not verified."]);
        r.provenance
            .statement_authentications
            .push(StatementAuthentication {
                statement_artifact_id: a.id.clone(),
                status: decoded.status.clone(),
                accepted_key_ids: decoded.accepted_key_ids.clone(),
                payload_sha256: decoded.payload_sha256.clone(),
                evidence_id: auth_eid.clone(),
            });
        for subject in statement.subject {
            if stop() {
                return;
            }
            // Statement names are not generally paths. This adapter supports only
            // relative local names under the statement directory, without traversal.
            let local = !Path::new(&subject.name).is_absolute()
                && !subject.name.contains(':')
                && !subject.name.contains('\\')
                && subject
                    .name
                    .split('/')
                    .all(|p| !matches!(p, "" | "." | ".."));
            let target = if local {
                content::resolve(path.parent().unwrap(), &subject.name, artifacts)
                    .ok()
                    .and_then(|p| artifacts.get(&p))
                    .filter(|a| a.kind == "file")
            } else {
                None
            };
            let digest = subject.digest.sha256.map(|d| d.to_ascii_lowercase());
            let hash = target.and_then(|a| hashes.get(&a.id));
            let status = match (&digest, hash) {
                (Some(d), Some(h)) if d == &h.sha256 => "consistent",
                (Some(_), Some(_)) => "mismatch",
                _ => "unresolved",
            };
            let eid=evidence(r,a,format!("Statement subject {:?}; claimed SHA256 {:?}; predicate type {:?}",subject.name,digest,statement.predicate_type),&["Consult the separate authentication record. Predicate meaning, real-world signer identity and build execution remain unverified."]);
            r.provenance.statement_subjects.push(StatementSubject {
                statement_artifact_id: a.id.clone(),
                name: subject.name,
                declared_sha256: digest,
                predicate_type: statement.predicate_type.clone(),
                target_artifact_id: target.map(|a| a.id.clone()),
                evidence_id: eid.clone(),
                authentication: decoded.status.clone(),
            });
            let mut support = vec![source_id.clone(), auth_eid.clone()];
            if let Some(h) = hash {
                support.push(h.evidence_id.clone());
            }
            r.provenance.checks.push(ConsistencyCheck {kind:"statement_digest".into(),subject_evidence_id:eid,status:status.into(),observed_value:hash.map(|h|h.sha256.clone()),supporting_evidence_ids:support,detail:"Compares a statement claim with an explicitly selected target hash only. No target content is read implicitly. Unsupported names, absent SHA256 or missing selected hashes remain unresolved; a digest match alone is not signature verification, build proof or cleanup authority.".into()});
        }
    }
}
