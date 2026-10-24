use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub path: String,
    pub identity: String,
    pub kind: String,
    pub project_owner: Option<String>,
    pub logical_bytes: u64,
    pub allocated_bytes: Option<u64>,
    pub modified_filetime: u64,
    pub hard_links: u32,
    pub counted: bool,
    pub originating_task: Option<String>,
    pub generation_method: Option<String>,
    pub dependencies: Option<Vec<String>>,
    pub retention_holds: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub artifact_id: String,
    pub observation: String,
    pub source: String,
    pub timestamp_unix: u64,
    pub collector_version: String,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub artifact_id: String,
    pub classification: String,
    pub proposed_operation: String,
    pub evidence_ids: Vec<String>,
    pub blockers: Vec<String>,
    pub recovery_method: Option<String>,
    pub reconstruction_cost: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub path: String,
    pub code: String,
    pub detail: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub path: String,
    pub kind: String,
    pub head: Option<String>,
    pub gitdir_claim: Option<String>,
    pub common_dir_claim: Option<String>,
    pub resolved_gitdir: Option<String>,
    pub resolved_common_dir: Option<String>,
    pub index_checksum: Option<String>,
    pub locked: Option<bool>,
    pub index_entries: Option<usize>,
    pub possibly_modified: Vec<String>,
    pub untracked: Vec<String>,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub schema_version: String,
    pub roots: Vec<String>,
    pub candidate_scope: Vec<String>,
    pub protected_paths: Vec<String>,
    pub required_approval: String,
    pub manifest_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Totals {
    pub logical_bytes: u64,
    pub allocated_known_bytes: u64,
    pub allocated_unknown_files: u64,
    pub unique_files: u64,
    pub hard_link_aliases: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub tool_version: String,
    pub timestamp_unix: u64,
    pub complete: bool,
    pub cancelled: bool,
    pub inventory_coverage: String,
    pub roots: Vec<String>,
    pub root_identities: Vec<String>,
    pub artifacts: Vec<Artifact>,
    pub evidence: Vec<Evidence>,
    pub candidates: Vec<Candidate>,
    pub repositories: Vec<Repository>,
    pub provenance: Provenance,
    pub issues: Vec<Issue>,
    pub totals: Totals,
    pub plan: Plan,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Provenance {
    pub cargo_lockfiles: Vec<CargoLockfileSelection>,
    pub trusted_keys: Vec<TrustedKey>,
    pub statement_authentications: Vec<StatementAuthentication>,
    pub statement_subjects: Vec<StatementSubject>,
    pub source_hashes: Vec<ContentHash>,
    pub checks: Vec<ConsistencyCheck>,
    pub enabled: bool,
    pub bytes_read: u64,
    pub projects: Vec<Project>,
    pub dependencies: Vec<Dependency>,
    pub claims: Vec<ArtifactClaim>,
    pub ownership: Vec<Ownership>,
    pub hashes: Vec<ContentHash>,
    pub duplicate_groups: Vec<Vec<String>>,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub root: String,
    pub manifest_artifact_id: String,
    pub ecosystem: String,
    pub declared_name: Option<String>,
    pub declared_version: Option<String>,
    pub evidence_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub declared_package: Option<String>,
    pub declared_version_requirement: Option<String>,
    pub project_id: String,
    pub declared_path: String,
    pub relationship: String,
    pub target_artifact_id: Option<String>,
    pub resolution: String,
    pub evidence_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactClaim {
    pub record_artifact_id: String,
    pub target_artifact_id: Option<String>,
    pub declared_path: String,
    pub declared_owner: Option<String>,
    pub declared_generation_method: Option<String>,
    pub declared_source_revision: Option<String>,
    pub retention_holds: Vec<String>,
    pub resolution: String,
    pub evidence_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ownership {
    pub artifact_id: String,
    pub project_ids: Vec<String>,
    pub declared_owners: Vec<String>,
    pub status: String,
    pub evidence_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentHash {
    pub artifact_id: String,
    pub sha256: String,
    pub bytes: u64,
    pub evidence_id: String,
}

/// A comparison of local observations, never authentication or build verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyCheck {
    pub kind: String,
    pub subject_evidence_id: String,
    pub status: String,
    pub observed_value: Option<String>,
    pub supporting_evidence_ids: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementSubject {
    pub statement_artifact_id: String,
    pub name: String,
    pub declared_sha256: Option<String>,
    pub predicate_type: String,
    pub target_artifact_id: Option<String>,
    pub evidence_id: String,
    pub authentication: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedKey {
    pub key_id: String,
    pub public_key_hex: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementAuthentication {
    pub statement_artifact_id: String,
    pub status: String,
    pub accepted_key_ids: Vec<String>,
    pub payload_sha256: String,
    pub evidence_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoLockfileSelection {
    pub manifest_path: String,
    pub lockfile_path: String,
}
