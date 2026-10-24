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
    pub issues: Vec<Issue>,
    pub totals: Totals,
    pub plan: Plan,
    pub limitations: Vec<String>,
}
