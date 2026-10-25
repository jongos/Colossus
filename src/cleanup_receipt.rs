//! Read-only receipt diagnostics. Journal claims are not filesystem verification or approval.
use crate::{cleanup, platform};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
    path::Path,
};

const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVENTS: usize = 130; // preflight + 64 intent/outcome pairs + finish

fn error(message: &str) -> io::Error {
    io::Error::other(message)
}

#[derive(Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    ApprovedPreflight {
        schema_version: String,
        plan: Box<cleanup::Plan>,
        free_bytes_before: Option<u64>,
        limitations: Vec<String>,
    },
    DeleteIntent {
        path: String,
        identity: String,
    },
    Removed {
        path: String,
        identity: String,
    },
    OutcomeUnconfirmed {
        path: String,
        identity: String,
    },
    Failed {
        path: String,
        error: String,
    },
    Finished {
        complete: bool,
        removed_files: usize,
        planned_files: usize,
        selected_removed_allocation_bytes: u64,
        free_bytes_after: Option<u64>,
        observed_free_space_delta_bytes: Option<serde_json::Number>,
        causal_reclaimed_bytes: (),
        cancelled: bool,
    },
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetState {
    Unattempted,
    IntentUnresolved,
    ReportedRemoved,
    ReportedFailed,
    OutcomeUnconfirmed,
}

#[derive(Debug, Serialize)]
pub struct TargetReview {
    pub path: String,
    pub identity: String,
    pub state: TargetState,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    CompleteReported,
    PartialReported,
    Interrupted,
}

#[derive(Debug, Serialize)]
pub struct Review {
    pub schema_version: &'static str,
    pub plan_digest: String,
    pub completion: Completion,
    pub targets: Vec<TargetReview>,
    pub complete_events: usize,
    pub trailing_partial_bytes: usize,
    pub reported_removed_files: usize,
    pub reported_removed_allocation_bytes: u64,
    pub free_bytes_before: Option<u64>,
    pub free_bytes_after: Option<u64>,
    pub observed_free_space_delta_bytes: Option<i128>,
    pub cancelled_reported: Option<bool>,
    pub limitations: Vec<&'static str>,
}

/// Analyze bounded bytes without opening or modifying any path named inside them.
pub fn analyze(bytes: &[u8]) -> io::Result<Review> {
    if bytes.len() > MAX_BYTES {
        return Err(error("receipt exceeds 2 MiB limit"));
    }
    let end = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |n| n + 1);
    let trailing = bytes.len() - end;
    let mut events = Vec::new();
    for line in bytes[..end].split_inclusive(|b| *b == b'\n') {
        if events.len() >= MAX_EVENTS {
            return Err(error("too many receipt events"));
        }
        let event: Event = serde_json::from_slice(line)?;
        // Optional measurements must be explicitly null when unavailable, never omitted.
        let value: serde_json::Value = serde_json::from_slice(line)?;
        let required: &[&str] = match &event {
            Event::ApprovedPreflight { .. } => &["free_bytes_before"],
            Event::Finished { .. } => &[
                "free_bytes_after",
                "observed_free_space_delta_bytes",
                "causal_reclaimed_bytes",
            ],
            _ => &[],
        };
        if required.iter().any(|key| value.get(key).is_none()) {
            return Err(error("missing receipt measurement field"));
        }
        events.push(event);
    }
    let count = events.len();
    let mut events = events.into_iter();
    let Some(Event::ApprovedPreflight {
        schema_version,
        plan,
        free_bytes_before,
        limitations,
    }) = events.next()
    else {
        return Err(error("receipt lacks a complete initial preflight event"));
    };
    if schema_version != "cleanup-receipt-1" {
        return Err(error("unsupported receipt schema"));
    }
    cleanup::shape(&plan)?;
    if cleanup::digest(&plan)? != plan.digest {
        return Err(error("embedded plan digest mismatch"));
    }
    if limitations.len() > 64 || limitations.iter().any(|s| s.len() > 4096) {
        return Err(error("oversized receipt limitations"));
    }
    let mut review = Review {
        schema_version: "cleanup-receipt-review-1", plan_digest: plan.digest.clone(),
        completion: Completion::Interrupted,
        targets: plan.targets.iter().map(|t| TargetReview { path: t.path.clone(), identity: t.identity.clone(), state: TargetState::Unattempted }).collect(),
        complete_events: count, trailing_partial_bytes: trailing,
        reported_removed_files: 0, reported_removed_allocation_bytes: 0,
        free_bytes_before, free_bytes_after: None, observed_free_space_delta_bytes: None,
        cancelled_reported: None,
        limitations: vec!["Receipt claims are unauthenticated; consistency does not prove human approval, deletion, preservation or current filesystem state.",
            "No referenced target was opened or changed. No retry, resume or deletion is authorized by this review.",
            "An unresolved intent may have taken effect; reconcile it manually before proposing a fresh plan.",
            "Free-space observations include concurrent activity; exact causal reclaimed bytes remain unknown."],
    };
    let mut cursor = 0usize;
    let mut pending = false;
    let mut stopped = false;
    let mut finished = false;
    for event in events {
        if finished {
            return Err(error("event after finished marker"));
        }
        let is_removed = matches!(&event, Event::Removed { .. });
        match event {
            Event::ApprovedPreflight { .. } => return Err(error("duplicate preflight event")),
            Event::DeleteIntent { path, identity } => {
                if pending || stopped {
                    return Err(error("unexpected deletion intent"));
                }
                let target = plan
                    .targets
                    .get(cursor)
                    .ok_or_else(|| error("intent exceeds plan"))?;
                if path != target.path || identity != target.identity {
                    return Err(error("intent differs from exact ordered plan"));
                }
                review.targets[cursor].state = TargetState::IntentUnresolved;
                pending = true;
            }
            Event::Removed { path, identity } | Event::OutcomeUnconfirmed { path, identity } => {
                if !pending {
                    return Err(error("outcome without matching intent"));
                }
                let target = &plan.targets[cursor];
                if path != target.path || identity != target.identity {
                    return Err(error("outcome differs from pending target"));
                }
                // Resolve the variant without re-reading paths or touching the filesystem.
                let removed = is_removed;
                if removed {
                    review.targets[cursor].state = TargetState::ReportedRemoved;
                    review.reported_removed_files += 1;
                    review.reported_removed_allocation_bytes = review
                        .reported_removed_allocation_bytes
                        .checked_add(target.allocated)
                        .ok_or_else(|| error("allocation overflow"))?;
                } else {
                    review.targets[cursor].state = TargetState::OutcomeUnconfirmed;
                    stopped = true;
                }
                cursor += 1;
                pending = false;
            }
            Event::Failed {
                path,
                error: message,
            } => {
                if !pending || path != plan.targets[cursor].path || message.len() > 4096 {
                    return Err(error("invalid failure outcome"));
                }
                review.targets[cursor].state = TargetState::ReportedFailed;
                cursor += 1;
                pending = false;
                stopped = true;
            }
            Event::Finished {
                complete,
                removed_files,
                planned_files,
                selected_removed_allocation_bytes,
                free_bytes_after,
                observed_free_space_delta_bytes,
                causal_reclaimed_bytes: (),
                cancelled,
            } => {
                if pending {
                    return Err(error("finished marker leaves an unresolved intent"));
                }
                let all_removed = review.reported_removed_files == plan.targets.len();
                if complete != all_removed
                    || (!complete && !stopped && !cancelled)
                    || removed_files != review.reported_removed_files
                    || planned_files != plan.targets.len()
                    || selected_removed_allocation_bytes != review.reported_removed_allocation_bytes
                {
                    return Err(error(
                        "finished counters or completion conflict with events",
                    ));
                }
                let delta = free_bytes_before
                    .zip(free_bytes_after)
                    .map(|(b, a)| i128::from(a) - i128::from(b));
                let observed = observed_free_space_delta_bytes.map(|n| {
                    n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from))
                        .ok_or_else(|| error("free-space delta must be an exactly represented integer"))
                }).transpose()?;
                if delta != observed {
                    return Err(error("free-space arithmetic mismatch"));
                }
                review.completion = if complete {
                    Completion::CompleteReported
                } else {
                    Completion::PartialReported
                };
                review.free_bytes_after = free_bytes_after;
                review.observed_free_space_delta_bytes = delta;
                review.cancelled_reported = Some(cancelled);
                finished = true;
            }
        }
    }
    if finished && trailing != 0 {
        return Err(error("trailing bytes after finished marker"));
    }
    Ok(review)
}

/// Pin the explicitly selected receipt and take a bounded, deny-write snapshot.
pub fn load(path: &Path) -> io::Result<Review> {
    let pinned = platform::pin(path)?;
    if pinned.stat.directory || pinned.stat.logical > MAX_BYTES as u64 {
        return Err(error("invalid or oversized receipt"));
    }
    let file = platform::open(&pinned.path, true)?;
    let before = platform::stat(&file)?;
    if before != pinned.stat {
        return Err(error("receipt changed while opening"));
    }
    let mut bytes = Vec::new();
    (&file).take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if platform::stat(&file)? != before || bytes.len() as u64 != before.logical {
        return Err(error("receipt changed while reading"));
    }
    analyze(&bytes)
}
