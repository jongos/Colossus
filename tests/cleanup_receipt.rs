//! Pure synthetic journal fixtures; no delete executor is called.
use colossus_audit::{cleanup::{Plan, Target}, cleanup_receipt::{analyze, Completion, TargetState}};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn plan() -> Plan {
    let mut plan = Plan { schema_version: "cleanup-plan-1".into(), operation: "permanent-delete-files".into(),
        root: "Z:\\synthetic-unopened".into(), root_identity: "root".into(), reason: "synthetic journal only".into(),
        recovery: "no actual files or deletion".into(), targets: (0..2).map(|n| Target {
            path: format!("Z:\\synthetic-unopened\\{n}.bin"), identity: format!("id-{n}"), ancestors: vec!["root".into()],
            bytes: 4, allocated: 4096, modified: 1, sha256: "a".repeat(64),
        }).collect(), digest: String::new() };
    plan.digest = format!("sha256:{:x}", Sha256::digest(serde_json::to_vec(&plan).unwrap()));
    plan
}
fn start() -> Value { json!({"event":"approved_preflight","schema_version":"cleanup-receipt-1","plan":plan(),"free_bytes_before":10000,"limitations":[]}) }
fn event(kind:&str, n:usize) -> Value { let p=plan();json!({"event":kind,"path":p.targets[n].path,"identity":p.targets[n].identity}) }
fn finish(complete:bool, removed:usize, cancelled:bool) -> Value { json!({"event":"finished","complete":complete,"removed_files":removed,"planned_files":2,"selected_removed_allocation_bytes":removed*4096,"free_bytes_after":18000,"observed_free_space_delta_bytes":8000,"causal_reclaimed_bytes":null,"cancelled":cancelled}) }
fn bytes(rows:&[Value]) -> Vec<u8> { rows.iter().flat_map(|row| {let mut b=serde_json::to_vec(row).unwrap();b.push(b'\n');b}).collect() }
fn complete() -> Vec<Value> { vec![start(),event("delete_intent",0),event("removed",0),event("delete_intent",1),event("removed",1),finish(true,2,false)] }

#[test] fn complete_claim_is_qualified_and_never_probes_targets() {
    let r=analyze(&bytes(&complete())).unwrap();assert_eq!(r.completion,Completion::CompleteReported);
    assert_eq!(r.reported_removed_files,2);assert_eq!(r.reported_removed_allocation_bytes,8192);
    assert_eq!(r.observed_free_space_delta_bytes,Some(8000));assert_eq!(r.targets[0].state,TargetState::ReportedRemoved);
    assert!(r.limitations.iter().any(|s|s.contains("unauthenticated")));
}
#[test] fn preflight_only_is_interrupted_and_unattempted() { let r=analyze(&bytes(&[start()])).unwrap();assert_eq!(r.completion,Completion::Interrupted);assert!(r.targets.iter().all(|t|t.state==TargetState::Unattempted)); }
#[test] fn intent_without_outcome_remains_unresolved() { let r=analyze(&bytes(&[start(),event("delete_intent",0)])).unwrap();assert_eq!(r.targets[0].state,TargetState::IntentUnresolved);assert_eq!(r.reported_removed_files,0); }
#[test] fn partial_last_write_preserves_only_complete_events() { let mut b=bytes(&[start(),event("delete_intent",0)]);b.extend_from_slice(b"{\"event\":\"removed\"");let r=analyze(&b).unwrap();assert!(r.trailing_partial_bytes>0);assert_eq!(r.targets[0].state,TargetState::IntentUnresolved); }
#[test] fn finish_without_newline_is_not_completion() { let mut b=bytes(&complete());b.pop();let r=analyze(&b).unwrap();assert_eq!(r.completion,Completion::Interrupted);assert_eq!(r.reported_removed_files,2); }
#[test] fn cancelled_before_first_intent_is_partial() { let r=analyze(&bytes(&[start(),finish(false,0,true)])).unwrap();assert_eq!(r.completion,Completion::PartialReported);assert_eq!(r.cancelled_reported,Some(true)); }
#[test] fn failure_stops_and_preserves_remaining_unattempted() { let failed=json!({"event":"failed","path":plan().targets[0].path,"error":"synthetic denial"});let r=analyze(&bytes(&[start(),event("delete_intent",0),failed,finish(false,0,false)])).unwrap();assert_eq!(r.targets[0].state,TargetState::ReportedFailed);assert_eq!(r.targets[1].state,TargetState::Unattempted); }
#[test] fn unconfirmed_outcome_is_not_removed() { let r=analyze(&bytes(&[start(),event("delete_intent",0),event("outcome_unconfirmed",0),finish(false,0,false)])).unwrap();assert_eq!(r.targets[0].state,TargetState::OutcomeUnconfirmed);assert_eq!(r.reported_removed_allocation_bytes,0); }
#[test] fn tampered_plan_is_rejected() { let mut s=start();s["plan"]["reason"]=json!("changed");assert!(analyze(&bytes(&[s])).is_err()); }
#[test] fn foreign_identity_is_rejected() { let mut e=event("delete_intent",0);e["identity"]=json!("foreign");assert!(analyze(&bytes(&[start(),e])).is_err()); }
#[test] fn reordered_targets_are_rejected() { assert!(analyze(&bytes(&[start(),event("delete_intent",1)])).is_err()); }
#[test] fn outcome_without_intent_is_rejected() { assert!(analyze(&bytes(&[start(),event("removed",0)])).is_err()); }
#[test] fn duplicate_intent_is_rejected() { assert!(analyze(&bytes(&[start(),event("delete_intent",0),event("delete_intent",0)])).is_err()); }
#[test] fn mismatched_outcome_is_rejected() { assert!(analyze(&bytes(&[start(),event("delete_intent",0),event("removed",1)])).is_err()); }
#[test] fn counters_must_match_events() { for key in ["removed_files","planned_files","selected_removed_allocation_bytes"] { let mut rows=complete();rows.last_mut().unwrap()[key]=json!(99);assert!(analyze(&bytes(&rows)).is_err(),"{key}"); } }
#[test] fn arithmetic_mismatch_is_rejected() { let mut rows=complete();rows.last_mut().unwrap()["observed_free_space_delta_bytes"]=json!(8001);assert!(analyze(&bytes(&rows)).is_err()); }
#[test] fn unavailable_measurement_requires_null_delta() { let mut rows=complete();rows[0]["free_bytes_before"]=Value::Null;assert!(analyze(&bytes(&rows)).is_err());rows.last_mut().unwrap()["observed_free_space_delta_bytes"]=Value::Null;assert_eq!(analyze(&bytes(&rows)).unwrap().observed_free_space_delta_bytes,None); }
#[test] fn missing_nullable_measurement_is_rejected() { let mut rows=complete();rows.last_mut().unwrap().as_object_mut().unwrap().remove("free_bytes_after");assert!(analyze(&bytes(&rows)).is_err()); }
#[test] fn extra_event_after_finish_is_rejected() { let mut rows=complete();rows.push(event("delete_intent",0));assert!(analyze(&bytes(&rows)).is_err()); }
#[test] fn trailing_fragment_after_finish_is_rejected() { let mut b=bytes(&complete());b.push(b'{');assert!(analyze(&b).is_err()); }
#[test] fn unknown_fields_and_events_are_rejected() { let mut e=event("delete_intent",0);e["auto_retry"]=json!(true);assert!(analyze(&bytes(&[start(),e])).is_err());assert!(analyze(&bytes(&[start(),json!({"event":"resume"})])).is_err()); }
#[test] fn malformed_complete_line_is_rejected() { let mut b=bytes(&[start()]);b.extend_from_slice(b"{broken}\n");assert!(analyze(&b).is_err()); }
#[test] fn duplicate_preflight_is_rejected() { assert!(analyze(&bytes(&[start(),start()])).is_err()); }
#[test] fn new_intent_after_failed_outcome_is_rejected() { let failed=json!({"event":"failed","path":plan().targets[0].path,"error":"denied"});assert!(analyze(&bytes(&[start(),event("delete_intent",0),failed,event("delete_intent",1)])).is_err()); }
#[test] fn unresolved_intent_cannot_be_finished() { assert!(analyze(&bytes(&[start(),event("delete_intent",0),finish(false,0,true)])).is_err()); }
#[test] fn complete_without_removals_is_rejected() { assert!(analyze(&bytes(&[start(),finish(true,0,false)])).is_err()); }
#[test] fn size_limit_and_missing_preflight_are_rejected() { assert!(analyze(&vec![b'x';2*1024*1024+1]).is_err());assert!(analyze(b"").is_err());assert!(analyze(&bytes(&[event("removed",0)])).is_err()); }
#[test] fn invented_causal_reclamation_is_rejected() { let mut rows=complete();rows.last_mut().unwrap()["causal_reclaimed_bytes"]=json!(8192);assert!(analyze(&bytes(&rows)).is_err()); }

#[cfg(windows)]
#[test]
fn cli_review_is_read_only_and_strict_about_arguments() {
    use std::{fs,process::Command,time::{SystemTime,UNIX_EPOCH}};
    let dir=std::env::temp_dir().join(format!("colossus-receipt-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir(&dir).unwrap();let path=dir.join("receipt.jsonl");let content=bytes(&complete());fs::write(&path,&content).unwrap();
    let before=fs::metadata(&path).unwrap().modified().unwrap();
    let result=Command::new(env!("CARGO_BIN_EXE_colossus")).args(["cleanup","receipt","--receipt"]).arg(&path).output().unwrap();
    assert!(result.status.success(),"{}",String::from_utf8_lossy(&result.stderr));
    let review:Value=serde_json::from_slice(&result.stdout).unwrap();assert_eq!(review["completion"],"complete_reported");
    assert_eq!(content,fs::read(&path).unwrap());assert_eq!(before,fs::metadata(&path).unwrap().modified().unwrap());
    let bad=Command::new(env!("CARGO_BIN_EXE_colossus")).args(["cleanup","receipt","--receipt"]).arg(&path).args(["--file","extra"]).output().unwrap();assert_eq!(bad.status.code(),Some(1));
    fs::write(&path,bytes(&[start(),event("delete_intent",0)])).unwrap();
    let partial=Command::new(env!("CARGO_BIN_EXE_colossus")).args(["cleanup","receipt","--receipt"]).arg(&path).output().unwrap();assert_eq!(partial.status.code(),Some(2));
    // All fixtures are retained; no temporary-directory cleanup runs.
}

#[cfg(windows)]
#[test]
fn locked_receipt_is_refused() {
    use std::{fs::{self,OpenOptions},os::windows::fs::OpenOptionsExt,time::{SystemTime,UNIX_EPOCH}};
    let path=std::env::temp_dir().join(format!("colossus-locked-receipt-{}-{}.jsonl",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::write(&path,bytes(&complete())).unwrap();let _lock=OpenOptions::new().read(true).share_mode(0).open(&path).unwrap();
    assert!(colossus_audit::cleanup_receipt::load(&path).is_err());
}
