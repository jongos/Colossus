#![cfg(windows)]
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use colossus_audit::{
    audit,
    authentication::{self, inspect, pae, parse_key, PAYLOAD_TYPE},
    model::TrustedKey,
    Options,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/dsse-ed25519.json")).unwrap()
}
fn pin() -> TrustedKey {
    parse_key(&format!(
        "caller-approved={}",
        fixture()["public_key_hex"].as_str().unwrap()
    ))
    .unwrap()
}
fn envelope() -> Value {
    fixture()["envelope"].clone()
}
fn bytes(e: &Value) -> Vec<u8> {
    serde_json::to_vec(e).unwrap()
}
fn wrong_pin() -> TrustedKey {
    let key = SigningKey::from_bytes(&[42; 32]);
    parse_key(&format!(
        "other={}",
        key.verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .unwrap()
}
fn setup() -> (PathBuf, Options) {
    let p = std::env::temp_dir().join(format!(
        "colossus-m5-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&p).unwrap();
    fs::write(p.join("artifact.bin"), b"abc").unwrap();
    fs::write(p.join("envelope.json"), bytes(&envelope())).unwrap();
    let mut o = Options::new(vec![p.clone()]);
    o.statement_files.push(p.join("envelope.json"));
    o.hash_files.push(p.join("artifact.bin"));
    o.trusted_keys.push(pin());
    (p, o)
}
#[test]
fn pae_matches_published_dsse_example() {
    assert_eq!(
        pae("http://example.com/HelloWorld", b"hello world"),
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    );
}
#[test]
fn independently_generated_python_signature_verifies() {
    let result = inspect(&bytes(&envelope()), &[pin()], &|| false).unwrap();
    assert_eq!(result.status, "verified_with_supplied_key");
    assert_eq!(result.accepted_key_ids, vec!["caller-approved"]);
    assert_eq!(
        result.payload,
        STANDARD
            .decode(envelope()["payload"].as_str().unwrap())
            .unwrap()
    );
}
#[test]
fn no_key_means_no_trust() {
    let result = inspect(&bytes(&envelope()), &[], &|| false).unwrap();
    assert_eq!(result.status, "no_trusted_keys");
    assert!(result.accepted_key_ids.is_empty());
}
#[test]
fn wrong_key_never_verifies() {
    assert_eq!(
        inspect(&bytes(&envelope()), &[wrong_pin()], &|| false)
            .unwrap()
            .status,
        "not_verified_with_supplied_keys"
    );
}
#[test]
fn byte_tampering_breaks_signature_even_when_json_still_parses() {
    let mut e = envelope();
    let mut payload = STANDARD.decode(e["payload"].as_str().unwrap()).unwrap();
    payload.push(b' ');
    e["payload"] = json!(STANDARD.encode(payload));
    assert_eq!(
        inspect(&bytes(&e), &[pin()], &|| false).unwrap().status,
        "not_verified_with_supplied_keys"
    );
}
#[test]
fn wrong_payload_type_is_rejected() {
    let mut e = envelope();
    e["payloadType"] = json!("application/json");
    assert!(inspect(&bytes(&e), &[pin()], &|| false).is_err());
}
#[test]
fn signature_over_raw_body_is_not_a_dsse_signature() {
    let mut e = envelope();
    let key = SigningKey::from_bytes(&std::array::from_fn(|i| i as u8));
    let body = STANDARD.decode(e["payload"].as_str().unwrap()).unwrap();
    e["signatures"][0]["sig"] = json!(STANDARD.encode(key.sign(&body).to_bytes()));
    assert_eq!(
        inspect(&bytes(&e), &[pin()], &|| false).unwrap().status,
        "not_verified_with_supplied_keys"
    );
}
#[test]
fn key_hints_cannot_substitute_keys_or_reported_identity() {
    let mut e = envelope();
    e["signatures"][0]["keyid"] = json!("trusted-production-admin");
    e["publicKey"] = json!(fixture()["public_key_hex"]);
    let result = inspect(&bytes(&e), &[pin()], &|| false).unwrap();
    assert_eq!(result.accepted_key_ids, vec!["caller-approved"]);
    assert_eq!(
        inspect(&bytes(&e), &[], &|| false).unwrap().status,
        "no_trusted_keys"
    );
    e["signatures"][0].as_object_mut().unwrap().remove("keyid");
    assert_eq!(
        inspect(&bytes(&e), &[pin()], &|| false).unwrap().status,
        "verified_with_supplied_key"
    );
}
#[test]
fn standard_and_urlsafe_base64_with_optional_padding_work() {
    let original = envelope();
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        let mut e = original.clone();
        for path in ["/payload", "/signatures/0/sig"] {
            let raw = STANDARD
                .decode(original.pointer(path).unwrap().as_str().unwrap())
                .unwrap();
            *e.pointer_mut(path).unwrap() = json!(engine.encode(raw));
        }
        assert_eq!(
            inspect(&bytes(&e), &[pin()], &|| false).unwrap().status,
            "verified_with_supplied_key"
        );
    }
}
#[test]
fn duplicate_recognized_envelope_fields_are_rejected() {
    let e = envelope();
    let raw = format!(
        "{{\"payload\":\"bad\",{}",
        &serde_json::to_string(&e).unwrap()[1..]
    );
    assert!(inspect(raw.as_bytes(), &[pin()], &|| false).is_err());
}
#[test]
fn invalid_base64_and_wrong_signature_lengths_are_rejected() {
    for sig in [
        "***".to_string(),
        STANDARD.encode([0u8; 63]),
        STANDARD.encode([0u8; 65]),
    ] {
        let mut e = envelope();
        e["signatures"][0]["sig"] = json!(sig);
        assert!(inspect(&bytes(&e), &[pin()], &|| false).is_err());
    }
}
#[test]
fn weak_and_malformed_public_keys_are_rejected() {
    for value in [
        "x=invalid".to_string(),
        format!("x={}", "0".repeat(64)),
        format!("x=01{}", "00".repeat(31)),
        format!(
            "bad label={}",
            fixture()["public_key_hex"].as_str().unwrap()
        ),
    ] {
        assert!(parse_key(&value).is_err());
    }
}
#[test]
fn duplicate_pins_and_excessive_policy_are_rejected() {
    assert!(authentication::validate_keys(&[pin(), pin()]).is_err());
    let mut alias = pin();
    alias.key_id = "alias".into();
    assert!(authentication::validate_keys(&[pin(), alias]).is_err());
    assert!(authentication::validate_keys(&vec![pin(); 17]).is_err());
}
#[test]
fn signature_count_is_bounded() {
    for count in [0, 17] {
        let mut e = envelope();
        e["signatures"] = json!(vec![e["signatures"][0].clone(); count]);
        assert!(inspect(&bytes(&e), &[pin()], &|| false).is_err());
    }
}
#[test]
fn any_one_supplied_key_policy_reports_only_verifying_keys() {
    let result = inspect(&bytes(&envelope()), &[wrong_pin(), pin()], &|| false).unwrap();
    assert_eq!(result.accepted_key_ids, vec!["caller-approved"]);
}
#[test]
fn cancellation_does_not_return_partial_authentication() {
    let calls = AtomicUsize::new(0);
    let result = inspect(&bytes(&envelope()), &[pin(), wrong_pin()], &|| {
        calls.fetch_add(1, Ordering::Relaxed) >= 3
    });
    assert!(result.is_err());
    assert!(inspect(&bytes(&envelope()), &[pin()], &|| true).is_err());
}
#[test]
fn verified_signature_does_not_make_wrong_artifact_digest_match() {
    let (p, o) = setup();
    fs::write(p.join("artifact.bin"), b"different").unwrap();
    let r = audit(&o).unwrap();
    assert_eq!(
        r.provenance.statement_authentications[0].status,
        "verified_with_supplied_key"
    );
    assert_eq!(
        r.provenance.statement_subjects[0].authentication,
        "verified_with_supplied_key"
    );
    assert_eq!(
        r.provenance
            .checks
            .iter()
            .find(|c| c.kind == "statement_digest")
            .unwrap()
            .status,
        "mismatch"
    );
    assert!(r
        .candidates
        .iter()
        .all(|c| c.proposed_operation == "investigate"));
}
#[test]
fn signed_scan_preserves_sources_and_records_caller_policy() {
    let (p, o) = setup();
    let file = p.join("envelope.json");
    let before = fs::read(&file).unwrap();
    let modified = fs::metadata(&file).unwrap().modified().unwrap();
    let r = audit(&o).unwrap();
    assert_eq!(r.provenance.trusted_keys[0].key_id, "caller-approved");
    assert_eq!(
        r.provenance.statement_authentications[0].status,
        "verified_with_supplied_key"
    );
    assert_eq!(fs::read(file).unwrap(), before);
    assert_eq!(
        fs::metadata(p.join("envelope.json"))
            .unwrap()
            .modified()
            .unwrap(),
        modified
    );
}
#[test]
fn signed_invalid_statement_payload_produces_no_accepted_claims() {
    let (p, o) = setup();
    let key = SigningKey::from_bytes(&std::array::from_fn(|i| i as u8));
    let payload = b"{}";
    let mut e = envelope();
    e["payload"] = json!(STANDARD.encode(payload));
    e["signatures"][0]["sig"] =
        json!(STANDARD.encode(key.sign(&pae(PAYLOAD_TYPE, payload)).to_bytes()));
    fs::write(p.join("envelope.json"), bytes(&e)).unwrap();
    let r = audit(&o).unwrap();
    assert!(!r.complete);
    assert!(r.provenance.statement_subjects.is_empty());
    assert!(r.provenance.statement_authentications.is_empty());
}
#[test]
fn raw_statement_is_never_authenticated_by_presence_of_keys() {
    let (p, o) = setup();
    let raw = STANDARD
        .decode(envelope()["payload"].as_str().unwrap())
        .unwrap();
    fs::write(p.join("envelope.json"), raw).unwrap();
    let r = audit(&o).unwrap();
    assert_eq!(
        r.provenance.statement_authentications[0].status,
        "unverified"
    );
}
#[test]
fn key_policy_without_statement_selection_is_rejected_before_scan() {
    let (_, mut o) = setup();
    o.statement_files.clear();
    assert!(audit(&o).is_err());
}

#[test]
fn duplicate_signatures_do_not_multiply_accepted_keys() {
    let mut e = envelope();
    let duplicate = e["signatures"][0].clone();
    e["signatures"].as_array_mut().unwrap().push(duplicate);
    let result = inspect(&bytes(&e), &[pin()], &|| false).unwrap();
    assert_eq!(result.accepted_key_ids, vec!["caller-approved"]);
}
#[test]
fn valid_signature_can_coexist_with_a_nonverifying_signature() {
    let mut e = envelope();
    e["signatures"]
        .as_array_mut()
        .unwrap()
        .push(json!({"sig":STANDARD.encode([0u8;64])}));
    assert_eq!(
        inspect(&bytes(&e), &[pin()], &|| false).unwrap().status,
        "verified_with_supplied_key"
    );
}
#[test]
fn signature_result_reaches_candidates_without_removing_other_blockers() {
    let (p, mut o) = setup();
    fs::create_dir(p.join("build")).unwrap();
    fs::write(p.join("package.json"), b"{}").unwrap();
    for name in ["envelope.json", "artifact.bin"] {
        fs::rename(p.join(name), p.join("build").join(name)).unwrap();
    }
    o.statement_files = vec![p.join("build/envelope.json")];
    o.hash_files = vec![p.join("build/artifact.bin")];
    o.trusted_keys = vec![wrong_pin()];
    let r = audit(&o).unwrap();
    assert!(r.candidates[0]
        .blockers
        .iter()
        .any(|b| b.contains("statement signature: not_verified_with_supplied_keys")));
    o.trusted_keys = vec![pin()];
    let r = audit(&o).unwrap();
    assert_eq!(
        r.provenance.statement_authentications[0].status,
        "verified_with_supplied_key"
    );
    assert!(!r.candidates[0].blockers.is_empty());
    assert_eq!(r.candidates[0].proposed_operation, "investigate");
    assert!(r
        .plan
        .protected_paths
        .contains(&p.join("build").to_string_lossy().into_owned()));
}
