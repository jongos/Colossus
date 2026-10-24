//! Offline DSSE verification. Trust comes only from caller-supplied public keys.
use crate::model::TrustedKey;
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

pub fn parse_key(value: &str) -> Result<TrustedKey, String> {
    let (label, hex) = value
        .split_once('=')
        .ok_or("trusted key must be LABEL=64_HEX_CHARACTERS")?;
    let key = TrustedKey {
        key_id: label.into(),
        public_key_hex: hex.to_ascii_lowercase(),
    };
    validate_keys(std::slice::from_ref(&key))?;
    Ok(key)
}
fn public_key(hex: &str) -> Result<VerifyingKey, String> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Ed25519 public key must be exactly 64 hexadecimal characters".into());
    }
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| "invalid key hex")?;
    }
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid Ed25519 public key")?;
    if key.is_weak() {
        return Err("weak Ed25519 public keys are not accepted".into());
    }
    Ok(key)
}
pub fn validate_keys(keys: &[TrustedKey]) -> Result<(), String> {
    if keys.len() > 16 {
        return Err("at most 16 trusted public keys may be supplied".into());
    }
    let mut labels = BTreeSet::new();
    let mut values = BTreeSet::new();
    for key in keys {
        if key.key_id.is_empty()
            || key.key_id.len() > 64
            || !key
                .key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(
                "key labels must be 1-64 ASCII letters, digits, dot, underscore or hyphen".into(),
            );
        }
        if !labels.insert(&key.key_id)
            || !values.insert(public_key(&key.public_key_hex)?.to_bytes())
        {
            return Err("duplicate trusted key label or public key".into());
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct Envelope {
    payload: String,
    #[serde(rename = "payloadType")]
    payload_type: String,
    signatures: Vec<EnvelopeSignature>,
}
#[derive(Deserialize)]
struct EnvelopeSignature {
    // This unauthenticated hint is never used as a source of trust or identity.
    #[serde(default)]
    keyid: String,
    sig: String,
}
pub struct Decoded {
    pub payload: Vec<u8>,
    pub status: String,
    pub accepted_key_ids: Vec<String>,
    pub payload_sha256: String,
}
fn decode64(s: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .map_err(|_| "invalid base64 encoding".into())
}
pub fn pae(kind: &str, payload: &[u8]) -> Vec<u8> {
    let mut bytes = format!("DSSEv1 {} {} {} ", kind.len(), kind, payload.len()).into_bytes();
    bytes.extend_from_slice(payload);
    bytes
}
pub fn inspect(
    bytes: &[u8],
    keys: &[TrustedKey],
    stop: &dyn Fn() -> bool,
) -> Result<Decoded, String> {
    if stop() {
        return Err("cancelled before signature inspection".into());
    }
    if bytes.len() > 1024 * 1024 {
        return Err("statement exceeds 1 MiB".into());
    }
    validate_keys(keys)?;
    let shape: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "invalid statement JSON")?;
    if !["payload", "payloadType", "signatures"]
        .iter()
        .any(|k| shape.get(k).is_some())
    {
        return Ok(Decoded {
            payload: bytes.to_vec(),
            status: "unverified".into(),
            accepted_key_ids: vec![],
            payload_sha256: format!("{:x}", Sha256::digest(bytes)),
        });
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|_| "malformed DSSE envelope")?;
    if envelope.payload_type != PAYLOAD_TYPE {
        return Err("unsupported DSSE payload type".into());
    }
    if envelope.signatures.is_empty() || envelope.signatures.len() > 16 {
        return Err("DSSE requires 1-16 signatures".into());
    }
    let payload = decode64(&envelope.payload)?;
    if payload.len() > 1024 * 1024 {
        return Err("decoded payload exceeds 1 MiB".into());
    }
    let message = pae(&envelope.payload_type, &payload);
    let verification_keys: Vec<_> = keys
        .iter()
        .map(|k| public_key(&k.public_key_hex))
        .collect::<Result<_, _>>()?;
    let mut accepted = BTreeSet::new();
    for entry in envelope.signatures {
        if stop() {
            return Err("cancelled during signature inspection".into());
        }
        if entry.keyid.len() > 4096 || entry.sig.len() > 128 {
            return Err("signature or key hint exceeds bounds".into());
        }
        let sig_bytes = decode64(&entry.sig)?;
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| "Ed25519 signature must be 64 bytes")?;
        // Every supplied key is tried: an envelope keyid cannot introduce or
        // substitute a key. Policy is any one valid explicitly supplied key.
        for (pin, key) in keys.iter().zip(&verification_keys) {
            if stop() {
                return Err("cancelled during signature inspection".into());
            }
            if key.verify_strict(&message, &signature).is_ok() {
                accepted.insert(pin.key_id.clone());
            }
        }
    }
    let status = if !accepted.is_empty() {
        "verified_with_supplied_key"
    } else if keys.is_empty() {
        "no_trusted_keys"
    } else {
        "not_verified_with_supplied_keys"
    };
    Ok(Decoded {
        payload_sha256: format!("{:x}", Sha256::digest(&payload)),
        payload,
        status: status.into(),
        accepted_key_ids: accepted.into_iter().collect(),
    })
}
