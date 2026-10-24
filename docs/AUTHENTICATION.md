# Offline signature verification and trust policy

Version 0.5.0 verifies DSSE envelopes using Ed25519 public keys supplied explicitly for that invocation. No key is trusted by default, and the auditor never imports trust from a repository, envelope, certificate, URL or global keyring. No key or policy is installed or persisted outside the requested report.

```powershell
colossus audit --root C:\dev\example --statement-file C:\dev\example\envelope.json --hash-file C:\dev\example\build\output.bin --trusted-key release=PUBLIC_KEY_HEX --format json
```

`PUBLIC_KEY_HEX` means exactly 64 hexadecimal characters encoding a 32-byte Ed25519 **public** key. Obtain approval for the key independently of the material being audited. Labels are caller-chosen identifiers, not authenticated names of people or builders. Labels contain 1–64 ASCII letters, digits, dots, underscores or hyphens. Duplicate labels, duplicate keys, malformed/weak keys and more than 16 supplied keys are rejected before scanning. Supplying keys without selecting a statement is also rejected.

## Supported protocol and fixed policy

The supported payload type is exactly `application/vnd.in-toto+json`. The collector accepts standard or URL-safe base64, padded or unpadded. It implements [DSSE pre-authentication encoding](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md): the signature covers the exact payload bytes and the payload-type bytes with their byte lengths. The same decoded byte buffer is then passed to the strict [statement payload parser](STATEMENTS.md); it is not reserialized before verification or recovered from a second envelope parse.

Verification uses `ed25519-dalek` 3.0.0 `verify_strict`. Every supplied public key is tried against each structurally supported signature. The fixed acceptance policy is **any one supplied key verifies**; configurable thresholds and identity-based trust policies are not implemented. Accepted caller labels are deduplicated. Envelope `keyid` values are unauthenticated hints and do not choose trust or appear as verified identities.

The [DSSE envelope](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md) has `payload`, `payloadType` and `signatures` fields. Signature entries have `sig` and an optional `keyid`. Extra envelope fields are ignored as specified by DSSE and never supply keys. Duplicate recognized JSON fields, malformed base64, unsupported payload types and wrong signature lengths fail explicitly. A malformed entry rejects the envelope; a well-formed signature that does not verify can coexist with another signature that satisfies the any-one policy.

The existing 1 MiB selected-file limit includes envelope encoding overhead. There are at most 16 signatures per envelope, each a 64-byte Ed25519 signature; key hints are limited to 4,096 bytes. With at most 32 selected statements and 16 keys, verification work is bounded. Cancellation is checked between signature/key attempts. Raw statements are still supported and remain unverified even when keys are supplied.

## Reading results

`provenance.trusted_keys` records the caller-supplied public keys and labels. `statement_authentications` records the source artifact, payload SHA256, authentication evidence ID and accepted caller labels. Subject records repeat the corresponding status:

| Status | Meaning |
| --- | --- |
| `unverified` | Raw statement; no signature was verified. |
| `no_trusted_keys` | Supported envelope, but no public key was supplied. |
| `not_verified_with_supplied_keys` | None of the supplied public keys verified a signature. This does not identify whether the cause is a different signer or tampering. |
| `verified_with_supplied_key` | At least one supplied public key verified the DSSE signature over these exact payload bytes and type. |

Successful signature verification does not validate the predicate, real-world signer identity, key ownership, key age or revocation status, freshness, build execution, source inputs, artifact recovery or disposability. There is no certificate/transparency-log check or network access. Replay and expired-but-cryptographically-valid statements are not detected. The test key in the repository is a publicly reproducible synthetic fixture and must not be used as production trust.

Read `statement_digest` separately: a verified signature can accompany a mismatching local file, and an unverified statement can happen to match the local file. Both results and their evidence IDs matter. Nonverified signature results propagate as blockers to associated directory candidates. Verified signatures remove no existing blocker or protection.

An exit-0 report describes completed collection, not a successful authentication decision. Unsupported structures/read failures create coverage gaps, while an observed signature failure or lack of trust can appear in a complete report. A cryptographically valid payload that fails the supported statement schema produces a gap and no accepted subject/authentication record.

The JSON validator checks record structure, reference consistency and agreement between recorded fields. It does not independently reverify signatures from a report: the report contains fingerprints and observations, not the original envelope bytes. A report digest detects changes but is neither a signature nor authorization.
