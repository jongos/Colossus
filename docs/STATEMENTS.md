# Offline statements and Cargo version checks

Version 0.4.0 adds an explicit offline evidence adapter. The auditor does not fetch, sign, execute builds or evaluate predicate commands. Version 0.5.0 adds optional [DSSE signature verification](AUTHENTICATION.md) with explicitly supplied public keys. No trust root, trusted-builder policy or authenticated provenance is established.

## Select a statement and target

```powershell
colossus audit --root C:\dev\example --statement-file C:\dev\example\statement.json --hash-file C:\dev\example\build\output.bin --format json
```

Repeat `--statement-file` for additional selected files. This option works without `--provenance`; manifest collection still requires that flag. Each statement must already be an exact inventoried regular file. Statements are not discovered by filename or fetched from URLs. Selecting a statement does not select its subject files for hashing. Equal-content aliases are not substituted for the explicitly named subject.

The parser supports a strict subset of the [in-toto Statement v1 format](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "build/output.bin",
      "digest": {
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {}
}
```

The example digest is SHA256 of the three bytes `abc`; it is not a build attestation. Predicate contents are parsed as an opaque JSON object and are not copied into report claims or executed. The predicate type is only an untrusted label. A type label does not certify conformance to the named predicate specification.

This adapter treats supported subject names as relative file paths beneath the statement directory, using `/` separators. Absolute paths, URLs, `.`/`..` components, backslashes, stream syntax, junctions and targets absent from inventory cannot resolve. General in-toto subject names need not be filesystem paths; unsupported names remain unresolved rather than being guessed.

Top-level fields are exactly `_type`, `subject`, `predicateType` and `predicate`. Subject fields are exactly `name` and `digest`; the only supported digest field is `sha256`. Unknown payload structural fields, unsupported envelopes, duplicate recognized fields, invalid digests and oversized records fail explicitly. Missing/null SHA256 remains unresolved. Extensions and other digest algorithms are unsupported. This is an intentionally narrower reader than a general in-toto verifier.

## Bounds and results

At most 32 distinct selected statement paths are inspected, each at most 1 MiB, with at most 1,024 subjects per statement and 10,000 subjects per run. Names and predicate-type labels are limited to 4,096 bytes. Statement reads share the optional 64 MiB content budget with manifests, explicit hashes and revision checks. Ancestor pinning, regular-file checks, identity/size/time validation and cooperative cancellation apply. Failed reads or unsupported statement structures produce an incomplete report; unsupported subject resolution produces an unresolved check.

`provenance.statement_subjects` retains the claimed name, SHA256, predicate type, statement artifact ID and resolved target ID when available. Raw statements have `authentication: unverified`; supported signed envelopes report the separate signature-verification result. Each `statement_digest` check cites subject evidence, the statement fingerprint and any explicitly observed target hash:

- `consistent`: the claimed SHA256 equals the selected-file observation.
- `mismatch`: the claimed SHA256 differs from that observation.
- `unresolved`: a required digest, resolved target or selected-file hash is absent.

Contradictory claims remain separate. No match removes any blocker. Statement checks for resolved descendant files propagate to directory candidates; this association pass has a 100,000-link limit and reports an explicit gap if exceeded. Always inspect global checks too, including unresolved subjects that cannot be associated with a candidate.

## Cargo checks

With `--provenance`, Cargo path dependencies retain their declared package name and explicit version requirement. Package renames use the `package` field; otherwise the dependency key supplies the declared name. The target's already-read Cargo manifest supplies its declared name and version.

`cargo_package_name` compares the names. `cargo_version_requirement` uses the [Rust semver parser and matching rules](https://docs.rs/semver/1.0.28/semver/struct.VersionReq.html), including prerelease behavior. Missing, malformed, oversized and inherited versions remain unresolved. The original `dependency_manifest` check only establishes manifest presence and ecosystem; its result can be consistent while the separate name/version checks mismatch.

No Cargo invocation or package download occurs during auditing. npm version ranges, inherited workspace resolution, conditional dependencies, lockfile resolution, feature selection, patches and full build compatibility remain outside this adapter. A version match is a comparison of declarations, not a demonstrated successful build.
