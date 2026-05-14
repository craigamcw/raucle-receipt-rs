# raucle-receipt

[![CI](https://github.com/craigamcw/raucle-receipt-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/craigamcw/raucle-receipt-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/raucle-receipt)](https://crates.io/crates/raucle-receipt)
[![Docs.rs](https://img.shields.io/docsrs/raucle-receipt)](https://docs.rs/raucle-receipt)
[![Spec v1](https://img.shields.io/badge/spec-provenance--receipt%2Fv1-blue)](https://raucle.com/spec/provenance/v1)

**Rust reference implementation of the Raucle Provenance Receipt v1 spec** — cryptographic chain-of-custody for AI workflows.

Every step in a multi-agent / multi-tool LLM workflow can emit a signed receipt that composes into a Merkle DAG. Given any output, reconstruct the full causal chain back to the original input and prove nothing in the chain has been tampered with. The LLM-equivalent of [Sigstore](https://www.sigstore.dev/) for software artifacts.

- **Spec**: <https://raucle.com/spec/provenance/v1>
- **Spec version**: `raucle-provenance-receipt/v1`
- **Crypto**: Ed25519 (`ed25519-dalek` 2.x), compact JWS (RFC 7515)
- **Dependencies**: only what Rust requires for Ed25519 + JSON — `ed25519-dalek`, `sha2`, `serde_json`, `base64`, `pkcs8`, `rand_core`. No transitive policy traps.
- **MSRV**: Rust 1.74
- **License**: MIT

## Install

```toml
[dependencies]
raucle-receipt = "0.1"
```

## Quick start

```rust
use raucle_receipt::{AgentIdentity, GenerateOptions, Operation, Receipt, Verifier, hash_text};
use std::collections::HashMap;

// 1. Generate an agent identity (do this once at deploy time)
let identity = AgentIdentity::generate(GenerateOptions {
    agent_id: "agent:customer-support".to_string(),
    allowed_models: vec!["claude-sonnet-4-6".to_string()],
    allowed_tools: vec!["lookup_order".to_string()],
    ttl_seconds: Some(365 * 24 * 60 * 60),
    ..Default::default()
})?;

// 2. Emit a root receipt when untrusted input enters the graph
let mut root = Receipt::new(
    identity.agent_id.clone(),
    identity.key_id().to_string(),
    Operation::UserInput,
    chrono::Utc::now().timestamp(),
);
root.input_hash = hash_text("Please send my last invoice.");
root.taint = vec!["external_user".to_string()];
root.sign(&identity)?;

println!("{}", root.jws);          // compact JWS string
println!("{}", root.receipt_hash); // sha256:...

// 3. Each later step cites parents
let mut model_call = Receipt::new(
    identity.agent_id.clone(),
    identity.key_id().to_string(),
    Operation::ModelCall,
    chrono::Utc::now().timestamp(),
);
model_call.parents = vec![root.receipt_hash.clone()];
model_call.model = "claude-sonnet-4-6".to_string();
model_call.input_hash = hash_text("...");
model_call.output_hash = hash_text("...");
model_call.taint = vec!["external_user".to_string()]; // descendants carry parent taint
model_call.sign(&identity)?;

// 4. Verify chains later
let mut keys = HashMap::new();
keys.insert(identity.key_id().to_string(), identity.public_key_pem().to_string());
let verifier = Verifier::new(keys)?;
// verifier.verify_chain_file("audit.jsonl") -> VerificationReport
# Ok::<(), Box<dyn std::error::Error>>(())
```

## What's verified

Three classes of check, all must pass for `report.valid == true`:

1. **Signature**: every receipt's JWS verifies against its declared `agent_key_id`.
2. **DAG integrity**: every parent referenced by a receipt exists in the chain; receipt hashes match recomputed bytes (catches tampering).
3. **Taint monotonicity**: descendant taint ⊇ union(parent taints), unless a `sanitisation` operation explicitly lists removed tags.

## Receipt format

Compact JWS (`alg=EdDSA`, `typ=provenance-receipt/v1`). The `crit=["raucle/v1"]` header prevents JWT-compatible libraries from silently accepting receipts as bearer tokens.

```
<base64url(header)>.<base64url(payload)>.<base64url(signature)>
```

Payload fields (canonical JSON — sorted keys, no whitespace, UTF-8):

| Field | Description |
|---|---|
| `iss`, `typ`, `iat` | Issuer, receipt-type tag, issue timestamp |
| `agent_id`, `agent_key_id` | Who emitted this step |
| `operation` | One of 8 types: `user_input`, `model_call`, `tool_call`, `retrieval`, `guardrail_scan`, `agent_handoff`, `sanitisation`, `merge` |
| `parents` | Receipt hashes of immediate predecessors (sorted) |
| `taint` | Sorted set of provenance tags for untrusted data |
| `input_hash`, `output_hash` | SHA-256 of step inputs/outputs (`sha256:` + hex). Hashes only — receipts never embed raw content. |
| `model`, `tool`, `corpus` | Operation-specific identifiers |
| `ruleset_hash`, `guardrail_verdict` | Set for `guardrail_scan` operations |
| `tenant` | Optional multi-tenant SaaS label |

A receipt's *own* hash — cited by descendants in `parents` — is `sha256:` + hex of `sha256(compact_jws_string)`. Content-addressed, deterministic.

See the full spec at <https://raucle.com/spec/provenance/v1>.

## Conformance

This crate ships [the official v1 test vectors](./tests/data/test-vectors.json) in its integration test suite. CI runs them on every PR — divergence from the spec is caught immediately.

```bash
cargo test
```

Test output:

```
running 4 tests (conformance.rs)
running 3 tests (round_trip.rs)
running 11 tests (lib unit tests)

test result: ok. 19 passed; 0 failed
```

## Reference implementations

| Language | Repo | Status |
|---|---|---|
| Python | [craigamcw/raucle-detect](https://github.com/craigamcw/raucle-detect) | Canonical |
| TypeScript | [craigamcw/raucle-receipt-ts](https://github.com/craigamcw/raucle-receipt-ts) | v0.1.0 |
| Go | [craigamcw/raucle-receipt-go](https://github.com/craigamcw/raucle-receipt-go) | v0.1.0 |
| Rust | this repo | v0.1.0 |

## Security model

Defends against tampering, forging without the agent's private key, silent taint-laundering, and unauthorised model/tool invocation.

Does NOT defend against compromised private keys, lying agents (mitigation: TEE-attested inference), or replay (mitigation: `iat` + content hashes; window enforcement is the caller's responsibility).

See [§11 Security considerations](https://raucle.com/spec/provenance/v1#11-security-considerations) in the spec for the full threat model.

## License

MIT — see [LICENSE](./LICENSE).
