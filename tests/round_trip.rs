//! End-to-end round-trip tests: generate identity, sign receipt, verify it.

use std::collections::HashMap;

use raucle_receipt::{hash_text, AgentIdentity, GenerateOptions, Operation, Receipt, Verifier};

#[test]
fn sign_and_verify_round_trip() {
    let identity = AgentIdentity::generate(GenerateOptions {
        agent_id: "agent:rt".to_string(),
        allowed_models: vec!["m1".to_string()],
        ..Default::default()
    })
    .unwrap();

    let mut r = Receipt::new(
        identity.agent_id.clone(),
        identity.key_id().to_string(),
        Operation::UserInput,
        1_700_000_000,
    );
    r.input_hash = hash_text("hello");
    r.taint = vec!["external_user".to_string()];
    r.sign(&identity).unwrap();

    assert_eq!(r.jws.matches('.').count(), 2);
    assert!(r.receipt_hash.starts_with("sha256:"));

    let mut keys = HashMap::new();
    keys.insert(
        identity.key_id().to_string(),
        identity.public_key_pem().to_string(),
    );
    let verifier = Verifier::new(keys).unwrap();
    assert!(verifier.verify_signature(&r));
}

#[test]
fn tampered_jws_fails_verification() {
    let identity = AgentIdentity::generate(GenerateOptions {
        agent_id: "agent:tamper".to_string(),
        ..Default::default()
    })
    .unwrap();

    let mut r = Receipt::new(
        identity.agent_id.clone(),
        identity.key_id().to_string(),
        Operation::UserInput,
        1_700_000_000,
    );
    r.input_hash = hash_text("hi");
    r.sign(&identity).unwrap();

    // Flip the final char of the payload segment.
    let parts: Vec<&str> = r.jws.split('.').collect();
    let mut new_payload = parts[1].to_string();
    let last_idx = new_payload.len() - 1;
    let last_char = new_payload.chars().last().unwrap();
    new_payload.replace_range(last_idx.., if last_char == 'A' { "B" } else { "A" });
    let tampered_jws = format!("{}.{}.{}", parts[0], new_payload, parts[2]);

    let mut tampered = r.clone();
    tampered.jws = tampered_jws;

    let mut keys = HashMap::new();
    keys.insert(
        identity.key_id().to_string(),
        identity.public_key_pem().to_string(),
    );
    let verifier = Verifier::new(keys).unwrap();
    assert!(!verifier.verify_signature(&tampered));
}

#[test]
fn capability_disallowed_after_allowlist_set() {
    let identity = AgentIdentity::generate(GenerateOptions {
        agent_id: "agent:e".to_string(),
        allowed_models: vec!["claude-sonnet-4-6".to_string()],
        allowed_tools: vec!["send_email".to_string()],
        ..Default::default()
    })
    .unwrap();
    assert!(identity.statement.permits_model("claude-sonnet-4-6"));
    assert!(!identity.statement.permits_model("gpt-4o"));
    assert!(identity.statement.permits_tool("send_email"));
    assert!(!identity.statement.permits_tool("delete_db"));
}
