//! Spec conformance tests for the Rust reference implementation.
//!
//! Loads the canonical test vectors from the spec and checks that this
//! implementation produces byte-identical receipt hashes and successful
//! signature verification.

use std::collections::HashMap;

use raucle_receipt::{Operation, Receipt, Verifier};
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("data/test-vectors.json");

fn load_vectors() -> Value {
    serde_json::from_str(VECTORS_JSON).expect("vectors file is valid JSON")
}

#[test]
fn vector_file_well_formed() {
    let v = load_vectors();
    assert_eq!(
        v["spec_version"].as_str(),
        Some("raucle-provenance-receipt/v1"),
    );
    assert!(v["vectors"].as_array().unwrap().len() >= 5);
}

#[test]
fn receipt_hash_recomputes_byte_for_byte() {
    let v = load_vectors();
    for vec_entry in v["vectors"].as_array().unwrap() {
        let name = vec_entry["name"].as_str().unwrap();
        let expected_jws = vec_entry["expected_jws"].as_str().unwrap();
        let expected_hash = vec_entry["expected_receipt_hash"].as_str().unwrap();
        let r = Receipt::from_jws(expected_jws)
            .unwrap_or_else(|e| panic!("vector {}: from_jws: {}", name, e));
        assert_eq!(
            r.receipt_hash, expected_hash,
            "vector {} receipt_hash mismatch",
            name,
        );
    }
}

#[test]
fn signatures_verify_against_published_pubkey() {
    let v = load_vectors();
    let key_id = v["agent_key_id"].as_str().unwrap().to_string();
    let pubkey_pem = v["public_key_pem"].as_str().unwrap().to_string();
    let mut keys = HashMap::new();
    keys.insert(key_id, pubkey_pem);
    let verifier = Verifier::new(keys).expect("verifier setup");

    for vec_entry in v["vectors"].as_array().unwrap() {
        let name = vec_entry["name"].as_str().unwrap();
        let expected_jws = vec_entry["expected_jws"].as_str().unwrap();
        let r = Receipt::from_jws(expected_jws).expect("from_jws");
        assert!(
            verifier.verify_signature(&r),
            "vector {} signature did not verify",
            name,
        );
    }
}

#[test]
fn vectors_cover_required_operations() {
    let v = load_vectors();
    let mut seen = std::collections::HashSet::new();
    for vec_entry in v["vectors"].as_array().unwrap() {
        let jws = vec_entry["expected_jws"].as_str().unwrap();
        let r = Receipt::from_jws(jws).unwrap();
        seen.insert(r.operation);
    }
    for op in [
        Operation::UserInput,
        Operation::ModelCall,
        Operation::ToolCall,
        Operation::Sanitisation,
        Operation::GuardrailScan,
    ] {
        assert!(seen.contains(&op), "missing operation {:?}", op);
    }
}
