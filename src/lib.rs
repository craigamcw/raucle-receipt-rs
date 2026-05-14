//! Raucle Provenance Receipt v1 — Rust reference implementation.
//!
//! Cryptographic chain-of-custody for AI workflows. Every step in a
//! multi-agent / multi-tool LLM workflow can emit a signed receipt that
//! composes into a Merkle DAG. Given any output, you can reconstruct the
//! entire causal chain back to the original input and prove nothing in
//! the chain has been tampered with.
//!
//! **Spec**: <https://raucle.com/spec/provenance/v1>
//!
//! # Quick start
//!
//! ```no_run
//! use raucle_receipt::{AgentIdentity, GenerateOptions, Operation, Receipt, hash_text};
//!
//! let identity = AgentIdentity::generate(GenerateOptions {
//!     agent_id: "agent:customer-support".to_string(),
//!     allowed_models: vec!["claude-sonnet-4-6".to_string()],
//!     allowed_tools: vec!["lookup_order".to_string()],
//!     ttl_seconds: Some(365 * 24 * 60 * 60),
//!     ..Default::default()
//! }).unwrap();
//!
//! let mut root = Receipt::new(
//!     identity.agent_id.clone(),
//!     identity.key_id().to_string(),
//!     Operation::UserInput,
//!     1_700_000_000,
//! );
//! root.input_hash = hash_text("Please send my last invoice.");
//! root.taint = vec!["external_user".to_string()];
//! root.sign(&identity).unwrap();
//!
//! println!("{}", root.jws);          // compact JWS string
//! println!("{}", root.receipt_hash); // sha256:...
//! ```

mod b64;
mod canonical;
mod hash;
mod identity;
mod receipt;
mod verifier;

pub use b64::{b64url_decode, b64url_encode};
pub use canonical::{canonicalize, canonicalize_bytes, canonicalize_value};
pub use hash::{hash_obj, hash_text, sha256_hex};
pub use identity::{
    validate_agent_id, AgentIdentity, CapabilityStatement, GenerateOptions, IdentityError,
};
pub use receipt::{Operation, Receipt, ReceiptError, ISSUER, RAUCLE_VERSION_TAG, RECEIPT_TYP};
pub use verifier::{VerificationReport, Verifier, VerifierError};

/// Canonical spec URL. Implementations should reference this in their docs.
pub const SPEC_URL: &str = "https://raucle.com/spec/provenance/v1";

/// Spec version string. Matches the `typ` value in the JWS header.
pub const SPEC_VERSION: &str = "raucle-provenance-receipt/v1";
