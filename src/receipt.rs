//! Receipts: the core artifact of the Raucle Provenance Receipt v1 spec.

use serde_json::{json, Value};

use crate::b64::{b64url_decode, b64url_encode};
use crate::canonical::canonicalize_value;
use crate::hash::sha256_hex;
use crate::identity::AgentIdentity;

/// `typ` value in the JOSE header and payload.
pub const RECEIPT_TYP: &str = "provenance-receipt/v1";

/// Required entry in the JWS `crit` array.
pub const RAUCLE_VERSION_TAG: &str = "raucle/v1";

/// `iss` value emitted by this implementation.
pub const ISSUER: &str = "raucle-detect/provenance";

/// Errors raised by receipt operations.
#[derive(Debug)]
pub enum ReceiptError {
    Malformed(String),
    DecodeBase64(String),
    DecodeJson(String),
    UnknownOperation(String),
    Sign(String),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed receipt: {}", m),
            Self::DecodeBase64(e) => write!(f, "base64 decode error: {}", e),
            Self::DecodeJson(e) => write!(f, "JSON decode error: {}", e),
            Self::UnknownOperation(op) => write!(f, "unknown operation: {:?}", op),
            Self::Sign(e) => write!(f, "sign error: {}", e),
        }
    }
}

impl std::error::Error for ReceiptError {}

/// One of the eight operation types defined in spec v1 §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    UserInput,
    ModelCall,
    ToolCall,
    Retrieval,
    GuardrailScan,
    AgentHandoff,
    Sanitisation,
    Merge,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserInput => "user_input",
            Self::ModelCall => "model_call",
            Self::ToolCall => "tool_call",
            Self::Retrieval => "retrieval",
            Self::GuardrailScan => "guardrail_scan",
            Self::AgentHandoff => "agent_handoff",
            Self::Sanitisation => "sanitisation",
            Self::Merge => "merge",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "user_input" => Self::UserInput,
            "model_call" => Self::ModelCall,
            "tool_call" => Self::ToolCall,
            "retrieval" => Self::Retrieval,
            "guardrail_scan" => Self::GuardrailScan,
            "agent_handoff" => Self::AgentHandoff,
            "sanitisation" => Self::Sanitisation,
            "merge" => Self::Merge,
            _ => return None,
        })
    }
}

/// A Raucle Provenance Receipt v1.
#[derive(Debug, Clone)]
pub struct Receipt {
    pub agent_id: String,
    pub agent_key_id: String,
    pub operation: Operation,
    pub parents: Vec<String>,
    pub input_hash: String,
    pub output_hash: String,
    pub model: String,
    pub tool: String,
    pub corpus: String,
    pub ruleset_hash: String,
    pub guardrail_verdict: String,
    pub taint: Vec<String>,
    pub tenant: Option<String>,
    pub issued_at: i64,

    /// Populated after [`Receipt::sign`] or [`Receipt::from_jws`].
    pub jws: String,
    pub receipt_hash: String,
}

impl Receipt {
    /// Build a minimally-populated receipt. Set per-operation fields
    /// directly on the returned value before calling [`sign`].
    pub fn new(
        agent_id: String,
        agent_key_id: String,
        operation: Operation,
        issued_at: i64,
    ) -> Self {
        Self {
            agent_id,
            agent_key_id,
            operation,
            parents: Vec::new(),
            input_hash: String::new(),
            output_hash: String::new(),
            model: String::new(),
            tool: String::new(),
            corpus: String::new(),
            ruleset_hash: String::new(),
            guardrail_verdict: String::new(),
            taint: Vec::new(),
            tenant: None,
            issued_at,
            jws: String::new(),
            receipt_hash: String::new(),
        }
    }

    /// Build the canonical signed-payload value per spec §4.2.
    pub fn payload(&self) -> Value {
        let mut parents = self.parents.clone();
        parents.sort();
        let mut taint = self.taint.clone();
        taint.sort();
        let mut p = json!({
            "iss": ISSUER,
            "typ": RECEIPT_TYP,
            "iat": self.issued_at,
            "agent_id": self.agent_id,
            "agent_key_id": self.agent_key_id,
            "operation": self.operation.as_str(),
            "parents": parents,
            "taint": taint,
        });
        let obj = p.as_object_mut().expect("payload is object");
        if !self.input_hash.is_empty() {
            obj.insert("input_hash".to_string(), json!(self.input_hash));
        }
        if !self.output_hash.is_empty() {
            obj.insert("output_hash".to_string(), json!(self.output_hash));
        }
        if !self.model.is_empty() {
            obj.insert("model".to_string(), json!(self.model));
        }
        if !self.tool.is_empty() {
            obj.insert("tool".to_string(), json!(self.tool));
        }
        if !self.corpus.is_empty() {
            obj.insert("corpus".to_string(), json!(self.corpus));
        }
        if !self.ruleset_hash.is_empty() {
            obj.insert("ruleset_hash".to_string(), json!(self.ruleset_hash));
        }
        if !self.guardrail_verdict.is_empty() {
            obj.insert(
                "guardrail_verdict".to_string(),
                json!(self.guardrail_verdict),
            );
        }
        if let Some(ref t) = self.tenant {
            obj.insert("tenant".to_string(), json!(t));
        }
        p
    }

    /// Sign with *identity* and populate `jws` + `receipt_hash`. Returns
    /// the compact JWS string.
    pub fn sign(&mut self, identity: &AgentIdentity) -> Result<&str, ReceiptError> {
        let header = json!({
            "alg": "EdDSA",
            "typ": RECEIPT_TYP,
            "kid": identity.key_id(),
            "crit": [RAUCLE_VERSION_TAG],
            RAUCLE_VERSION_TAG: "provenance",
        });
        let header_b64 = b64url_encode(canonicalize_value(&header).as_bytes());
        let payload_b64 = b64url_encode(canonicalize_value(&self.payload()).as_bytes());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = identity.sign(signing_input.as_bytes());
        self.jws = format!("{}.{}", signing_input, b64url_encode(&sig));
        self.receipt_hash = format!("sha256:{}", sha256_hex(self.jws.as_bytes()));
        Ok(&self.jws)
    }

    /// Parse a compact JWS string back into a receipt. Does NOT verify the
    /// signature — use [`crate::verifier::Verifier`] for that.
    pub fn from_jws(jws: &str) -> Result<Self, ReceiptError> {
        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() != 3 {
            return Err(ReceiptError::Malformed(
                "expected three dot-separated segments".to_string(),
            ));
        }
        let payload_bytes =
            b64url_decode(parts[1]).map_err(|e| ReceiptError::DecodeBase64(e.to_string()))?;
        let payload: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| ReceiptError::DecodeJson(e.to_string()))?;
        let p = payload
            .as_object()
            .ok_or_else(|| ReceiptError::Malformed("payload is not an object".to_string()))?;

        let op_str = p
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| ReceiptError::Malformed("missing 'operation'".to_string()))?;
        let operation = Operation::parse(op_str)
            .ok_or_else(|| ReceiptError::UnknownOperation(op_str.to_string()))?;

        let s = |key: &str| -> String {
            p.get(key)
                .and_then(Value::as_str)
                .map(|v| v.to_string())
                .unwrap_or_default()
        };
        let strs = |key: &str| -> Vec<String> {
            p.get(key)
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        let tenant = p
            .get("tenant")
            .and_then(Value::as_str)
            .map(|t| t.to_string());

        let mut r = Self::new(
            s("agent_id"),
            s("agent_key_id"),
            operation,
            p.get("iat").and_then(Value::as_i64).unwrap_or(0),
        );
        r.parents = strs("parents");
        r.input_hash = s("input_hash");
        r.output_hash = s("output_hash");
        r.model = s("model");
        r.tool = s("tool");
        r.corpus = s("corpus");
        r.ruleset_hash = s("ruleset_hash");
        r.guardrail_verdict = s("guardrail_verdict");
        r.taint = strs("taint");
        r.tenant = tenant;
        r.jws = jws.to_string();
        r.receipt_hash = format!("sha256:{}", sha256_hex(jws.as_bytes()));
        Ok(r)
    }

    /// Produce the JSONL on-disk record: payload + `receipt_hash` + `jws`.
    pub fn to_log_line(&self) -> Value {
        let mut v = self.payload();
        let obj = v.as_object_mut().expect("payload is object");
        obj.insert("receipt_hash".to_string(), json!(self.receipt_hash));
        obj.insert("jws".to_string(), json!(self.jws));
        v
    }
}
