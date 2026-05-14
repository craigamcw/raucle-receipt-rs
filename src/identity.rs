//! Agent identity + capability statement per Raucle spec v1 §5.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64_STANDARD, Engine as _};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};

use crate::canonical::canonicalize_value;
use crate::hash::sha256_hex;

/// Manual validator for `^agent:[a-z0-9][a-z0-9_\-./]{0,127}$`.
/// Avoids pulling in a regex dependency for one pattern.
fn is_valid_agent_id(id: &str) -> bool {
    if !id.starts_with("agent:") {
        return false;
    }
    let local = &id["agent:".len()..];
    if local.is_empty() || local.len() > 128 {
        return false;
    }
    let mut chars = local.chars();
    // First char: [a-z0-9]
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    // Remaining chars: [a-z0-9_\-./]
    for c in chars {
        let ok = c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == '_'
            || c == '-'
            || c == '.'
            || c == '/';
        if !ok {
            return false;
        }
    }
    true
}

/// Errors raised by identity / capability operations.
#[derive(Debug)]
pub enum IdentityError {
    InvalidAgentId(String),
    Pem(String),
    Encode(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAgentId(id) => write!(f, "invalid agent_id {:?}", id),
            Self::Pem(msg) => write!(f, "PEM error: {}", msg),
            Self::Encode(msg) => write!(f, "encode error: {}", msg),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Validate an `agent_id` per spec §5.
pub fn validate_agent_id(id: &str) -> Result<(), IdentityError> {
    if is_valid_agent_id(id) {
        Ok(())
    } else {
        Err(IdentityError::InvalidAgentId(id.to_string()))
    }
}

/// A signed declaration of what an agent is permitted to do. Distributed
/// alongside the agent's public key.
#[derive(Debug, Clone)]
pub struct CapabilityStatement {
    pub agent_id: String,
    pub key_id: String,
    pub public_key_pem: String,
    pub allowed_models: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub data_classifications: Vec<String>,
    pub issuer: String,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    /// Base64 (standard alphabet) of Ed25519 signature over canonical-JSON
    /// of `body()`.
    pub signature: String,
}

impl CapabilityStatement {
    /// Canonical signed-body value (excludes `signature`).
    pub fn body(&self) -> Value {
        let mut allowed_models = self.allowed_models.clone();
        allowed_models.sort();
        let mut allowed_tools = self.allowed_tools.clone();
        allowed_tools.sort();
        let mut data_classifications = self.data_classifications.clone();
        data_classifications.sort();
        json!({
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "allowed_models": allowed_models,
            "allowed_tools": allowed_tools,
            "data_classifications": data_classifications,
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        })
    }

    pub fn permits_model(&self, model: &str) -> bool {
        self.allowed_models.is_empty() || self.allowed_models.iter().any(|m| m == model)
    }

    pub fn permits_tool(&self, tool: &str) -> bool {
        self.allowed_tools.is_empty() || self.allowed_tools.iter().any(|t| t == tool)
    }
}

/// Options for [`AgentIdentity::generate`].
#[derive(Debug, Clone, Default)]
pub struct GenerateOptions {
    pub agent_id: String,
    pub allowed_models: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub data_classifications: Vec<String>,
    pub issuer: Option<String>,
    pub ttl_seconds: Option<i64>,
}

/// Ed25519 keypair + signed capability statement.
pub struct AgentIdentity {
    pub agent_id: String,
    pub statement: CapabilityStatement,
    signing_key: SigningKey,
}

impl AgentIdentity {
    /// Fresh keypair + self-signed capability statement.
    pub fn generate(opts: GenerateOptions) -> Result<Self, IdentityError> {
        validate_agent_id(&opts.agent_id)?;
        let mut csprng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self::from_key(signing_key, opts)
    }

    /// Construct from existing key material — used internally and by tests
    /// that need deterministic seeds.
    pub(crate) fn from_key(
        signing_key: SigningKey,
        opts: GenerateOptions,
    ) -> Result<Self, IdentityError> {
        validate_agent_id(&opts.agent_id)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let public_key_pem = verifying_key
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .map_err(|e| IdentityError::Encode(e.to_string()))?;
        let key_id: String = sha256_hex(public_key_pem.as_bytes())
            .chars()
            .take(16)
            .collect();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| IdentityError::Encode(e.to_string()))?
            .as_secs() as i64;
        let expires_at = opts.ttl_seconds.map(|ttl| now + ttl);
        let issuer = opts.issuer.unwrap_or_else(|| "raucle-detect".to_string());
        let mut stmt = CapabilityStatement {
            agent_id: opts.agent_id.clone(),
            key_id,
            public_key_pem,
            allowed_models: opts.allowed_models,
            allowed_tools: opts.allowed_tools,
            data_classifications: opts.data_classifications,
            issuer,
            issued_at: now,
            expires_at,
            signature: String::new(),
        };
        let body_bytes = canonicalize_value(&stmt.body()).into_bytes();
        let sig = signing_key.sign(&body_bytes);
        stmt.signature = B64_STANDARD.encode(sig.to_bytes());
        Ok(Self {
            agent_id: opts.agent_id,
            statement: stmt,
            signing_key,
        })
    }

    /// Rebuild an identity from stored PEM + capability statement.
    pub fn load(
        private_key_pem: &str,
        statement: CapabilityStatement,
    ) -> Result<Self, IdentityError> {
        validate_agent_id(&statement.agent_id)?;
        let signing_key = SigningKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| IdentityError::Pem(e.to_string()))?;
        Ok(Self {
            agent_id: statement.agent_id.clone(),
            statement,
            signing_key,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.statement.key_id
    }

    pub fn public_key_pem(&self) -> &str {
        &self.statement.public_key_pem
    }

    /// PKCS8 PEM serialisation of the private key.
    pub fn private_key_pem(&self) -> Result<String, IdentityError> {
        let doc = self
            .signing_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map_err(|e| IdentityError::Encode(e.to_string()))?;
        Ok(doc.to_string())
    }

    /// Sign bytes with this identity's private key.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing_key.sign(data).to_bytes()
    }
}

/// Load a PEM-encoded Ed25519 public key.
pub fn load_public_key(pem: &str) -> Result<VerifyingKey, IdentityError> {
    VerifyingKey::from_public_key_pem(pem).map_err(|e| IdentityError::Pem(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_agent_id() {
        assert!(validate_agent_id("agent:ok").is_ok());
        assert!(validate_agent_id("agent:my.service-v1").is_ok());
        assert!(validate_agent_id("no-prefix").is_err());
        assert!(validate_agent_id("AGENT:upper").is_err());
        assert!(validate_agent_id("agent:").is_err());
        assert!(validate_agent_id("agent:has space").is_err());
    }

    #[test]
    fn generate_self_signs_statement() {
        let id = AgentIdentity::generate(GenerateOptions {
            agent_id: "agent:x".to_string(),
            allowed_models: vec!["m1".to_string()],
            allowed_tools: vec!["t1".to_string()],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(id.key_id().len(), 16);
        assert!(!id.statement.signature.is_empty());
        assert!(id.statement.permits_model("m1"));
        assert!(!id.statement.permits_model("rogue"));
        assert!(id.statement.permits_tool("t1"));
        assert!(!id.statement.permits_tool("rogue"));
    }

    #[test]
    fn default_allowlists_unrestricted() {
        let id = AgentIdentity::generate(GenerateOptions {
            agent_id: "agent:x".to_string(),
            ..Default::default()
        })
        .unwrap();
        assert!(id.statement.permits_model("anything"));
        assert!(id.statement.permits_tool("anything"));
    }
}
