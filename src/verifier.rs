//! Chain verifier per Raucle spec v1 §10.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use ed25519_dalek::{Signature, Verifier as DalekVerifier, VerifyingKey};
use serde_json::Value;

use crate::b64::b64url_decode;
use crate::identity::{load_public_key, IdentityError};
use crate::receipt::{Operation, Receipt, ReceiptError};

/// Outcome of verifying a chain.
#[derive(Debug, Default)]
pub struct VerificationReport {
    pub valid: bool,
    pub receipt_count: usize,
    pub signature_failures: usize,
    pub parent_link_failures: usize,
    pub taint_monotonicity_failures: usize,
    pub tampered_receipts: Vec<String>,
    pub errors: Vec<String>,
}

/// Errors raised by chain verification.
#[derive(Debug)]
pub enum VerifierError {
    Io(std::io::Error),
    Identity(IdentityError),
    Receipt(ReceiptError),
}

impl std::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Identity(e) => write!(f, "identity error: {}", e),
            Self::Receipt(e) => write!(f, "receipt error: {}", e),
        }
    }
}

impl std::error::Error for VerifierError {}

impl From<std::io::Error> for VerifierError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<IdentityError> for VerifierError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

/// Verifies provenance chains against a configured key store.
pub struct Verifier {
    keys: HashMap<String, VerifyingKey>,
}

impl Verifier {
    /// Build a verifier from `key_id` → PEM mappings.
    pub fn new(public_keys_pem: HashMap<String, String>) -> Result<Self, VerifierError> {
        let mut keys = HashMap::with_capacity(public_keys_pem.len());
        for (kid, pem) in public_keys_pem {
            let key = load_public_key(&pem)?;
            keys.insert(kid, key);
        }
        Ok(Self { keys })
    }

    /// Verify a JSONL chain file.
    pub fn verify_chain_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<VerificationReport, VerifierError> {
        let file = File::open(path)?;
        self.verify_chain(BufReader::new(file))
    }

    /// Verify a JSONL chain from any reader.
    pub fn verify_chain<R: Read>(&self, reader: R) -> Result<VerificationReport, VerifierError> {
        let mut report = VerificationReport {
            valid: true,
            ..VerificationReport::default()
        };
        let mut by_hash: HashMap<String, Receipt> = HashMap::new();

        for (i, line_result) in BufReader::new(reader).lines().enumerate() {
            let line_no = i + 1;
            let line = line_result?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let raw: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    report.push_err(format!("line {}: invalid JSON: {}", line_no, e));
                    continue;
                }
            };
            let obj = match raw.as_object() {
                Some(o) => o,
                None => {
                    report.push_err(format!("line {}: record is not an object", line_no));
                    continue;
                }
            };
            let jws = match obj.get("jws").and_then(Value::as_str) {
                Some(s) => s,
                None => {
                    report.push_err(format!(
                        "line {}: record has no string 'jws' field",
                        line_no
                    ));
                    continue;
                }
            };
            let receipt = match Receipt::from_jws(jws) {
                Ok(r) => r,
                Err(e) => {
                    report.push_err(format!("line {}: malformed receipt: {}", line_no, e));
                    continue;
                }
            };

            // Tampering check
            if let Some(stored) = obj.get("receipt_hash").and_then(Value::as_str) {
                if stored != receipt.receipt_hash {
                    report.tampered_receipts.push(receipt.receipt_hash.clone());
                    report.push_err(format!(
                        "line {}: receipt_hash mismatch — record tampered",
                        line_no
                    ));
                }
            }

            // Signature
            if !self.verify_signature(&receipt) {
                report.signature_failures += 1;
                report.push_err(format!(
                    "line {}: signature verification failed for agent_key_id={}",
                    line_no, receipt.agent_key_id
                ));
            }

            by_hash.insert(receipt.receipt_hash.clone(), receipt);
            report.receipt_count += 1;
        }

        // DAG integrity + taint monotonicity (separate borrow scope)
        let hashes: Vec<String> = by_hash.keys().cloned().collect();
        for h in &hashes {
            let receipt = by_hash.get(h).expect("hash present").clone();
            for parent in &receipt.parents {
                if !by_hash.contains_key(parent) {
                    report.parent_link_failures += 1;
                    report.push_err(format!(
                        "receipt {}: parent {} not in chain",
                        receipt.receipt_hash, parent
                    ));
                }
            }
            self.check_taint(&receipt, &by_hash, &mut report);
        }

        Ok(report)
    }

    /// Walk the DAG backwards from `receipt_hash` to all roots, deduplicated.
    pub fn trace<P: AsRef<Path>>(
        &self,
        receipt_hash: &str,
        chain_path: P,
    ) -> Result<Vec<Receipt>, VerifierError> {
        let file = File::open(chain_path)?;
        let mut all: HashMap<String, Receipt> = HashMap::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(raw): Result<Value, _> = serde_json::from_str(trimmed) else {
                continue;
            };
            let Some(jws) = raw.get("jws").and_then(Value::as_str) else {
                continue;
            };
            let Ok(r) = Receipt::from_jws(jws) else {
                continue;
            };
            all.insert(r.receipt_hash.clone(), r);
        }
        if !all.contains_key(receipt_hash) {
            return Err(VerifierError::Receipt(ReceiptError::Malformed(format!(
                "receipt {} not found in chain",
                receipt_hash
            ))));
        }
        let mut out = Vec::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: std::collections::VecDeque<String> =
            std::collections::VecDeque::from([receipt_hash.to_string()]);
        while let Some(current) = queue.pop_front() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(r) = all.get(&current) {
                out.push(r.clone());
                for parent in &r.parents {
                    queue.push_back(parent.clone());
                }
            }
        }
        Ok(out)
    }

    /// Verify the Ed25519 signature on a single receipt.
    pub fn verify_signature(&self, receipt: &Receipt) -> bool {
        let Some(key) = self.keys.get(&receipt.agent_key_id) else {
            return false;
        };
        let parts: Vec<&str> = receipt.jws.split('.').collect();
        if parts.len() != 3 {
            return false;
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let Ok(sig_bytes) = b64url_decode(parts[2]) else {
            return false;
        };
        let Ok(sig_array): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_array);
        key.verify(signing_input.as_bytes(), &sig).is_ok()
    }

    fn check_taint(
        &self,
        receipt: &Receipt,
        by_hash: &HashMap<String, Receipt>,
        report: &mut VerificationReport,
    ) {
        if receipt.parents.is_empty() {
            return;
        }
        let mut inherited: HashSet<&str> = HashSet::new();
        for p in &receipt.parents {
            if let Some(parent) = by_hash.get(p) {
                for t in &parent.taint {
                    inherited.insert(t.as_str());
                }
            }
        }
        let mine: HashSet<&str> = receipt.taint.iter().map(String::as_str).collect();

        if receipt.operation == Operation::Sanitisation {
            let removed: HashSet<&str> = if let Some(rest) = receipt.corpus.strip_prefix("removed:")
            {
                rest.split(',').filter(|s| !s.is_empty()).collect()
            } else {
                HashSet::new()
            };
            let expected: HashSet<&str> = inherited.difference(&removed).copied().collect();
            if expected != mine {
                report.taint_monotonicity_failures += 1;
                report.push_err(format!(
                    "receipt {}: sanitisation taint mismatch",
                    receipt.receipt_hash
                ));
            }
        } else {
            let missing: Vec<&&str> = inherited.iter().filter(|t| !mine.contains(*t)).collect();
            if !missing.is_empty() {
                report.taint_monotonicity_failures += 1;
                report.push_err(format!(
                    "receipt {}: taint not monotonic — dropped {:?} without a sanitisation step",
                    receipt.receipt_hash, missing
                ));
            }
        }
    }
}

impl VerificationReport {
    fn push_err(&mut self, msg: String) {
        self.errors.push(msg);
        self.valid = false;
    }
}
