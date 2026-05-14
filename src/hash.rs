//! SHA-256 helpers using the Raucle spec §7 prefix convention.

use sha2::{Digest, Sha256};

use crate::canonical::canonicalize_value;

/// Lowercase hex SHA-256 of *data*.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let bytes = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in bytes.iter() {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Hash a string per spec §7: `"sha256:"` + lowercase hex.
pub fn hash_text(s: &str) -> String {
    format!("sha256:{}", sha256_hex(s.as_bytes()))
}

/// Hash an arbitrary JSON-serialisable value per spec §7. Canonicalises the
/// value first so key order is irrelevant.
pub fn hash_obj(v: &serde_json::Value) -> String {
    format!("sha256:{}", sha256_hex(canonicalize_value(v).as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deterministic_and_prefixed() {
        assert_eq!(hash_text("hello"), hash_text("hello"));
        assert_ne!(hash_text("hello"), hash_text("world"));
        assert!(hash_text("x").starts_with("sha256:"));
        assert_eq!(hash_text("x").len(), "sha256:".len() + 64);
    }

    #[test]
    fn obj_order_independent() {
        assert_eq!(
            hash_obj(&json!({"a": 1, "b": 2})),
            hash_obj(&json!({"b": 2, "a": 1})),
        );
        assert_ne!(hash_obj(&json!({"a": 1})), hash_obj(&json!({"a": 2})));
    }
}
