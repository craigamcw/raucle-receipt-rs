//! Base64url (RFC 4648 §5), unpadded.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}
