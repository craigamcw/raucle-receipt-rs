//! Canonical JSON serialisation matching Raucle spec v1 §4.3.
//!
//! Requirements (must match Python's
//! `json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`):
//!
//!  1. Keys at every depth sorted lexicographically.
//!  2. Separators `,` and `:` with no whitespace.
//!  3. UTF-8 output.
//!  4. Non-ASCII strings NOT escaped — pass through as their raw codepoints.
//!  5. Numbers use the minimal lossless representation.
//!
//! `serde_json` does not satisfy these out of the box: it does not sort
//! map keys deterministically and offers no opt-out from its non-ASCII
//! escaping settings without custom serialisers. This module rebuilds
//! canonicalisation from scratch on top of [`serde_json::Value`].

use std::fmt::Write as _;

use serde_json::{Map, Number, Value};

/// Serialise *value* as canonical JSON. The output is a `String` because the
/// canonical form is always valid UTF-8.
pub fn canonicalize_value(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

/// Convenience: canonicalize anything that converts to a [`Value`].
pub fn canonicalize<T: Into<Value>>(v: T) -> String {
    canonicalize_value(&v.into())
}

/// Canonicalize and return raw UTF-8 bytes — what gets fed into SHA-256
/// or Ed25519.
pub fn canonicalize_bytes(value: &Value) -> Vec<u8> {
    canonicalize_value(value).into_bytes()
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_string(out, s),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(obj) => write_object(out, obj),
    }
}

fn write_object(out: &mut String, obj: &Map<String, Value>) {
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();
    out.push('{');
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(out, k);
        out.push(':');
        write_value(out, &obj[k.as_str()]);
    }
    out.push('}');
}

fn write_number(out: &mut String, n: &Number) {
    // Prefer integer rendering when possible — matches Python json.dumps,
    // which emits `1` not `1.0` for whole-number values.
    if let Some(i) = n.as_i64() {
        let _ = write!(out, "{}", i);
    } else if let Some(u) = n.as_u64() {
        let _ = write!(out, "{}", u);
    } else if let Some(f) = n.as_f64() {
        // Ed25519-signed receipts only contain integers in their
        // standard fields, but extension fields could carry floats.
        if f.is_finite() {
            let _ = write!(out, "{}", f);
        } else {
            // serde_json silently turns NaN/Infinity into null on parse,
            // so we should never see them here; if we do, fail loudly.
            panic!("canonical JSON cannot encode NaN or Infinity");
        }
    } else {
        // Number that isn't i64, u64, or f64 — unreachable in serde_json 1.x.
        out.push_str("null");
    }
}

/// Match Python's `ensure_ascii=False`: non-ASCII codepoints pass through
/// unescaped; only the JSON control characters mandated by RFC 8259 are
/// escaped.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_omits_whitespace() {
        assert_eq!(
            canonicalize_value(&json!({"b": 1, "a": 2})),
            r#"{"a":2,"b":1}"#
        );
    }

    #[test]
    fn nested_keys_sorted() {
        assert_eq!(
            canonicalize_value(&json!({"z": 1, "a": {"b": 2, "a": 1}})),
            r#"{"a":{"a":1,"b":2},"z":1}"#,
        );
    }

    #[test]
    fn non_ascii_passes_through() {
        assert_eq!(canonicalize_value(&json!("café")), "\"café\"");
        assert_eq!(canonicalize_value(&json!("→")), "\"→\"");
    }

    #[test]
    fn json_control_chars_escaped() {
        assert_eq!(canonicalize_value(&json!("a\nb")), r#""a\nb""#);
        assert_eq!(
            canonicalize_value(&json!("he said \"hi\"")),
            r#""he said \"hi\"""#
        );
    }

    #[test]
    fn array_preserves_order() {
        assert_eq!(canonicalize_value(&json!([3, 1, 2])), "[3,1,2]");
    }

    #[test]
    fn null_and_bools() {
        assert_eq!(
            canonicalize_value(&json!({"x": null, "y": true, "z": false})),
            r#"{"x":null,"y":true,"z":false}"#,
        );
    }
}
