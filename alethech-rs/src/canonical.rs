//! JCS (JSON Canonicalization Scheme) — RFC 8785.
//!
//! Serializes JSON to a canonical byte string suitable for hashing.
//! - Object keys sorted by UTF-16 code unit (RFC 8785 §3.2.3)
//! - Strings escaped per RFC 8259 (no escaped non-ASCII — UTF-8 direct)
//! - Numbers: serialized per ECMAScript Number.prototype.toString()

use serde_json::Value;

/// Canonicalize a JSON byte slice.
pub fn canonical_json_bytes(data: &[u8]) -> Vec<u8> {
    let value: Value = serde_json::from_slice(data).unwrap_or(Value::Null);
    canonicalize_value(&value).into_bytes()
}

/// Canonicalize a JSON value.
pub fn canonical_json(value: &Value) -> String {
    canonicalize_value(value)
}

fn canonicalize_value(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Number(n) => serialize_number(n),
        Value::String(s) => escape_string(s),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonicalize_value).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(obj) => {
            // Sort keys by UTF-16 code unit (RFC 8785 §3.2.3)
            let mut items: Vec<(String, &Value)> = obj
                .iter()
                .map(|(k, v)| (k.clone(), v))
                .collect();
            items.sort_by(|a, b| sort_utf16(&a.0, &b.0));

            let parts: Vec<String> = items
                .iter()
                .map(|(k, v)| format!("{}:{}", escape_string(k), canonicalize_value(v)))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// Sort by UTF-16 code units (RFC 8785).
fn sort_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    let a_utf16: Vec<u16> = a.encode_utf16().collect();
    let b_utf16: Vec<u16> = b.encode_utf16().collect();
    a_utf16.cmp(&b_utf16)
}

fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn serialize_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    if let Some(f) = n.as_f64() {
        return serialize_float(f);
    }
    n.to_string()
}

fn serialize_float(f: f64) -> String {
    if f == 0.0 {
        // RFC 8785: -0 serializes as "0"
        return "0".to_string();
    }
    if f.is_nan() || f.is_infinite() {
        // Not representable in JCS — but don't crash
        return "0".to_string();
    }

    let abs = f.abs();

    // ECMAScript uses scientific notation for |n| >= 1e21 or |n| < 1e-6
    if abs >= 1e21 || abs < 1e-6 {
        // Scientific notation: keep '+' for positive exponents
        let s = format!("{:e}", f);
        return normalize_scientific(&s);
    }

    // Check if integer-valued (e.g. 3.0 → "3")
    if f == f.trunc() && abs < 1e21 {
        return format!("{}", f as i64);
    }

    // Regular float
    format!("{}", f)
}

/// Normalize Rust's float formatting to match ECMAScript.
/// Rust: "1e21" → ECMAScript: "1e+21"
/// Rust: "1e-7" → ECMAScript: "1e-7"
fn normalize_scientific(s: &str) -> String {
    if let Some(e_pos) = s.find('e') {
        let mantissa = &s[..e_pos];
        let exp_str = &s[e_pos + 1..];
        let exp: i32 = exp_str.parse().unwrap_or(0);

        // Format exponent: +N for positive, -N for negative (no leading zeros)
        let exp_formatted = if exp >= 0 {
            format!("e+{}", exp)
        } else {
            format!("e-{}", exp.abs())
        };

        format!("{}{}", mantissa, exp_formatted)
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_basic_object() {
        let v = json!({"b": 1, "a": 2});
        assert_eq!(canonical_json(&v), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn test_nested_object() {
        let v = json!({"b": {"d": 1, "c": 2}, "a": 3});
        assert_eq!(canonical_json(&v), r#"{"a":3,"b":{"c":2,"d":1}}"#);
    }

    #[test]
    fn test_array_preserves_order() {
        let v = json!([3, 1, 2]);
        assert_eq!(canonical_json(&v), "[3,1,2]");
    }

    #[test]
    fn test_string_escaping() {
        let v = json!({"key": "hello\nworld"});
        assert_eq!(canonical_json(&v), r#"{"key":"hello\nworld"}"#);
    }

    #[test]
    fn test_integer_float() {
        let v = json!(3.0);
        assert_eq!(canonical_json(&v), "3");
    }

    #[test]
    fn test_zero() {
        let v = json!(0.0);
        assert_eq!(canonical_json(&v), "0");
    }

    #[test]
    fn test_negative_zero() {
        let v = json!(-0.0);
        // RFC 8785: -0 → "0"
        assert_eq!(canonical_json(&v), "0");
    }

    #[test]
    fn test_empty_object() {
        let v = json!({});
        assert_eq!(canonical_json(&v), "{}");
    }

    #[test]
    fn test_empty_array() {
        let v = json!([]);
        assert_eq!(canonical_json(&v), "[]");
    }

    #[test]
    fn test_null() {
        let v = json!(null);
        assert_eq!(canonical_json(&v), "null");
    }

    #[test]
    fn test_true_false() {
        assert_eq!(canonical_json(&json!(true)), "true");
        assert_eq!(canonical_json(&json!(false)), "false");
    }

    #[test]
    fn test_unicode_preserved() {
        let v = json!({"name": "café"});
        assert_eq!(canonical_json(&v), r#"{"name":"café"}"#);
    }

    #[test]
    fn test_utf16_sorting() {
        // U+10000 (surrogate pair D800 DC00) sorts before U+FFFF
        let v = json!({
            "\u{ffff}": 1,
            "\u{10000}": 2,
        });
        let result = canonical_json(&v);
        // The key with surrogate pair (U+10000) should come first
        assert!(result.starts_with("{\""));
        let first_key_end = result[2..].find('"').unwrap_or(0);
        let first_key = &result[2..2 + first_key_end];
        assert_eq!(first_key, "\u{10000}");
    }
}
