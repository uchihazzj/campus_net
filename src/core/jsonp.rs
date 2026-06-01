/// Safely truncate a string to at most `max_chars` characters, on a
/// UTF-8 character boundary. Does not panic for any input.
pub fn safe_truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => &s[..byte_idx],
        None => s,
    }
}

/// Strip a JSONP wrapper like `sdu({...})` or ` sdu({...}); ` from `body`,
/// returning the inner JSON string. Handles whitespace and optional trailing
/// semicolon. Returns `Err(description)` on malformed input; the description
/// uses char-safe truncation and never panics.
pub fn strip_jsonp(body: &str) -> Result<&str, String> {
    let trimmed = body.trim();

    let after_prefix = trimmed.strip_prefix("sdu(").ok_or_else(|| {
        format!(
            "Unexpected JSONP format (first 80 chars): {}",
            safe_truncate(trimmed, 80)
        )
    })?;

    let inner = after_prefix
        .strip_suffix(')')
        .or_else(|| after_prefix.strip_suffix(");"))
        .ok_or_else(|| {
            format!(
                "JSONP missing closing ')' (first 80 chars): {}",
                safe_truncate(trimmed, 80)
            )
        })?;

    Ok(inner.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── strip_jsonp ─────────────────────────────────────

    #[test]
    fn normal() {
        assert_eq!(strip_jsonp("sdu({\"a\":1})").unwrap(), "{\"a\":1}");
    }

    #[test]
    fn with_semicolon() {
        assert_eq!(strip_jsonp("sdu({\"a\":1});").unwrap(), "{\"a\":1}");
    }

    #[test]
    fn whitespace() {
        assert_eq!(strip_jsonp("  sdu({\"a\":1})  ").unwrap(), "{\"a\":1}");
    }

    #[test]
    fn whitespace_and_semicolon() {
        assert_eq!(strip_jsonp(" sdu(  {\"a\":1}  ); ").unwrap(), "{\"a\":1}");
    }

    #[test]
    fn malformed_no_prefix() {
        assert!(strip_jsonp("not_jsonp").is_err());
    }

    #[test]
    fn malformed_no_suffix() {
        assert!(strip_jsonp("sdu({\"a\":1}").is_err());
    }

    // ── safe_truncate ────────────────────────────────────

    #[test]
    fn short() {
        assert_eq!(safe_truncate("hello", 80), "hello");
    }

    #[test]
    fn exact_boundary() {
        assert_eq!(safe_truncate("abc", 3), "abc");
    }

    #[test]
    fn multibyte_safe() {
        let s = "你好世界";
        assert_eq!(safe_truncate(s, 2).chars().count(), 2);
        let _ = safe_truncate(s, 1);
        let _ = safe_truncate(s, 3);
    }

    #[test]
    fn empty() {
        assert_eq!(safe_truncate("", 80), "");
    }
}
