/// Default DNS label length used for the encoded subdomain. 57 (not the DNS max of 63) is the
/// historical slipstream value; it is now configurable purely on the client side because the
/// server strips all dots (`undotify`) before decoding, so label boundaries are invisible to it.
/// Varying it changes the on-the-wire label-length fingerprint without any server-side change.
pub const DEFAULT_LABEL_LEN: usize = 57;

pub fn dotify(input: &str) -> String {
    dotify_with_label_len(input, DEFAULT_LABEL_LEN)
}

/// Split `input` into DNS labels of at most `label_len` characters, joined by dots. `label_len`
/// is clamped to 1..=63 (the DNS label limit). No leading/trailing dot, no empty labels are
/// produced. Because the server only cares about the dot-stripped payload, any valid label_len
/// round-trips correctly.
pub fn dotify_with_label_len(input: &str, label_len: usize) -> String {
    if input.is_empty() {
        return String::new();
    }
    let label_len = label_len.clamp(1, 63);
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len() + bytes.len() / label_len + 1);
    let mut count = 0usize;
    for &b in bytes {
        if count == label_len {
            out.push('.');
            count = 0;
        }
        out.push(b as char);
        count += 1;
    }
    out
}

pub fn undotify(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b != b'.' {
            out.push(b);
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::dotify;

    #[test]
    fn dotify_skips_trailing_dot_for_exact_segments() {
        let input = "A".repeat(57);
        let dotted = dotify(&input);
        assert_eq!(dotted, input);
        assert!(!dotted.ends_with('.'));
    }

    #[test]
    fn dotify_inserts_between_segments() {
        let input = "A".repeat(114);
        let dotted = dotify(&input);
        let expected = format!("{}.{}", "A".repeat(57), "A".repeat(57));
        assert_eq!(dotted, expected);
        assert!(!dotted.ends_with('.'));
    }
}
