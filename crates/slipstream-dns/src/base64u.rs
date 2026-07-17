use std::fmt;

const ENCODE_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64UError {
    InvalidLength,
    InvalidChar,
}

impl fmt::Display for Base64UError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Base64UError::InvalidLength => "invalid base64u length",
            Base64UError::InvalidChar => "invalid base64u character",
        };
        write!(f, "{}", message)
    }
}

impl std::error::Error for Base64UError {}

/// RFC 4648 §5 base64url alphabet, unpadded (no `=`): 6 bits/char vs base32's 5, so ~20% denser --
/// but unlike this crate's base32 (whose decoder treats upper/lower as identical), base64url is
/// case-sensitive by construction. Only safe over a path confirmed to preserve label case end to
/// end; a resolver hop that normalizes case will silently decode to the wrong bytes rather than
/// failing cleanly.
pub fn encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity((input.len() * 8).div_ceil(6));
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;

    for &byte in input {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;

        while bits >= 6 {
            let shift = bits - 6;
            let index = ((buffer >> shift) & 0x3f) as usize;
            out.push(ENCODE_TABLE[index] as char);
            bits -= 6;
        }
    }

    if bits > 0 {
        let index = ((buffer << (6 - bits)) & 0x3f) as usize;
        out.push(ENCODE_TABLE[index] as char);
    }

    out
}

pub fn decode(input: &str) -> Result<Vec<u8>, Base64UError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 6 / 8 + 1);

    for b in input.bytes() {
        let value = decode_value(b)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    // A valid encode() output never leaves 6+ dangling bits (that would hide a whole undecoded
    // byte); it only ever leaves 0, 2, or 4 zero-padding bits from the final partial char.
    if bits >= 6 {
        return Err(Base64UError::InvalidLength);
    }
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return Err(Base64UError::InvalidChar);
    }

    Ok(out)
}

fn decode_value(b: u8) -> Result<u8, Base64UError> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(Base64UError::InvalidChar),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn round_trips_empty() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn round_trips_all_byte_values() {
        let input: Vec<u8> = (0..=255).collect();
        let encoded = encode(&input);
        assert_eq!(decode(&encoded).unwrap(), input);
    }

    #[test]
    fn round_trips_every_length_1_to_16() {
        for len in 1..=16usize {
            let input: Vec<u8> = (0..len as u8).collect();
            let encoded = encode(&input);
            assert_eq!(decode(&encoded).unwrap(), input, "len={}", len);
        }
    }

    #[test]
    fn encode_uses_url_safe_alphabet_only() {
        let input: Vec<u8> = (0..=255).collect();
        let encoded = encode(&input);
        assert!(encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn decode_rejects_invalid_char() {
        assert!(decode("AB CD").is_err());
        assert!(decode("AB.CD").is_err());
        assert!(decode("AB=").is_err());
    }

    #[test]
    fn decode_rejects_dangling_bits_that_would_hide_a_byte() {
        // A single char only carries 6 bits -- never enough to be a valid standalone encoding.
        assert!(decode("A").is_err());
    }

    #[test]
    fn decode_rejects_nonzero_padding_bits() {
        // 'B' = 000001 in the table; as a lone trailing char after a 1-byte-aligned prefix, its
        // low bits must be zero padding. Flip them nonzero and decoding must reject, not silently
        // truncate.
        let one_byte = encode(&[0xFF]);
        assert_eq!(one_byte.len(), 2);
        let mut corrupted = one_byte.clone();
        corrupted.replace_range(1..2, "B");
        if corrupted != one_byte {
            assert!(decode(&corrupted).is_err());
        }
    }
}
