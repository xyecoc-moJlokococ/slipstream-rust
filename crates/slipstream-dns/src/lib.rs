mod base32;
mod base64u;
mod codec;
mod dots;
mod name;
mod types;
mod wire;

pub use base32::{decode as base32_decode, encode as base32_encode, Base32Error};
pub use base64u::{decode as base64u_decode, encode as base64u_encode, Base64UError};
pub use codec::{
    build_edns_raw_qname, decode_query, decode_query_with_domains,
    decode_query_with_domains_and_qtype, decode_response, decode_response_with_encoding,
    encode_query, encode_query_compact, encode_query_edns_raw, encode_response,
    encode_response_with_ttl, encode_response_with_ttl_into, is_response, DEFAULT_RESPONSE_TTL,
};
pub use dots::{dotify, dotify_with_label_len, undotify, DEFAULT_LABEL_LEN};
use types::BASE64U_MARKER;
pub use types::{
    DataEncoding, DecodeQueryError, DecodedQuery, DnsError, QueryParams, Question, Rcode,
    ResponseParams, CLASS_IN, EDNS_SLIPSTREAM_PAYLOAD_OPTION, EDNS_UDP_PAYLOAD, RR_A, RR_AAAA,
    RR_CNAME, RR_HTTPS, RR_MX, RR_NULL, RR_OPT, RR_SRV, RR_TXT, SVCPARAM_ECH,
};

pub fn build_qname(payload: &[u8], domain: &str) -> Result<String, DnsError> {
    build_qname_with_label_len(payload, domain, DEFAULT_LABEL_LEN)
}

/// Like [`build_qname`] but splits the encoded subdomain into labels of `label_len` characters.
/// The label length only affects the on-the-wire fingerprint (the server strips dots before
/// decoding), so this can be varied freely per client.
pub fn build_qname_with_label_len(
    payload: &[u8],
    domain: &str,
    label_len: usize,
) -> Result<String, DnsError> {
    build_qname_with_encoding(payload, domain, label_len, DataEncoding::Base32)
}

/// Like [`build_qname_with_label_len`] but lets the client pick [`DataEncoding::Base64Url`] instead
/// of the default base32. When base64u is chosen, the encoded payload is prefixed with a reserved
/// marker (see [`crate::types::BASE64U_MARKER`]) so the server can detect the choice per-query with
/// no configuration of its own -- see `decode_query_with_domains_and_qtype`.
pub fn build_qname_with_encoding(
    payload: &[u8],
    domain: &str,
    label_len: usize,
    encoding: DataEncoding,
) -> Result<String, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    let max_payload = max_payload_len_for_domain_with_encoding(domain, label_len, encoding)?;
    if payload.len() > max_payload {
        return Err(DnsError::new("payload too large for domain"));
    }
    let encoded = match encoding {
        DataEncoding::Base32 => base32_encode(payload),
        DataEncoding::Base64Url => format!("{}{}", BASE64U_MARKER, base64u_encode(payload)),
    };
    let dotted = dotify_with_label_len(&encoded, label_len);
    Ok(format!("{}.{}.", dotted, domain))
}

pub fn max_payload_len_for_domain(domain: &str) -> Result<usize, DnsError> {
    max_payload_len_for_domain_with_label_len(domain, DEFAULT_LABEL_LEN)
}

/// Maximum payload bytes that fit in a query name for `domain` when the encoded subdomain is
/// split into `label_len`-char labels. Must use the same `label_len` as [`build_qname_with_label_len`]
/// so the client's payload sizing matches the name it actually builds.
pub fn max_payload_len_for_domain_with_label_len(
    domain: &str,
    label_len: usize,
) -> Result<usize, DnsError> {
    max_payload_len_for_domain_with_encoding(domain, label_len, DataEncoding::Base32)
}

/// Like [`max_payload_len_for_domain_with_label_len`] but for the encoding `build_qname_with_encoding`
/// would actually use. Must be called with the same `label_len` and `encoding` the client passes
/// there, so payload sizing matches the name actually built.
pub fn max_payload_len_for_domain_with_encoding(
    domain: &str,
    label_len: usize,
    encoding: DataEncoding,
) -> Result<usize, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    if domain.len() > name::MAX_DNS_NAME_LEN {
        return Err(DnsError::new("domain too long"));
    }
    let label_len = label_len.clamp(1, 63);
    let max_name_len = name::MAX_DNS_NAME_LEN;
    let max_dotted_len = max_name_len.saturating_sub(domain.len() + 1);
    let marker_len = match encoding {
        DataEncoding::Base32 => 0,
        DataEncoding::Base64Url => BASE64U_MARKER.len(),
    };
    if max_dotted_len <= marker_len {
        return Ok(0);
    }

    // The label-length fingerprint chunks the whole encoded run (marker + payload chars) as one
    // string -- dotify doesn't know or care that a marker prefix is in there.
    let mut max_encoded_total = 0usize;
    for len in 1..=max_dotted_len {
        let dots = (len - 1) / label_len;
        if len + dots > max_dotted_len {
            break;
        }
        max_encoded_total = len;
    }
    if max_encoded_total <= marker_len {
        return Ok(0);
    }
    let max_encoded_len = max_encoded_total - marker_len;

    let bits_per_char = match encoding {
        DataEncoding::Base32 => 5,
        DataEncoding::Base64Url => 6,
    };
    let mut max_payload = (max_encoded_len * bits_per_char) / 8;
    while max_payload > 0 && encoded_len(max_payload, encoding) > max_encoded_len {
        max_payload -= 1;
    }
    Ok(max_payload)
}

fn encoded_len(payload_len: usize, encoding: DataEncoding) -> usize {
    if payload_len == 0 {
        return 0;
    }
    let bits_per_char = match encoding {
        DataEncoding::Base32 => 5,
        DataEncoding::Base64Url => 6,
    };
    (payload_len * 8).div_ceil(bits_per_char)
}

#[cfg(test)]
mod tests {
    use super::{
        build_qname, build_qname_with_encoding, decode_query_with_domains_and_qtype,
        max_payload_len_for_domain, max_payload_len_for_domain_with_encoding, DataEncoding, RR_TXT,
    };

    #[test]
    fn build_qname_rejects_payload_overflow() {
        let domain = "test.com";
        let max_payload = max_payload_len_for_domain(domain).expect("max payload");
        let payload = vec![0u8; max_payload + 1];
        assert!(build_qname(&payload, domain).is_err());
    }

    #[test]
    fn build_qname_rejects_long_domain() {
        let domain = format!("{}.com", "a".repeat(260));
        let payload = vec![0u8; 1];
        assert!(build_qname(&payload, &domain).is_err());
    }

    /// End-to-end: the client builds a qname with `encoding`, the server decodes it back with no
    /// prior knowledge of which encoding was chosen (the whole point of the marker-prefix design --
    /// see `crate::types::BASE64U_MARKER`).
    fn query_round_trip(domain: &str, encoding: DataEncoding, payload: &[u8]) {
        let qname = build_qname_with_encoding(payload, domain, 57, encoding)
            .unwrap_or_else(|e| panic!("build_qname encoding={encoding:?}: {e}"));
        let query = crate::encode_query(&crate::QueryParams {
            id: 0x99,
            qname: &qname,
            qtype: RR_TXT,
            qclass: crate::CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
        })
        .expect("encode query");
        let decoded = decode_query_with_domains_and_qtype(&query, &[domain], RR_TXT)
            .unwrap_or_else(|e| panic!("decode query encoding={encoding:?}: {e:?}"));
        assert_eq!(decoded.encoding, encoding);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn build_qname_base32_round_trips_and_defaults_encoding() {
        query_round_trip("test.com", DataEncoding::Base32, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn build_qname_base64u_round_trips_and_is_detected_without_server_config() {
        query_round_trip("test.com", DataEncoding::Base64Url, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn build_qname_base64u_round_trips_empty_and_large_payloads() {
        query_round_trip("test.com", DataEncoding::Base64Url, &[]);
        let max_payload =
            max_payload_len_for_domain_with_encoding("test.com", 57, DataEncoding::Base64Url)
                .expect("max payload");
        let payload: Vec<u8> = (0..max_payload).map(|i| (i % 256) as u8).collect();
        query_round_trip("test.com", DataEncoding::Base64Url, &payload);
    }

    #[test]
    fn build_qname_base64u_round_trips_across_label_lengths() {
        // The marker + payload run gets dotify-chunked as one string; small label lengths are the
        // sharpest test that the marker survives being split across a label boundary (undotify
        // just concatenates everything back before the server ever looks for the marker).
        for label_len in [1usize, 2, 3, 5, 57, 63] {
            let qname =
                build_qname_with_encoding(b"hello", "test.com", label_len, DataEncoding::Base64Url)
                    .unwrap_or_else(|e| panic!("label_len={label_len}: {e}"));
            let query = crate::encode_query(&crate::QueryParams {
                id: 1,
                qname: &qname,
                qtype: RR_TXT,
                qclass: crate::CLASS_IN,
                rd: true,
                cd: false,
                qdcount: 1,
                is_query: true,
            })
            .expect("encode query");
            let decoded = decode_query_with_domains_and_qtype(&query, &["test.com"], RR_TXT)
                .unwrap_or_else(|e| panic!("label_len={label_len}: {e:?}"));
            assert_eq!(
                decoded.encoding,
                DataEncoding::Base64Url,
                "label_len={label_len}"
            );
            assert_eq!(decoded.payload, b"hello", "label_len={label_len}");
        }
    }

    #[test]
    fn max_payload_len_base64u_exceeds_base32_for_same_domain() {
        // The whole point of base64u: more payload bytes fit in the same name budget, even after
        // accounting for the marker prefix's overhead.
        let domain = "test.com";
        let base32_max = max_payload_len_for_domain_with_encoding(domain, 57, DataEncoding::Base32)
            .expect("base32 max");
        let base64u_max =
            max_payload_len_for_domain_with_encoding(domain, 57, DataEncoding::Base64Url)
                .expect("base64u max");
        assert!(
            base64u_max > base32_max,
            "base64u_max={base64u_max} should exceed base32_max={base32_max}"
        );
    }

    #[test]
    fn build_qname_base64u_rejects_payload_overflow() {
        let domain = "test.com";
        let max_payload =
            max_payload_len_for_domain_with_encoding(domain, 57, DataEncoding::Base64Url)
                .expect("max payload");
        let payload = vec![0u8; max_payload + 1];
        assert!(build_qname_with_encoding(&payload, domain, 57, DataEncoding::Base64Url).is_err());
    }
}
