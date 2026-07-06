mod base32;
mod codec;
mod dots;
mod name;
mod types;
mod wire;

pub use base32::{decode as base32_decode, encode as base32_encode, Base32Error};
pub use codec::{
    build_edns_raw_qname, decode_query, decode_query_with_domains,
    decode_query_with_domains_and_qtype, decode_response, encode_query, encode_query_compact,
    encode_query_edns_raw, encode_response, encode_response_with_ttl, is_response,
    DEFAULT_RESPONSE_TTL,
};
pub use dots::{dotify, dotify_with_label_len, undotify, DEFAULT_LABEL_LEN};
pub use types::{
    DecodeQueryError, DecodedQuery, DnsError, QueryParams, Question, Rcode, ResponseParams,
    CLASS_IN, EDNS_SLIPSTREAM_PAYLOAD_OPTION, EDNS_UDP_PAYLOAD, RR_A, RR_HTTPS, RR_OPT, RR_TXT,
    SVCPARAM_ECH,
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
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    let max_payload = max_payload_len_for_domain_with_label_len(domain, label_len)?;
    if payload.len() > max_payload {
        return Err(DnsError::new("payload too large for domain"));
    }
    let base32 = base32_encode(payload);
    let dotted = dotify_with_label_len(&base32, label_len);
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
    if max_dotted_len == 0 {
        return Ok(0);
    }
    let mut max_base32_len = 0usize;
    for len in 1..=max_dotted_len {
        let dots = (len - 1) / label_len;
        if len + dots > max_dotted_len {
            break;
        }
        max_base32_len = len;
    }

    let mut max_payload = (max_base32_len * 5) / 8;
    while max_payload > 0 && base32_len(max_payload) > max_base32_len {
        max_payload -= 1;
    }
    Ok(max_payload)
}

fn base32_len(payload_len: usize) -> usize {
    if payload_len == 0 {
        return 0;
    }
    (payload_len * 8).div_ceil(5)
}

#[cfg(test)]
mod tests {
    use super::{build_qname, max_payload_len_for_domain};

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
}
