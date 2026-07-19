use crate::base32;
use crate::base64u;
use crate::dots;

use crate::name::{encode_name, extract_subdomain_multi, parse_name};
use crate::types::{
    DataEncoding, DecodeQueryError, DecodedQuery, DnsError, QueryParams, Rcode, ResponseParams,
    BASE64U_MARKER, EDNS_SLIPSTREAM_PAYLOAD_OPTION, EDNS_UDP_PAYLOAD, RR_A, RR_AAAA, RR_CNAME,
    RR_HTTPS, RR_MX, RR_NULL, RR_OPT, RR_SRV, RR_TXT, SVCPARAM_ECH,
};
use crate::wire::{
    parse_header, parse_question, parse_question_for_reply, read_u16, read_u32, write_u16,
    write_u32,
};

pub fn decode_query(packet: &[u8], domain: &str) -> Result<DecodedQuery, DecodeQueryError> {
    decode_query_with_domains(packet, &[domain])
}

pub fn decode_query_with_domains(
    packet: &[u8],
    domains: &[&str],
) -> Result<DecodedQuery, DecodeQueryError> {
    decode_query_with_domains_and_qtype(packet, domains, RR_TXT)
}

/// Every query/answer type this server knows how to encode an answer for (see
/// [`encode_answer_rdata`]). The query-type choice is meant to be purely a client-side knob (a
/// client picks whichever type its network doesn't filter) with no server reconfiguration needed,
/// so the server accepts any of these unconditionally rather than requiring an operator to
/// pre-select one alternate type to allow.
fn is_supported_answer_qtype(qtype: u16) -> bool {
    matches!(
        qtype,
        RR_TXT | RR_HTTPS | RR_A | RR_AAAA | RR_CNAME | RR_MX | RR_SRV | RR_NULL
    )
}

/// Like [`decode_query_with_domains`] but also accepts queries whose qtype equals `accepted_qtype`,
/// in addition to every type in [`is_supported_answer_qtype`] (which are always accepted -- see its
/// doc comment). `accepted_qtype` exists for operators who want to explicitly allow some other,
/// not-yet-hardcoded type without a code change; it is not needed for any of the types this server
/// already knows how to answer.
pub fn decode_query_with_domains_and_qtype(
    packet: &[u8],
    domains: &[&str],
    accepted_qtype: u16,
) -> Result<DecodedQuery, DecodeQueryError> {
    let header = match parse_header(packet) {
        Some(header) => header,
        None => return Err(DecodeQueryError::Drop),
    };

    let rd = header.rd;
    let cd = header.cd;

    if header.is_response {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    if header.qdcount != 1 {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    let (question, after_question) = match parse_question(packet, header.offset) {
        Ok((question, offset)) => (question, offset),
        Err(_) => return Err(DecodeQueryError::Drop),
    };

    // Accept any type we can actually answer, plus whatever extra type the operator configured.
    // The answer is encoded to match each query's own qtype.
    if !is_supported_answer_qtype(question.qtype) && question.qtype != accepted_qtype {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::Ok,
        });
    }

    let subdomain_raw = match extract_subdomain_multi(&question.name, domains) {
        Ok(subdomain_raw) => subdomain_raw,
        Err(rcode) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode,
            })
        }
    };

    if subdomain_raw.eq_ignore_ascii_case("_s") {
        let payload = match parse_edns_raw_payload(packet, after_question, header.arcount) {
            Some(payload) if !payload.is_empty() => payload,
            _ => {
                return Err(DecodeQueryError::Reply {
                    id: header.id,
                    rd,
                    cd,
                    question: Some(question),
                    // NXDOMAIN, not SERVFAIL: an undecodable/garbage query (e.g. corrupted in
                    // transit) must not make us look like a failing authoritative server.
                    // Recursive resolvers retry SERVFAIL ~3x (amplifying load against per-client
                    // query-rate limits, e.g. Megafon ~50 q/s) and may damp/blacklist the domain;
                    // NXDOMAIN is cacheable and handled gently. Valid tunnel queries still decode
                    // and get their TXT, so this only changes the error path.
                    rcode: Rcode::NameError,
                });
            }
        };
        return Ok(DecodedQuery {
            id: header.id,
            rd,
            cd,
            question,
            payload,
            // EDNS-raw carries the payload out of band; there's no name-encoding choice to make,
            // so this only matters if the server later needs to pick a CNAME/MX/SRV answer
            // encoding for it, in which case the safe default is fine.
            encoding: DataEncoding::default(),
        });
    }

    let undotted = dots::undotify(&subdomain_raw);
    if undotted.is_empty() {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    let (encoding, encoded) = split_encoding_marker(&undotted);
    let payload = match decode_encoded_payload(encoding, encoded) {
        Ok(payload) => payload,
        Err(_) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                // NXDOMAIN, not SERVFAIL (see the `_s` branch above): an undecodable qname is
                // just a bogus name, not a server failure. Avoids resolver retry-amplification
                // and domain damping under per-client query-rate limits.
                rcode: Rcode::NameError,
            });
        }
    };

    Ok(DecodedQuery {
        id: header.id,
        rd,
        cd,
        question,
        payload,
        encoding,
    })
}

/// Detects the base64u marker prefix (see [`BASE64U_MARKER`]) on an already-undotted query
/// payload and strips it, returning which encoding to use and the remaining encoded data. The
/// marker check is case-insensitive (`_`/letters survive resolver case-folding fine either way);
/// it's the base64u payload *after* it that's at risk if a hop mangles case, not detection itself.
fn split_encoding_marker(undotted: &str) -> (DataEncoding, &str) {
    if undotted.len() >= BASE64U_MARKER.len()
        && undotted.is_char_boundary(BASE64U_MARKER.len())
        && undotted.as_bytes()[..BASE64U_MARKER.len()]
            .eq_ignore_ascii_case(BASE64U_MARKER.as_bytes())
    {
        (DataEncoding::Base64Url, &undotted[BASE64U_MARKER.len()..])
    } else {
        (DataEncoding::Base32, undotted)
    }
}

fn decode_encoded_payload(encoding: DataEncoding, data: &str) -> Result<Vec<u8>, ()> {
    match encoding {
        DataEncoding::Base32 => base32::decode(data).map_err(|_| ()),
        DataEncoding::Base64Url => base64u::decode(data).map_err(|_| ()),
    }
}

pub fn build_edns_raw_qname(domain: &str) -> Result<String, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    Ok(format!("_s.{}.", domain))
}

pub fn encode_query(params: &QueryParams<'_>) -> Result<Vec<u8>, DnsError> {
    encode_query_inner(params, true)
}

pub fn encode_query_compact(params: &QueryParams<'_>) -> Result<Vec<u8>, DnsError> {
    encode_query_inner(params, false)
}

fn encode_query_inner(params: &QueryParams<'_>, include_opt: bool) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(256);
    let mut flags = 0u16;
    if !params.is_query {
        flags |= 0x8000;
    }
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, params.qdcount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, if include_opt { 1 } else { 0 });

    if params.qdcount > 0 {
        encode_name(params.qname, &mut out)?;
        write_u16(&mut out, params.qtype);
        write_u16(&mut out, params.qclass);
    }

    if include_opt {
        encode_opt_record(&mut out)?;
    }

    Ok(out)
}

pub fn encode_query_edns_raw(
    id: u16,
    qname: &str,
    payload: &[u8],
    rd: bool,
    cd: bool,
) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(64 + payload.len());
    let mut flags = 0u16;
    if rd {
        flags |= 0x0100;
    }
    if cd {
        flags |= 0x0010;
    }

    write_u16(&mut out, id);
    write_u16(&mut out, flags);
    write_u16(&mut out, 1);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    encode_name(qname, &mut out)?;
    write_u16(&mut out, RR_TXT);
    write_u16(&mut out, crate::types::CLASS_IN);

    encode_opt_record_with_payload(&mut out, Some(payload))?;
    Ok(out)
}

/// Default answer TTL (seconds) used by [`encode_response`]. Configurable via
/// [`encode_response_with_ttl`] so the server can vary/randomize it and avoid a constant-TTL
/// fingerprint on the response side.
pub const DEFAULT_RESPONSE_TTL: u32 = 60;

pub fn encode_response(params: &ResponseParams<'_>) -> Result<Vec<u8>, DnsError> {
    encode_response_with_ttl(params, DEFAULT_RESPONSE_TTL)
}

/// Raw payload bytes a chunk of [`RR_CNAME`]/[`RR_MX`]/[`RR_SRV`] data can carry when base32-encoded
/// (150*8/5 = 240 chars exactly, no padding) and dotted into 63-char labels, that's 240 + 3 dots =
/// 243 wire "name length" bytes -- comfortably under the 253-byte DNS name limit.
const NAME_CARRIER_CHUNK_BYTES: usize = 150;

/// Same as [`NAME_CARRIER_CHUNK_BYTES`] but for base64u: 187*8/6 = 250 chars (ceil, no padding),
/// dotted into 63-char labels is 4 labels / 3 dots, 250 + 3 = 253 -- the largest chunk that still
/// exactly fits the 253-byte name limit (188 bytes would need 254). base64u's 6-bit chars pack more
/// densely than base32's 5-bit ones, so the same name budget carries more payload per record.
const NAME_CARRIER_CHUNK_BYTES_BASE64U: usize = 187;

/// Max raw payload bytes a single answer record of `qtype` can carry. `None` means the type carries
/// the whole payload in one record, self-length-delimited within its own RDATA (TXT's per-string
/// length prefixes, HTTPS's SvcParam length, NULL's rdlen). `Some(n)` means the payload is split
/// across multiple same-type answer records of up to `n` bytes each; `n` depends on `encoding` for
/// the name-carrier types since it packs a different number of bits per wire character.
fn max_bytes_per_record(qtype: u16, encoding: DataEncoding) -> Option<usize> {
    match qtype {
        RR_A => Some(4),
        RR_AAAA => Some(16),
        RR_CNAME | RR_MX | RR_SRV => Some(match encoding {
            DataEncoding::Base32 => NAME_CARRIER_CHUNK_BYTES,
            DataEncoding::Base64Url => NAME_CARRIER_CHUNK_BYTES_BASE64U,
        }),
        _ => None,
    }
}

pub fn encode_response_with_ttl(
    params: &ResponseParams<'_>,
    answer_ttl: u32,
) -> Result<Vec<u8>, DnsError> {
    let payload_len = params.payload.map(|payload| payload.len()).unwrap_or(0);
    let mut out = Vec::with_capacity(256 + payload_len * 2);
    encode_response_with_ttl_into(params, answer_ttl, &mut out)?;
    Ok(out)
}

/// Like [`encode_response_with_ttl`], but reuses `out`'s allocation (clears first).
/// Hot path on the DNS-tunnel server under multi-kQPS load — avoids a malloc per reply.
pub fn encode_response_with_ttl_into(
    params: &ResponseParams<'_>,
    answer_ttl: u32,
    out: &mut Vec<u8>,
) -> Result<(), DnsError> {
    let payload_len = params.payload.map(|payload| payload.len()).unwrap_or(0);
    let payload = params.payload.unwrap_or(&[]);
    let per_record = max_bytes_per_record(params.question.qtype, params.encoding);

    let mut rcode = params.rcode.unwrap_or(if payload_len > 0 {
        Rcode::Ok
    } else {
        Rcode::NameError
    });

    let mut ancount = 0u16;
    if payload_len > 0 && rcode == Rcode::Ok {
        let count = match per_record {
            Some(n) => payload_len.div_ceil(n),
            None => 1,
        };
        if count > u16::MAX as usize {
            return Err(DnsError::new("payload too long"));
        }
        ancount = count as u16;
    } else if params.rcode.is_some() {
        rcode = params.rcode.unwrap_or(Rcode::Ok);
    }

    out.clear();
    let need = 256 + payload_len * 2;
    if out.capacity() < need {
        out.reserve(need - out.capacity());
    }
    let mut flags = 0x8000 | 0x0400;
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }
    flags |= rcode.to_u8() as u16;

    write_u16(out, params.id);
    write_u16(out, flags);
    write_u16(out, 1);
    write_u16(out, ancount);
    write_u16(out, 0);
    write_u16(out, 1);

    encode_name(&params.question.name, out)?;
    write_u16(out, params.question.qtype);
    write_u16(out, params.question.qclass);

    let chunk_size = per_record.unwrap_or(payload_len);
    let mut cursor = 0usize;
    for _ in 0..ancount {
        let remaining = payload_len - cursor;
        let this_chunk = chunk_size.min(remaining);
        let chunk = &payload[cursor..cursor + this_chunk];
        cursor += this_chunk;

        out.extend_from_slice(&[0xC0, 0x0C]);
        write_u16(out, params.question.qtype);
        write_u16(out, params.question.qclass);
        write_u32(out, answer_ttl);
        encode_answer_rdata(params.question.qtype, chunk, params.encoding, out)?;
    }

    encode_opt_record(out)?;

    Ok(())
}

/// Encode one answer record's RDATA (length-prefixed) for `chunk` of the tunnel payload, per
/// `qtype`'s wire format. Called once per answer record; for single-record types (TXT/HTTPS/NULL)
/// `chunk` is the whole payload, for chunked types (A/AAAA/CNAME/MX/SRV) it's one slice of it.
fn encode_answer_rdata(
    qtype: u16,
    chunk: &[u8],
    encoding: DataEncoding,
    out: &mut Vec<u8>,
) -> Result<(), DnsError> {
    match qtype {
        RR_HTTPS => {
            // SVCB/HTTPS (RFC 9460) rdata carrying the tunnel payload in an opaque `ech` SvcParam:
            //   SvcPriority(2)=1 | TargetName(1)=root 0x00 | SvcParam{ key=ech(5), len(2), value=payload }
            // High capacity like TXT, but on the wire it reads as a normal HTTPS record with an ECH
            // config -- clients query type 65 constantly and ECH values are legitimately opaque binary.
            let rdata_len = 2 + 1 + 2 + 2 + chunk.len();
            if rdata_len > u16::MAX as usize {
                return Err(DnsError::new("payload too long"));
            }
            write_u16(out, rdata_len as u16);
            write_u16(out, 1); // SvcPriority = 1 (ServiceMode)
            out.push(0); // TargetName = "." (root, i.e. same as owner name)
            write_u16(out, SVCPARAM_ECH); // SvcParamKey = ech (5)
            write_u16(out, chunk.len() as u16); // SvcParamValue length
            out.extend_from_slice(chunk);
        }
        RR_A | RR_AAAA | RR_NULL => {
            // Raw bytes, rdlen = chunk.len(). A/AAAA are nominally fixed-size (4/16 bytes) per
            // RFC, so a final short chunk produces a non-standard rdlen; we accept that tradeoff
            // to avoid a padding/length-disambiguation scheme -- our own decoder (the only thing
            // that ever interprets these bytes) reads whatever rdlen says. A strict validating
            // resolver could in principle reject a non-4/16-byte A/AAAA record; caching-only
            // resolvers (the common case in front of this tunnel) just relay rdata opaquely.
            if chunk.len() > u16::MAX as usize {
                return Err(DnsError::new("payload too long"));
            }
            write_u16(out, chunk.len() as u16);
            out.extend_from_slice(chunk);
        }
        RR_CNAME => {
            let mut name_buf = Vec::new();
            encode_data_name(chunk, encoding, &mut name_buf)?;
            if name_buf.len() > u16::MAX as usize {
                return Err(DnsError::new("payload too long"));
            }
            write_u16(out, name_buf.len() as u16);
            out.extend_from_slice(&name_buf);
        }
        RR_MX => {
            // 2-byte preference (fixed; not used to carry data) + exchange name.
            let mut name_buf = Vec::new();
            encode_data_name(chunk, encoding, &mut name_buf)?;
            let rdata_len = 2 + name_buf.len();
            if rdata_len > u16::MAX as usize {
                return Err(DnsError::new("payload too long"));
            }
            write_u16(out, rdata_len as u16);
            write_u16(out, 10); // preference: an unremarkable, plausible-looking value
            out.extend_from_slice(&name_buf);
        }
        RR_SRV => {
            // priority(2) + weight(2) + port(2) (fixed; not used to carry data) + target name.
            let mut name_buf = Vec::new();
            encode_data_name(chunk, encoding, &mut name_buf)?;
            let rdata_len = 6 + name_buf.len();
            if rdata_len > u16::MAX as usize {
                return Err(DnsError::new("payload too long"));
            }
            write_u16(out, rdata_len as u16);
            write_u16(out, 0); // priority
            write_u16(out, 0); // weight
            write_u16(out, 443); // port: an unremarkable, plausible-looking value
            out.extend_from_slice(&name_buf);
        }
        _ => {
            // TXT (default / fallback): payload split into 255-byte character-strings.
            let chunk_count = chunk.len().div_ceil(255);
            let rdata_len = chunk.len() + chunk_count;
            if rdata_len > u16::MAX as usize {
                return Err(DnsError::new("payload too long"));
            }
            write_u16(out, rdata_len as u16);
            let mut remaining = chunk.len();
            let mut cursor = 0;
            while remaining > 0 {
                let string_len = remaining.min(255);
                out.push(string_len as u8);
                out.extend_from_slice(&chunk[cursor..cursor + string_len]);
                cursor += string_len;
                remaining -= string_len;
            }
        }
    }
    Ok(())
}

/// Encode `chunk` as a wire-format domain name (base32/base64u -> dotted labels -> length-prefixed
/// labels), used as the RDATA (or RDATA tail, for MX/SRV) of the name-carrier answer types. No
/// marker prefix here (unlike the query side): the client already knows which encoding it asked
/// for, so the answer just needs to match it, no in-band signal required.
fn encode_data_name(
    chunk: &[u8],
    encoding: DataEncoding,
    out: &mut Vec<u8>,
) -> Result<(), DnsError> {
    let encoded = match encoding {
        DataEncoding::Base32 => base32::encode(chunk),
        DataEncoding::Base64Url => base64u::encode(chunk),
    };
    let dotted = dots::dotify_with_label_len(&encoded, 63);
    encode_name(&dotted, out)
}

/// Like [`decode_response`] but for a client configured to use base64u for its own queries; the
/// server mirrors whatever encoding the query used (see [`encode_data_name`]), so the client must
/// pass the same choice back here to decode CNAME/MX/SRV answers correctly.
pub fn decode_response_with_encoding(packet: &[u8], encoding: DataEncoding) -> Option<Vec<u8>> {
    let header = parse_header(packet)?;
    if !header.is_response {
        return None;
    }
    let rcode = header.rcode?;
    if rcode != Rcode::Ok {
        return None;
    }
    if header.ancount < 1 {
        return None;
    }

    let mut offset = header.offset;
    for _ in 0..header.qdcount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 4 > packet.len() {
            return None;
        }
        offset += 4;
    }

    let mut out = Vec::new();
    let mut answer_qtype: Option<u16> = None;
    for _ in 0..header.ancount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 10 > packet.len() {
            return None;
        }
        let qtype = read_u16(packet, offset)?;
        offset += 2;
        let _qclass = read_u16(packet, offset)?;
        offset += 2;
        let _ttl = read_u32(packet, offset)?;
        offset += 4;
        let rdlen = read_u16(packet, offset)? as usize;
        offset += 2;
        if offset + rdlen > packet.len() || rdlen < 1 {
            return None;
        }
        let rdata_start = offset;
        let rdata = packet.get(offset..offset + rdlen)?;
        offset += rdlen;

        // A multi-record answer must be internally consistent -- every record the same type.
        match answer_qtype {
            None => answer_qtype = Some(qtype),
            Some(t) if t == qtype => {}
            _ => return None,
        }

        out.extend_from_slice(&decode_answer_rdata(
            qtype,
            packet,
            rdata_start,
            rdata,
            encoding,
        )?);
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub fn decode_response(packet: &[u8]) -> Option<Vec<u8>> {
    decode_response_with_encoding(packet, DataEncoding::Base32)
}

/// Decode one answer record's RDATA back into its slice of the tunnel payload, per `qtype`'s wire
/// format (the mirror of [`encode_answer_rdata`]). `rdata_start` is `rdata`'s absolute offset in
/// `packet`, needed by the name-carrier types to call [`parse_name`].
fn decode_answer_rdata(
    qtype: u16,
    packet: &[u8],
    rdata_start: usize,
    rdata: &[u8],
    encoding: DataEncoding,
) -> Option<Vec<u8>> {
    match qtype {
        RR_TXT => {
            let mut remaining = rdata.len();
            let mut cursor = 0usize;
            let mut out = Vec::with_capacity(rdata.len());
            while remaining > 0 {
                let string_len = *rdata.get(cursor)? as usize;
                cursor += 1;
                remaining -= 1;
                if string_len > remaining {
                    return None;
                }
                out.extend_from_slice(rdata.get(cursor..cursor + string_len)?);
                cursor += string_len;
                remaining -= string_len;
            }
            Some(out)
        }
        RR_HTTPS => decode_svcb_ech_payload(rdata),
        RR_A | RR_AAAA | RR_NULL => Some(rdata.to_vec()),
        RR_CNAME => decode_data_name(packet, rdata_start, encoding),
        RR_MX if rdata.len() >= 2 => decode_data_name(packet, rdata_start + 2, encoding),
        RR_SRV if rdata.len() >= 6 => decode_data_name(packet, rdata_start + 6, encoding),
        _ => None,
    }
}

/// Decode a name-carrier answer's embedded domain name (starting at `name_start` in `packet`) back
/// into raw payload bytes: parse the wire name, strip dots, base32/base64u-decode per `encoding`.
fn decode_data_name(packet: &[u8], name_start: usize, encoding: DataEncoding) -> Option<Vec<u8>> {
    let (name, _) = parse_name(packet, name_start).ok()?;
    let undotted = dots::undotify(name.trim_end_matches('.'));
    match encoding {
        DataEncoding::Base32 => base32::decode(&undotted).ok(),
        DataEncoding::Base64Url => base64u::decode(&undotted).ok(),
    }
}

/// Extract the tunnel payload carried in an SVCB/HTTPS record's `ech` SvcParam (RFC 9460).
/// rdata layout: SvcPriority(2) | TargetName | SvcParams[ key(2) len(2) value(len) ]* .
fn decode_svcb_ech_payload(rdata: &[u8]) -> Option<Vec<u8>> {
    if rdata.len() < 2 {
        return None;
    }
    let mut cursor = 2usize; // skip SvcPriority
                             // Skip TargetName (uncompressed length-prefixed labels ending in a 0 byte).
    loop {
        let label_len = *rdata.get(cursor)? as usize;
        cursor += 1;
        if label_len == 0 {
            break;
        }
        if label_len >= 0xC0 {
            return None; // SVCB target names are not compressed
        }
        cursor += label_len;
        if cursor > rdata.len() {
            return None;
        }
    }
    // Walk SvcParams for the ech key.
    while cursor + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[cursor], rdata[cursor + 1]]);
        let len = u16::from_be_bytes([rdata[cursor + 2], rdata[cursor + 3]]) as usize;
        cursor += 4;
        let value = rdata.get(cursor..cursor + len)?;
        if key == SVCPARAM_ECH {
            return if value.is_empty() {
                None
            } else {
                Some(value.to_vec())
            };
        }
        cursor += len;
    }
    None
}

pub fn is_response(packet: &[u8]) -> bool {
    parse_header(packet)
        .map(|header| header.is_response)
        .unwrap_or(false)
}

fn encode_opt_record(out: &mut Vec<u8>) -> Result<(), DnsError> {
    encode_opt_record_with_payload(out, None)
}

fn encode_opt_record_with_payload(
    out: &mut Vec<u8>,
    payload: Option<&[u8]>,
) -> Result<(), DnsError> {
    out.push(0);
    write_u16(out, RR_OPT);
    write_u16(out, EDNS_UDP_PAYLOAD);
    write_u32(out, 0);
    let rdlen = payload.map(|payload| payload.len() + 4).unwrap_or(0);
    if rdlen > u16::MAX as usize {
        return Err(DnsError::new("EDNS payload too long"));
    }
    write_u16(out, rdlen as u16);
    if let Some(payload) = payload {
        write_u16(out, EDNS_SLIPSTREAM_PAYLOAD_OPTION);
        write_u16(out, payload.len() as u16);
        out.extend_from_slice(payload);
    }
    Ok(())
}

fn parse_edns_raw_payload(packet: &[u8], mut offset: usize, arcount: u16) -> Option<Vec<u8>> {
    for _ in 0..arcount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 10 > packet.len() {
            return None;
        }
        let rr_type = read_u16(packet, offset)?;
        offset += 2;
        let _rr_class = read_u16(packet, offset)?;
        offset += 2;
        let _ttl = read_u32(packet, offset)?;
        offset += 4;
        let rdlen = read_u16(packet, offset)? as usize;
        offset += 2;
        if offset + rdlen > packet.len() {
            return None;
        }
        if rr_type == RR_OPT {
            let end = offset + rdlen;
            let mut cursor = offset;
            while cursor + 4 <= end {
                let code = read_u16(packet, cursor)?;
                cursor += 2;
                let len = read_u16(packet, cursor)? as usize;
                cursor += 2;
                if cursor + len > end {
                    return None;
                }
                if code == EDNS_SLIPSTREAM_PAYLOAD_OPTION {
                    return Some(packet[cursor..cursor + len].to_vec());
                }
                cursor += len;
            }
        }
        offset += rdlen;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        decode_response_with_encoding, encode_query, encode_response, DEFAULT_RESPONSE_TTL,
    };
    use crate::codec::encode_response_with_ttl;
    use crate::types::{
        DataEncoding, QueryParams, Question, ResponseParams, CLASS_IN, EDNS_UDP_PAYLOAD, RR_A,
        RR_AAAA, RR_CNAME, RR_HTTPS, RR_MX, RR_NULL, RR_OPT, RR_SRV, RR_TXT,
    };

    /// Shared round-trip check used by every per-type test below: encode a response carrying
    /// `payload` as `qtype`'s answer using `encoding`, then decode it back and assert byte-for-byte
    /// equality. This is the tunnel's actual encode/decode mechanism, so it doubles as a minimal
    /// end-to-end test of "does this Response Type (and encoding) carry a tunnel payload correctly."
    fn round_trip(qtype: u16, encoding: DataEncoding, payload: &[u8]) {
        let question = Question {
            name: "abc.tunnel.example.com.".to_string(),
            qtype,
            qclass: CLASS_IN,
        };
        let encoded = encode_response_with_ttl(
            &ResponseParams {
                id: 0x4242,
                rd: true,
                cd: false,
                question: &question,
                payload: Some(payload),
                rcode: None,
                encoding,
            },
            DEFAULT_RESPONSE_TTL,
        )
        .unwrap_or_else(|e| panic!("encode qtype={qtype} encoding={encoding:?} response: {e}"));
        let decoded = decode_response_with_encoding(&encoded, encoding)
            .unwrap_or_else(|| panic!("decode qtype={qtype} encoding={encoding:?} response"));
        assert_eq!(
            decoded, payload,
            "round-trip mismatch for qtype={qtype} encoding={encoding:?}"
        );
    }

    #[test]
    fn encode_response_https_svcb_round_trips_payload() {
        let payload: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        round_trip(RR_HTTPS, DataEncoding::Base32, &payload);
    }

    #[test]
    fn encode_response_txt_round_trips_payload() {
        let payload: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        round_trip(RR_TXT, DataEncoding::Base32, &payload);
    }

    #[test]
    fn encode_response_a_round_trips_payload() {
        // 600 bytes / 4 bytes-per-record = 150 answer records; exercises multi-record chunking
        // and a non-multiple-of-4 final chunk (150 * 4 = 600 exactly here, so add one more test
        // with an odd length to hit the padding-free final-chunk path too).
        let payload: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        round_trip(RR_A, DataEncoding::Base32, &payload);
        let odd_payload: Vec<u8> = (0u16..601).map(|i| (i % 256) as u8).collect();
        round_trip(RR_A, DataEncoding::Base32, &odd_payload);
    }

    #[test]
    fn encode_response_aaaa_round_trips_payload() {
        let payload: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        round_trip(RR_AAAA, DataEncoding::Base32, &payload);
        let odd_payload: Vec<u8> = (0u16..611).map(|i| (i % 256) as u8).collect();
        round_trip(RR_AAAA, DataEncoding::Base32, &odd_payload);
    }

    #[test]
    fn encode_response_cname_round_trips_payload() {
        let payload: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        round_trip(RR_CNAME, DataEncoding::Base32, &payload);
    }

    #[test]
    fn encode_response_mx_round_trips_payload() {
        let payload: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        round_trip(RR_MX, DataEncoding::Base32, &payload);
    }

    #[test]
    fn encode_response_srv_round_trips_payload() {
        let payload: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        round_trip(RR_SRV, DataEncoding::Base32, &payload);
    }

    #[test]
    fn encode_response_null_round_trips_payload() {
        let payload: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        round_trip(RR_NULL, DataEncoding::Base32, &payload);
    }

    #[test]
    fn encode_response_small_payload_round_trips_for_every_type() {
        // A single byte is the sharpest edge case for the name-carrier types (shortest possible
        // encoded chunk) and for A/AAAA (single record far short of the 4/16-byte "standard" size).
        let payload = [0xABu8];
        for qtype in [
            RR_TXT, RR_HTTPS, RR_A, RR_AAAA, RR_CNAME, RR_MX, RR_SRV, RR_NULL,
        ] {
            round_trip(qtype, DataEncoding::Base32, &payload);
        }
    }

    #[test]
    fn encode_response_cname_base64u_round_trips_payload() {
        // base64u only changes anything for the name-carrier types (CNAME/MX/SRV); this also
        // exercises the larger NAME_CARRIER_CHUNK_BYTES_BASE64U chunk size (multi-record chunking
        // at 187 bytes/record instead of base32's 150).
        let payload: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        round_trip(RR_CNAME, DataEncoding::Base64Url, &payload);
    }

    #[test]
    fn encode_response_mx_base64u_round_trips_payload() {
        let payload: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        round_trip(RR_MX, DataEncoding::Base64Url, &payload);
    }

    #[test]
    fn encode_response_srv_base64u_round_trips_payload() {
        let payload: Vec<u8> = (0u16..600).map(|i| (i % 256) as u8).collect();
        round_trip(RR_SRV, DataEncoding::Base64Url, &payload);
    }

    #[test]
    fn encode_response_base64u_small_payload_round_trips_for_name_carrier_types() {
        let payload = [0xABu8];
        for qtype in [RR_CNAME, RR_MX, RR_SRV] {
            round_trip(qtype, DataEncoding::Base64Url, &payload);
        }
    }

    #[test]
    fn encode_response_base64u_chunk_boundary_round_trips() {
        // Exercise the exact NAME_CARRIER_CHUNK_BYTES_BASE64U boundary (187 bytes): one byte under,
        // exactly at, and one byte over -- the last forces a second answer record.
        for len in [186usize, 187, 188] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            round_trip(RR_CNAME, DataEncoding::Base64Url, &payload);
        }
    }

    #[test]
    fn encode_query_includes_edns_opt_for_udp_payload() {
        let params = QueryParams {
            id: 0x1234,
            qname: "payload.example.com.",
            qtype: RR_TXT,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
        };

        let packet = encode_query(&params).expect("encode query");

        assert_eq!(u16::from_be_bytes([packet[10], packet[11]]), 1);
        assert!(packet.len() >= 11);
        let opt = &packet[packet.len() - 11..];
        assert_eq!(opt[0], 0);
        assert_eq!(u16::from_be_bytes([opt[1], opt[2]]), RR_OPT);
        assert_eq!(u16::from_be_bytes([opt[3], opt[4]]), EDNS_UDP_PAYLOAD);
    }

    #[test]
    fn encode_response_rejects_large_payload() {
        let question = Question {
            name: "a.test.com.".to_string(),
            qtype: RR_TXT,
            qclass: CLASS_IN,
        };
        let payload = vec![0u8; u16::MAX as usize];
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(&payload),
            rcode: None,
            encoding: DataEncoding::Base32,
        };
        assert!(encode_response(&params).is_err());
    }
}
