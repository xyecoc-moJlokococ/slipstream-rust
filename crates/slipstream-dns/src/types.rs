use std::fmt;

pub const RR_A: u16 = 1;
pub const RR_CNAME: u16 = 5;
pub const RR_MX: u16 = 15;
pub const RR_TXT: u16 = 16;
pub const RR_AAAA: u16 = 28;
pub const RR_SRV: u16 = 33;
pub const RR_OPT: u16 = 41;
/// SVCB/HTTPS resource-record type (RFC 9460). Used as an optional, less-suspicious carrier for the
/// tunnel download payload (browsers query type 65 constantly; its ECH SvcParam is opaque binary).
pub const RR_HTTPS: u16 = 65;
/// Experimental record type (RFC 1035 §3.3.10) with fully opaque RDATA: no legitimate production
/// use, so some resolvers refuse or strip it, but if it gets through it carries the payload with
/// zero encoding overhead, same as TXT/HTTPS.
pub const RR_NULL: u16 = 10;
/// `ech` SvcParamKey (RFC 9460 §14): opaque value, used to carry the tunnel payload in HTTPS mode.
pub const SVCPARAM_ECH: u16 = 5;
pub const CLASS_IN: u16 = 1;
pub const EDNS_UDP_PAYLOAD: u16 = 1232;
pub const EDNS_SLIPSTREAM_PAYLOAD_OPTION: u16 = 65001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    Ok,
    FormatError,
    ServerFailure,
    NameError,
}

impl Rcode {
    pub fn to_u8(self) -> u8 {
        match self {
            Rcode::Ok => 0,
            Rcode::FormatError => 1,
            Rcode::ServerFailure => 2,
            Rcode::NameError => 3,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Rcode::Ok),
            1 => Some(Rcode::FormatError),
            2 => Some(Rcode::ServerFailure),
            3 => Some(Rcode::NameError),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// How the tunnel payload is packed into DNS-label-safe characters. The choice is carried
/// per-query (see [`crate::codec::decode_query_with_domains_and_qtype`]'s marker-prefix
/// detection), never server-configured -- a client picks whichever encoding it wants and the
/// server just reads what's there, same "no server reconfiguration needed" design as the query
/// type knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataEncoding {
    /// 5 bits/char, `A-Z2-7`. Decodes upper and lower case identically (see `base32::decode`),
    /// so it survives a resolver hop that normalizes name case. The safe default.
    #[default]
    Base32,
    /// 6 bits/char (~20% denser), RFC 4648 §5 alphabet. Case-sensitive by construction: a
    /// resolver that normalizes case will silently corrupt the payload rather than fail cleanly.
    /// Opt-in only, and only safe once the exact resolver path has been verified to preserve case.
    Base64Url,
}

/// Reserved prefix marking a base64u-encoded query payload (see [`DataEncoding`]). Underscore is
/// outside base32's `A-Z2-7` alphabet, so a marker-prefixed payload can never collide with a
/// genuine base32 one -- detection needs no server-side config, just this one string.
pub(crate) const BASE64U_MARKER: &str = "_u";

#[derive(Debug, Clone)]
pub struct DecodedQuery {
    pub id: u16,
    pub rd: bool,
    pub cd: bool,
    pub question: Question,
    pub payload: Vec<u8>,
    pub encoding: DataEncoding,
}

#[derive(Debug, Clone)]
pub enum DecodeQueryError {
    Drop,
    Reply {
        id: u16,
        rd: bool,
        cd: bool,
        question: Option<Question>,
        rcode: Rcode,
    },
}

#[derive(Debug, Clone)]
pub struct QueryParams<'a> {
    pub id: u16,
    pub qname: &'a str,
    pub qtype: u16,
    pub qclass: u16,
    pub rd: bool,
    pub cd: bool,
    pub qdcount: u16,
    pub is_query: bool,
}

#[derive(Debug, Clone)]
pub struct ResponseParams<'a> {
    pub id: u16,
    pub rd: bool,
    pub cd: bool,
    pub question: &'a Question,
    pub payload: Option<&'a [u8]>,
    pub rcode: Option<Rcode>,
    /// Encoding for the name-carrier answer types (CNAME/MX/SRV); ignored otherwise. Should match
    /// whatever the originating query used (see [`DataEncoding`]) so the client's own choice
    /// round-trips without any server-side coordination.
    pub encoding: DataEncoding,
}

#[derive(Debug, Clone)]
pub struct DnsError {
    message: String,
}

impl DnsError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DnsError {}
