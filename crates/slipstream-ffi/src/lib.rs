#[cfg(feature = "openssl-vendored")]
#[allow(unused_imports)]
use openssl_sys as _;
use slipstream_core::HostPort;

pub mod picoquic;
pub mod runtime;

pub use picoquic::{get_pacing_rate, get_rtt, SockaddrStorage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ResolverMode {
    Recursive = 1,
    Authoritative = 2,
}

#[derive(Debug, Clone)]
pub struct ResolverSpec {
    pub resolver: HostPort,
    pub mode: ResolverMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamEncoding {
    Qname,
    EdnsRaw,
}

#[derive(Debug)]
pub struct ClientConfig<'a> {
    pub tcp_listen_host: &'a str,
    pub tcp_listen_port: u16,
    pub resolvers: &'a [ResolverSpec],
    pub domain: &'a str,
    pub cert: Option<&'a str>,
    pub congestion_control: Option<&'a str>,
    pub gso: bool,
    pub resolver_transport: ResolverTransport,
    pub upstream_encoding: UpstreamEncoding,
    pub qname_mtu: u32,
    pub pacing_gain_probe: f64,
    pub dns_tcp_packet_loop_burst: usize,
    pub keep_alive_interval: usize,
    // --- Anti-fingerprinting / DPI-evasion knobs (defaults preserve historical behavior) ---
    /// DNS query type sent in poll queries (default 16 = TXT). The server must accept the same type
    /// (`ServerConfig`/`decode_query_with_domains_and_qtype`). NOTE: non-TXT also needs per-type
    /// answer RDATA encoding on the server, which is not implemented yet — keep 16 until it is.
    pub dns_query_type: u16,
    /// Label length (chars) for the encoded subdomain (default 57). Client-only: the server strips
    /// dots before decoding, so this only alters the on-the-wire label-length fingerprint.
    pub dns_label_length: usize,
    /// Optional cap on DNS poll queries per second (0 = unlimited, the default). Trades throughput
    /// for a lower query-rate/volume fingerprint; only engages when set > 0.
    pub max_poll_qps: u32,
    pub debug_poll: bool,
    pub debug_streams: bool,
}

pub use runtime::{
    abort_stream_bidi, configure_quic, configure_quic_with_custom, sockaddr_storage_to_socket_addr,
    socket_addr_to_storage, take_crypto_errors, take_stateless_packet_for_cid,
    write_stream_or_reset, QuicGuard, SLIPSTREAM_FILE_CANCEL_ERROR, SLIPSTREAM_INTERNAL_ERROR,
    SLIPSTREAM_MAX_DATA_CONTROL_BYTES,
};
