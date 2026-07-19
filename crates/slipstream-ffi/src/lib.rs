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
    /// Verify the server's certificate chain against the OS's default CA bundle, like a normal
    /// HTTPS client (full chain + hostname check, via picotls/OpenSSL) -- as opposed to `cert`
    /// (pin one exact leaf) or neither (no verification at all). Mutually exclusive with `cert`;
    /// callers are expected to enforce that (see `slipstream-client`'s CLI).
    pub verify_system_ca: bool,
    pub congestion_control: Option<&'a str>,
    pub gso: bool,
    pub resolver_transport: ResolverTransport,
    pub upstream_encoding: UpstreamEncoding,
    pub qname_mtu: u32,
    pub pacing_gain_probe: f64,
    pub dns_tcp_packet_loop_burst: usize,
    pub keep_alive_interval: usize,
    // --- Anti-fingerprinting / DPI-evasion knobs (defaults preserve historical behavior) ---
    /// DNS query type sent in poll queries (default 16 = TXT). Purely a client choice: the server
    /// (`decode_query_with_domains_and_qtype`) accepts every type it knows how to answer
    /// unconditionally, no matching server config needed.
    pub dns_query_type: u16,
    /// Label length (chars) for the encoded subdomain (default 57). Client-only: the server strips
    /// dots before decoding, so this only alters the on-the-wire label-length fingerprint.
    pub dns_label_length: usize,
    /// Encode the tunnel payload with base64u instead of base32 in DNS query/answer names (default
    /// false = base32). Purely a client choice: the server detects it per-query via a marker
    /// prefix (`slipstream_dns::DataEncoding`), no server config needed. ~20% denser than base32,
    /// but case-sensitive -- only safe once the exact resolver path is confirmed to preserve label
    /// case end to end (a resolver/cache that normalizes case would silently corrupt the payload
    /// rather than fail cleanly).
    pub base64u_encoding: bool,
    /// Optional cap on DNS poll queries per second (0 = unlimited, the default). Trades throughput
    /// for a lower query-rate/volume fingerprint; only engages when set > 0.
    pub max_poll_qps: u32,
    pub debug_poll: bool,
    pub debug_streams: bool,
}

pub use runtime::{
    abort_stream_bidi, configure_quic, configure_quic_with_custom,
    set_server_half_open_retry_threshold, set_server_stream_data_control,
    sockaddr_storage_to_socket_addr, socket_addr_to_storage, take_crypto_errors,
    take_stateless_packet_for_cid, write_stream_or_reset, QuicGuard,
    SLIPSTREAM_FILE_CANCEL_ERROR, SLIPSTREAM_INTERNAL_ERROR, SLIPSTREAM_MAX_DATA_CONTROL_BYTES,
    SLIPSTREAM_MODERATE_STREAM_DATA_BYTES,
};
