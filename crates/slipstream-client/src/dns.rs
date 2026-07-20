mod debug;
mod path;
mod poll;
mod resolver;
mod response;
mod transport;
mod txid;

pub(crate) use debug::maybe_report_debug;
pub(crate) use path::{add_paths, refresh_resolver_path, resolver_mode_to_c};
pub(crate) use poll::{expire_inflight_polls, send_poll_queries};
pub(crate) use resolver::{
    reset_resolver_path, resolve_resolvers, sockaddr_storage_to_socket_addr, PeerAddrMode,
    ResolverState,
};
pub(crate) use response::{handle_dns_response, DnsResponseContext};
pub(crate) use transport::DnsTransport;
pub(crate) use txid::TxidGen;

/// Translate the client's plain-bool config knob into the DNS crate's encoding choice. Kept as one
/// spot so every qname-building/parsing call site picks the same encoding the same way.
pub(crate) fn data_encoding(
    config: &slipstream_ffi::ClientConfig<'_>,
) -> slipstream_dns::DataEncoding {
    if config.base64u_encoding {
        slipstream_dns::DataEncoding::Base64Url
    } else {
        slipstream_dns::DataEncoding::Base32
    }
}
