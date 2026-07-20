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

/// Pure form of [`min_label_length`]: smallest label length for a `base`/`jitter` pair.
fn min_label_len(base: usize, jitter: u32) -> usize {
    let base = base.clamp(1, 63);
    base.saturating_sub(jitter as usize).max(1)
}

/// The smallest label length any query might use given the configured base length and jitter. The
/// transport MTU is sized at this worst case (shorter labels -> more dots -> a longer name for the
/// same payload) so a jittered name can never overflow the 253-byte DNS name limit. Always >= 1.
pub(crate) fn min_label_length(config: &slipstream_ffi::ClientConfig<'_>) -> usize {
    min_label_len(config.dns_label_length, config.dns_label_length_jitter)
}

/// Pure form of [`pick_label_length`], taking the raw `base`/`jitter` and a draw fn so the
/// MTU-safety invariant (`min_label_len <= result <= base`) is unit-testable without a full config.
fn pick_label_len(base: usize, jitter: u32, draw: impl FnOnce(usize, usize) -> usize) -> usize {
    let base = base.clamp(1, 63);
    if jitter == 0 {
        return base;
    }
    draw(min_label_len(base, jitter), base)
}

/// Label length to use for one specific query: the base length when jitter is off (unchanged,
/// constant-length behavior), otherwise a uniform draw in `[min_label_length, base]`. Kept within
/// `[1, base]` so the built name always fits the MTU that was sized at `min_label_length`.
pub(crate) fn pick_label_length(
    config: &slipstream_ffi::ClientConfig<'_>,
    txid: &mut TxidGen,
) -> usize {
    pick_label_len(
        config.dns_label_length,
        config.dns_label_length_jitter,
        |lo, hi| txid.next_in_range(lo, hi),
    )
}

#[cfg(test)]
mod label_length_tests {
    use super::{min_label_len, pick_label_len};
    use crate::dns::TxidGen;

    #[test]
    fn jitter_off_is_constant_base() {
        // Off (jitter 0) must reproduce the historical constant-length behavior exactly.
        for base in [1usize, 40, 57, 63, 100] {
            assert_eq!(
                pick_label_len(base, 0, |_, _| unreachable!("must not draw when jitter off")),
                base.clamp(1, 63)
            );
        }
    }

    #[test]
    fn pick_never_exceeds_base_or_drops_below_min() {
        // The MTU-safety invariant: the chosen length is always within [min_label_len, base], so a
        // jittered name fits the MTU sized at min_label_len.
        let mut txid = TxidGen::from_seed(0x5151_5151_9999_0001);
        for &(base, jitter) in &[(57usize, 10u32), (63, 62), (40, 100), (10, 3), (1, 5)] {
            let lo = min_label_len(base, jitter);
            let hi = base.clamp(1, 63);
            assert!(lo >= 1 && lo <= hi);
            for _ in 0..2000 {
                let v = pick_label_len(base, jitter, |lo, hi| txid.next_in_range(lo, hi));
                assert!(
                    (lo..=hi).contains(&v),
                    "base={base} jitter={jitter}: {v} not in [{lo},{hi}]"
                );
            }
        }
    }

    #[test]
    fn jitter_larger_than_base_floors_at_one() {
        assert_eq!(min_label_len(5, 100), 1);
        assert_eq!(min_label_len(63, 1000), 1);
    }
}
