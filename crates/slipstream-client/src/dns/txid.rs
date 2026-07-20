//! DNS transaction-ID generation.
//!
//! Real stub resolvers randomize the DNS transaction ID on every query (RFC 5452, as an
//! anti-cache-poisoning measure). Slipstream historically used a monotonic `1, 2, 3, ...`
//! counter, which is one of the cheapest possible DPI signatures for a DNS tunnel: a stream of
//! queries to port 53 whose IDs increment by one is trivially matched with a single stateless
//! rule and almost never occurs in legitimate traffic. [`TxidGen`] replaces that counter with a
//! non-sequential generator whose output is indistinguishable from a normal randomized stub.
//!
//! The IDs do not need to be cryptographically unpredictable (the tunnel's confidentiality comes
//! from QUIC/TLS, not from the DNS ID) -- they only need to be non-sequential and well spread so
//! they don't stand out. We therefore seed once from the OS CSPRNG and then advance with a fast
//! userspace SplitMix64 step per query, so we don't pay a syscall per query at multi-kQPS.

/// Non-sequential DNS transaction-ID generator (see module docs).
pub(crate) struct TxidGen {
    state: u64,
}

/// SplitMix64 increment (the golden-ratio odd constant) and finalizer constants. SplitMix64 has
/// good statistical distribution over its full period, which is all we need here.
const SPLITMIX_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

impl TxidGen {
    /// Seed from the OS CSPRNG (the same source the server uses for cert serials/seeds). If the
    /// RNG is somehow unavailable we fall back to a time-based seed rather than panic -- a
    /// slightly-worse seed is still far better than a monotonic counter, and this path never
    /// aborts a client that would otherwise run.
    pub(crate) fn new() -> Self {
        let mut seed = [0u8; 8];
        if openssl::rand::rand_bytes(&mut seed).is_err() {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(SPLITMIX_GAMMA);
            seed = nanos.to_le_bytes();
        }
        Self {
            state: u64::from_le_bytes(seed),
        }
    }

    /// Deterministic constructor for tests.
    #[cfg(test)]
    pub(crate) fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Next transaction ID. Advances the SplitMix64 state and returns the high 16 bits of the
    /// mixed output (the high bits have the best avalanche).
    pub(crate) fn next_id(&mut self) -> u16 {
        self.state = self.state.wrapping_add(SPLITMIX_GAMMA);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 48) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::TxidGen;
    use std::collections::HashSet;

    #[test]
    fn is_deterministic_from_seed() {
        let mut a = TxidGen::from_seed(0x1234_5678_9ABC_DEF0);
        let mut b = TxidGen::from_seed(0x1234_5678_9ABC_DEF0);
        for _ in 0..1000 {
            assert_eq!(a.next_id(), b.next_id());
        }
    }

    #[test]
    fn is_not_sequential() {
        // The whole point: consecutive IDs must not differ by a constant (least of all by 1,
        // the old counter's step). Count how many consecutive pairs differ by exactly 1; a
        // sequential counter would score 100%, a good generator should be near 1/65536.
        let mut gen = TxidGen::from_seed(0xDEAD_BEEF_CAFE_F00D);
        let mut prev = gen.next_id();
        let mut plus_one = 0usize;
        let n = 20_000;
        for _ in 0..n {
            let cur = gen.next_id();
            if cur == prev.wrapping_add(1) {
                plus_one += 1;
            }
            prev = cur;
        }
        assert!(
            plus_one < n / 100,
            "too many +1 steps ({plus_one}/{n}); output looks sequential"
        );
    }

    #[test]
    fn covers_the_id_space() {
        // A randomized stub uses the full 16-bit space; make sure we're not stuck in a tiny
        // sub-range. Over many draws we should see a large fraction of distinct values.
        let mut gen = TxidGen::from_seed(0x0F0F_0F0F_1111_2222);
        let mut seen = HashSet::new();
        for _ in 0..40_000 {
            seen.insert(gen.next_id());
        }
        assert!(
            seen.len() > 20_000,
            "only {} distinct IDs seen; distribution too narrow",
            seen.len()
        );
    }
}
