//! Per-connection cap on how often the server hands a connection a fresh QUIC packet in
//! response to a poll.
//!
//! Authoritative-mode client pacing targets `target_inflight / measured_RTT` queries/sec
//! (see slipstream-client's `pacing.rs`); on a fast, low-RTT carrier (typically UDP) this
//! can reach tens of thousands of polls/sec for a single connection, since the client's own
//! congestion controller just reacts to how fast responses come back -- there's no ceiling
//! on the server side to react against. Rather than change that formula client-side (easy
//! to get subtly wrong per-transport, and an "advisory" client cap is unenforceable against
//! a connection that just doesn't apply it), this caps how often the SERVER actually hands
//! a connection a fresh prepared QUIC packet: a poll over budget still gets a normal empty
//! NOERROR DNS answer (so a recursive resolver relaying it doesn't see a failure/timeout and
//! retry), it just carries no new QUIC content this round -- exactly like "genuinely nothing
//! ready yet" (`send_length == 0`), which is already a normal, handled case; nothing pending
//! is lost, it's just prepared on a later, allowed round. picoquic's own congestion control
//! then sees reduced achieved throughput and naturally lowers its pacing rate over time,
//! which (per the client formula above) directly lowers the connection's own future poll
//! rate -- a real feedback loop instead of an unenforceable client-side knob.

use std::collections::HashMap;

struct Bucket {
    tokens: f64,
    last_refill_us: u64,
}

pub(crate) struct PollRateLimiter {
    rate_per_sec: f64,
    burst: f64,
    buckets: HashMap<usize, Bucket>,
}

impl PollRateLimiter {
    /// `max_qps_per_connection == 0` disables the cap entirely (matches the existing
    /// 0-means-unlimited convention used by the client's `max_poll_qps`).
    pub(crate) fn new(max_qps_per_connection: u32) -> Self {
        let rate_per_sec = max_qps_per_connection as f64;
        Self {
            rate_per_sec,
            // One second's worth of burst credit -- generous enough that a connection
            // ramping up from idle isn't immediately throttled, small enough to still cap
            // sustained runaway polling.
            burst: rate_per_sec.max(1.0),
            buckets: HashMap::new(),
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.rate_per_sec > 0.0
    }

    /// Returns true if this connection may receive a fresh prepared QUIC packet right now,
    /// consuming one token if so. `now_us` should be `picoquic_current_time()` (or any
    /// monotonically non-decreasing microsecond clock shared across calls).
    pub(crate) fn allow(&mut self, cnx_id: usize, now_us: u64) -> bool {
        if !self.enabled() {
            return true;
        }
        let bucket = self.buckets.entry(cnx_id).or_insert_with(|| Bucket {
            tokens: self.burst,
            last_refill_us: now_us,
        });
        let elapsed_us = now_us.saturating_sub(bucket.last_refill_us) as f64;
        bucket.tokens =
            (bucket.tokens + elapsed_us * self.rate_per_sec / 1_000_000.0).min(self.burst);
        bucket.last_refill_us = now_us;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drops bucket state for connections no longer present in `active`, mirroring the
    /// existing idle-connection GC in `server.rs` so this map doesn't grow forever as
    /// connections churn. Cheap no-op when the cap is disabled (map stays empty).
    pub(crate) fn retain_active<V>(&mut self, active: &HashMap<usize, V>) {
        if self.buckets.is_empty() {
            return;
        }
        self.buckets.retain(|cnx_id, _| active.contains_key(cnx_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_always_allows() {
        let mut limiter = PollRateLimiter::new(0);
        for i in 0..1000 {
            assert!(limiter.allow(1, i));
        }
    }

    #[test]
    fn caps_sustained_rate_but_allows_initial_burst() {
        let mut limiter = PollRateLimiter::new(10);
        // Burst credit (10 tokens) lets the first 10 calls at the same instant through.
        for _ in 0..10 {
            assert!(limiter.allow(1, 0));
        }
        // The 11th call with no elapsed time should be denied (bucket empty).
        assert!(!limiter.allow(1, 0));
        // After 1 full second, the bucket refills up to `burst` and allows again.
        assert!(limiter.allow(1, 1_000_000));
    }

    #[test]
    fn connections_are_independent() {
        let mut limiter = PollRateLimiter::new(1);
        assert!(limiter.allow(1, 0));
        assert!(!limiter.allow(1, 0));
        // A different connection has its own budget.
        assert!(limiter.allow(2, 0));
    }

    #[test]
    fn retain_active_prunes_closed_connections() {
        let mut limiter = PollRateLimiter::new(5);
        limiter.allow(1, 0);
        limiter.allow(2, 0);
        assert_eq!(limiter.buckets.len(), 2);
        let active: HashMap<usize, ()> = HashMap::from([(1, ())]);
        limiter.retain_active(&active);
        assert_eq!(limiter.buckets.len(), 1);
        assert!(limiter.buckets.contains_key(&1));
    }
}
