//! Stall/no-progress detection for the client poll loop.
//!
//! This is pure decision logic extracted out of `run_client_with_control` specifically so it can
//! be unit tested without a live picoquic connection or a real network -- every trigger condition
//! here is the exact code responsible for two real incidents: an empty-poll flood pegging a CPU
//! core, and a silently-black-holed resolver going undetected for up to a minute before the slow
//! Kotlin-side failure counter finally restarted the tunnel. See docs/config.md and the comments
//! below for the reasoning; the constants and formulas are unchanged from the inline version.

use tracing::{error, info, warn};

/// Demand-driven poll throttle. In authoritative mode the CC is disabled (cwin = pacing_rate =
/// UINT64_MAX, see slipstream_server_cc.c), so target_inflight is pinned at its clamp maximum
/// (384) and the actual poll rate is target_inflight / RTT. On a low-RTT carrier that becomes
/// thousands of DNS queries/sec that keep flowing even when NO real data is moving -- an
/// empty-poll flood that pegs the phone's CPU (and hammers the single-core server). Capping
/// target_inflight to UNPRODUCTIVE_MAX_INFLIGHT while idle collapses the flood without touching
/// productive transfers.
pub(crate) const UNPRODUCTIVE_POLL_BACKOFF_US: u64 = 1_000_000;
pub(crate) const UNPRODUCTIVE_MAX_INFLIGHT: usize = 8;
/// When peer stream/connection flow control is blocking us we still need DNS polls so the
/// responses can carry MAX_STREAM_DATA / ACKs — but we must not use the full active budget
/// (or max_poll_qps=1400). Moderate inflight keeps window updates flowing without empty-poll
/// firehose that starves the response path on the single-thread server.
pub(crate) const FLOW_BLOCKED_MAX_INFLIGHT: usize = 24;
/// Cap effective max_poll_qps while flow_blocked. Operators set high ceilings (e.g. 1400) for
/// productive upload; under FC block those queries only amplify req≫resp asymmetry.
pub(crate) const FLOW_BLOCKED_MAX_POLL_QPS: u32 = 96;
/// A stream can look "active" indefinitely while genuinely stuck (peer not acking) -- without
/// this, the loop's sleep-timing stays pinned at the active floor forever, pegging a core at
/// 100% CPU with zero throughput. This only affects sleep timing, not pacing/reconnection/the
/// no-progress detector below.
pub(crate) const CPU_THROTTLE_NO_PROGRESS_US: u64 = 750_000;
pub(crate) const NO_PROGRESS_TIMEOUT_US: u64 = 5_000_000;
pub(crate) const NO_PROGRESS_MIN_ENQUEUED_BYTES: u64 = 128 * 1024;
pub(crate) const NO_PROGRESS_ARM_LOG_INTERVAL_US: u64 = 2_000_000;
pub(crate) const DOWNSTREAM_STALE_ZERO_SEND_MIN: u64 = 10_000;
pub(crate) const STALE_STREAM_MIN_ENQUEUED_BYTES: u64 = 1;
pub(crate) const STALE_STREAM_MIN_IDLE_US: u64 = 4_000_000;

/// Everything the detector needs from one loop iteration. All plain values -- no picoquic/FFI
/// types -- so a test can drive this with hand-picked numbers instead of a live connection.
pub(crate) struct StallInput {
    pub now: u64,
    pub streams_len: usize,
    pub enqueued_bytes: u64,
    pub data_consumed: u64,
    pub data_rx_queued_chunks_total: u64,
    pub streams_with_data_rx_queued: usize,
    pub dns_send_bytes_total: u64,
    pub dns_responses_total: u64,
    pub has_ready_stream: bool,
    pub flow_blocked: bool,
    pub zero_send_with_streams: u64,
    pub last_enqueue_at: u64,
    pub connection_ready: bool,
}

pub(crate) struct StallDetector {
    // Tracks whether the resolver itself is still saying anything back at all (any decodable DNS
    // response, ack-only or not), independent of enqueued_bytes/data_consumed. Those two can keep
    // climbing purely from the app opening new (doomed) connections while the carrier is fully
    // black-holed, which fooled both the progress check below and the no-progress detector into
    // thinking the link was fine.
    last_dns_responses_seen: u64,
    last_dns_response_at: u64,
    last_useful_progress_at: u64,
    last_useful_enqueued_bytes: u64,
    last_useful_data_consumed: u64,
    poll_backoff_active: bool,
    cpu_throttle_since: u64,
    cpu_throttle_active: bool,
    no_progress_since: u64,
    last_no_progress_arm_log_at: u64,
    last_no_progress_enqueued_bytes: u64,
    last_no_progress_dns_send_bytes: u64,
}

impl StallDetector {
    pub(crate) fn new() -> Self {
        Self {
            last_dns_responses_seen: 0,
            last_dns_response_at: 0,
            last_useful_progress_at: 0,
            last_useful_enqueued_bytes: 0,
            last_useful_data_consumed: 0,
            poll_backoff_active: false,
            cpu_throttle_since: 0,
            cpu_throttle_active: false,
            no_progress_since: 0,
            last_no_progress_arm_log_at: 0,
            last_no_progress_enqueued_bytes: 0,
            last_no_progress_dns_send_bytes: 0,
        }
    }

    /// Whether the poll-rate cap is currently engaged. Read at the top of the loop (reflecting
    /// last iteration's decision) to mirror the cap into the pacing target computation.
    pub(crate) fn poll_backoff_active(&self) -> bool {
        self.poll_backoff_active
    }

    /// Whether the loop should fall back to the idle sleep floor.
    pub(crate) fn cpu_throttle_active(&self) -> bool {
        self.cpu_throttle_active
    }

    /// Call once per loop iteration after the send/recv work is done. Returns `Some(reason)` once
    /// the no-progress timeout has fully elapsed -- the caller should treat the connection as dead
    /// and break out of the loop.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn tick(&mut self, input: StallInput) -> Option<String> {
        let StallInput {
            now,
            streams_len,
            enqueued_bytes,
            data_consumed,
            data_rx_queued_chunks_total,
            streams_with_data_rx_queued,
            dns_send_bytes_total,
            dns_responses_total,
            has_ready_stream,
            flow_blocked,
            zero_send_with_streams,
            last_enqueue_at,
            connection_ready,
        } = input;

        // Any decodable response from any resolver, regardless of whether it carries app
        // payload -- this is the one signal that can't be manufactured by the app retrying
        // doomed connections, unlike enqueued_bytes. received_recently uses a time window rather
        // than a per-cycle delta so a healthy connection's normal poll cadence (a response most,
        // not every, cycle) doesn't make this flap.
        if dns_responses_total > self.last_dns_responses_seen || self.last_dns_response_at == 0 {
            self.last_dns_response_at = now;
        }
        self.last_dns_responses_seen = dns_responses_total;
        let received_recently =
            now.saturating_sub(self.last_dns_response_at) < UNPRODUCTIVE_POLL_BACKOFF_US;
        let useful_progress = received_recently
            && (enqueued_bytes > self.last_useful_enqueued_bytes
                || data_consumed > self.last_useful_data_consumed
                || data_rx_queued_chunks_total > 0);
        self.last_useful_enqueued_bytes = enqueued_bytes;
        self.last_useful_data_consumed = data_consumed;
        if useful_progress || self.last_useful_progress_at == 0 {
            self.last_useful_progress_at = now;
        }
        let poll_backoff = streams_len > 0
            && now.saturating_sub(self.last_useful_progress_at) >= UNPRODUCTIVE_POLL_BACKOFF_US;
        if poll_backoff != self.poll_backoff_active {
            self.poll_backoff_active = poll_backoff;
            if poll_backoff {
                info!(
                    "poll_backoff: engaged (no up/down data for {}ms) — capping target_inflight to {} streams={}",
                    UNPRODUCTIVE_POLL_BACKOFF_US / 1_000,
                    UNPRODUCTIVE_MAX_INFLIGHT,
                    streams_len
                );
            } else {
                info!(
                    "poll_backoff: released — real data flowing again streams={}",
                    streams_len
                );
            }
        }

        let last_enqueue_ms = if last_enqueue_at == 0 {
            0
        } else {
            now.saturating_sub(last_enqueue_at) / 1_000
        };

        let local_pressure = enqueued_bytes > self.last_no_progress_enqueued_bytes
            || streams_with_data_rx_queued > 0
            || data_rx_queued_chunks_total > 0;
        let dns_send_progress = dns_send_bytes_total > self.last_no_progress_dns_send_bytes;
        if local_pressure || dns_send_progress {
            if self.cpu_throttle_active {
                info!(
                    "cpu_throttle: released after {}ms streams={} enqueued_bytes={} dns_send_bytes_total={}",
                    now.saturating_sub(self.cpu_throttle_since) / 1_000,
                    streams_len,
                    enqueued_bytes,
                    dns_send_bytes_total
                );
            }
            self.cpu_throttle_since = 0;
            self.cpu_throttle_active = false;
        } else {
            if self.cpu_throttle_since == 0 {
                self.cpu_throttle_since = now;
            }
            if !self.cpu_throttle_active
                && now.saturating_sub(self.cpu_throttle_since) >= CPU_THROTTLE_NO_PROGRESS_US
            {
                self.cpu_throttle_active = true;
                warn!(
                    "cpu_throttle: engaged after {}ms without send/receive progress; falling back \
                     to idle poll rate streams={} enqueued_bytes={} dns_send_bytes_total={} \
                     flow_blocked={} has_ready_stream={} zero_send_with_streams={}",
                    CPU_THROTTLE_NO_PROGRESS_US / 1_000,
                    streams_len,
                    enqueued_bytes,
                    dns_send_bytes_total,
                    flow_blocked,
                    has_ready_stream,
                    zero_send_with_streams
                );
            }
        }

        let stalled_signal = flow_blocked || !has_ready_stream || zero_send_with_streams > 0;
        let downstream_stale = data_rx_queued_chunks_total == 0
            && streams_with_data_rx_queued == 0
            && zero_send_with_streams >= DOWNSTREAM_STALE_ZERO_SEND_MIN;
        let stale_stream = enqueued_bytes >= STALE_STREAM_MIN_ENQUEUED_BYTES
            && last_enqueue_at != 0
            && now.saturating_sub(last_enqueue_at) >= STALE_STREAM_MIN_IDLE_US
            && downstream_stale
            && !has_ready_stream;
        let no_recent_enqueue =
            last_enqueue_at != 0 && now.saturating_sub(last_enqueue_at) >= NO_PROGRESS_TIMEOUT_US;
        let large_no_progress = enqueued_bytes >= NO_PROGRESS_MIN_ENQUEUED_BYTES
            && no_recent_enqueue
            && !has_ready_stream
            && (!dns_send_progress || downstream_stale);
        // Independent of the enqueue-based heuristics above (which the app can keep refreshing by
        // retrying doomed connections): if we are actively transmitting but the resolver has not
        // sent back a single decodable response, of any kind, for NO_PROGRESS_TIMEOUT_US, that
        // alone is a definitive dead-carrier signal and doesn't need stalled_signal's
        // corroboration. Unlike stale_stream/large_no_progress below, this fires immediately
        // instead of arming and waiting a further NO_PROGRESS_TIMEOUT_US to confirm: the
        // NO_PROGRESS_TIMEOUT_US threshold is already the full detection window here (it directly
        // measures elapsed silence), so requiring a second one would double the effective latency
        // to ~10s for no benefit -- there is nothing fuzzy about this signal left to confirm.
        let resolver_silent = connection_ready
            && streams_len > 0
            && dns_send_progress
            && now.saturating_sub(self.last_dns_response_at) >= NO_PROGRESS_TIMEOUT_US;
        if resolver_silent {
            self.no_progress_since = 0;
            self.last_no_progress_enqueued_bytes = enqueued_bytes;
            self.last_no_progress_dns_send_bytes = dns_send_bytes_total;
            let silent_for_ms = now.saturating_sub(self.last_dns_response_at) / 1_000;
            error!(
                "no-progress detected for {}ms reason=resolver_silent: streams={} enqueued_bytes={} dns_send_bytes_total={} last_enqueue_ms={} flow_blocked={} has_ready_stream={} data_rx_queued_chunks_total={} zero_send_with_streams={}; resetting connection",
                silent_for_ms,
                streams_len,
                enqueued_bytes,
                dns_send_bytes_total,
                last_enqueue_ms,
                flow_blocked,
                has_ready_stream,
                data_rx_queued_chunks_total,
                zero_send_with_streams
            );
            return Some(format!(
                "native no-progress reason=resolver_silent streams={streams_len} enqueued_bytes={enqueued_bytes} last_enqueue_ms={last_enqueue_ms} zero_send_with_streams={zero_send_with_streams}"
            ));
        }
        let stalled_no_progress = connection_ready
            && streams_len > 0
            && (large_no_progress || stale_stream)
            && stalled_signal;
        let no_progress_reason = if stale_stream {
            "stale_stream"
        } else {
            "large_no_progress"
        };

        let mut fatal = None;
        if stalled_no_progress && (local_pressure || self.no_progress_since != 0) {
            if self.no_progress_since == 0 {
                self.no_progress_since = now;
                if now.saturating_sub(self.last_no_progress_arm_log_at)
                    >= NO_PROGRESS_ARM_LOG_INTERVAL_US
                {
                    self.last_no_progress_arm_log_at = now;
                    warn!(
                        "no-progress detector armed: reason={} streams={} enqueued_bytes={} dns_send_bytes_total={} last_enqueue_ms={} flow_blocked={} has_ready_stream={} data_rx_queued_chunks_total={} zero_send_with_streams={}",
                        no_progress_reason,
                        streams_len,
                        enqueued_bytes,
                        dns_send_bytes_total,
                        last_enqueue_ms,
                        flow_blocked,
                        has_ready_stream,
                        data_rx_queued_chunks_total,
                        zero_send_with_streams
                    );
                }
            } else if now.saturating_sub(self.no_progress_since) >= NO_PROGRESS_TIMEOUT_US {
                error!(
                    "no-progress detected for {}ms reason={}: streams={} enqueued_bytes={} dns_send_bytes_total={} last_enqueue_ms={} flow_blocked={} has_ready_stream={} data_rx_queued_chunks_total={} zero_send_with_streams={}; resetting connection",
                    now.saturating_sub(self.no_progress_since) / 1_000,
                    no_progress_reason,
                    streams_len,
                    enqueued_bytes,
                    dns_send_bytes_total,
                    last_enqueue_ms,
                    flow_blocked,
                    has_ready_stream,
                    data_rx_queued_chunks_total,
                    zero_send_with_streams
                );
                fatal = Some(format!(
                    "native no-progress reason={} streams={} enqueued_bytes={} last_enqueue_ms={} zero_send_with_streams={}",
                    no_progress_reason, streams_len, enqueued_bytes, last_enqueue_ms, zero_send_with_streams
                ));
            }
        } else {
            self.no_progress_since = 0;
        }
        self.last_no_progress_enqueued_bytes = enqueued_bytes;
        self.last_no_progress_dns_send_bytes = dns_send_bytes_total;
        fatal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // picoquic_current_time() is a realtime-based monotonic clock and is never actually 0 in
    // production; the detector uses 0 as its "never seen yet" sentinel for a couple of trackers,
    // so tests must start the simulated clock at a nonzero value to avoid colliding with that
    // sentinel (which would make "no response yet" indistinguishable from "just got a response
    // at t=0").
    const BASE: u64 = 10_000_000;

    fn base_input(now: u64) -> StallInput {
        StallInput {
            now,
            streams_len: 1,
            enqueued_bytes: 0,
            data_consumed: 0,
            data_rx_queued_chunks_total: 0,
            streams_with_data_rx_queued: 0,
            dns_send_bytes_total: 0,
            dns_responses_total: 0,
            has_ready_stream: true,
            flow_blocked: false,
            zero_send_with_streams: 0,
            last_enqueue_at: 0,
            connection_ready: true,
        }
    }

    #[test]
    fn poll_backoff_stays_off_while_data_keeps_moving() {
        // "Steady" here means real payload progress (enqueued_bytes growing), not just responses
        // arriving -- a resolver that only ever ACKs without carrying data must not count.
        let mut detector = StallDetector::new();
        let mut now = BASE;
        for i in 0..10u64 {
            now += 200_000; // 200ms per tick, well under the 1s backoff window
            let mut input = base_input(now);
            input.dns_responses_total = i + 1;
            input.enqueued_bytes = (i + 1) * 100; // real upload progress every tick
            detector.tick(input);
            assert!(
                !detector.poll_backoff_active(),
                "poll_backoff engaged despite steady data flow at tick {i}"
            );
        }
    }

    #[test]
    fn poll_backoff_engages_after_one_second_of_no_useful_progress() {
        let mut detector = StallDetector::new();
        // Establish a baseline with real progress, then nothing moves at all afterward.
        let mut input = base_input(BASE);
        input.dns_responses_total = 1;
        input.enqueued_bytes = 100;
        detector.tick(input);
        assert!(!detector.poll_backoff_active());

        let mut input = base_input(BASE + 999_999);
        input.dns_responses_total = 1; // unchanged
        input.enqueued_bytes = 100; // unchanged
        detector.tick(input);
        assert!(
            !detector.poll_backoff_active(),
            "must not engage before the 1s window elapses"
        );

        let mut input = base_input(BASE + 1_000_001);
        input.dns_responses_total = 1;
        input.enqueued_bytes = 100;
        detector.tick(input);
        assert!(
            detector.poll_backoff_active(),
            "must engage once 1s has passed with no new progress"
        );
    }

    #[test]
    fn poll_backoff_is_not_fooled_by_enqueued_bytes_alone() {
        // This is the exact bug from the incident: the app keeps opening new (doomed) streams,
        // so enqueued_bytes keeps climbing, but the resolver never answers again. Growing
        // enqueued_bytes with NO corresponding response must not count as useful progress.
        let mut detector = StallDetector::new();
        let mut input = base_input(BASE);
        input.dns_responses_total = 1;
        input.enqueued_bytes = 100;
        detector.tick(input);

        let mut input = base_input(BASE + 2_000_000);
        input.dns_responses_total = 1; // still nothing new from the resolver
        input.enqueued_bytes = 5_000; // but the app keeps enqueueing new bytes
        detector.tick(input);

        assert!(
            detector.poll_backoff_active(),
            "growing enqueued_bytes alone must not suppress poll_backoff once the resolver goes silent"
        );
    }

    #[test]
    fn cpu_throttle_engages_after_750ms_without_send_or_receive_progress() {
        let mut detector = StallDetector::new();
        // Tick 1: any nonzero send total looks like "progress" against the zeroed baseline --
        // this just establishes dns_send_bytes_total's starting point.
        let mut input = base_input(BASE);
        input.dns_send_bytes_total = 100;
        detector.tick(input);
        assert!(!detector.cpu_throttle_active());

        // Tick 2: first tick where nothing has moved -- this is when the no-progress clock
        // actually starts (cpu_throttle_since), not tick 1.
        let clock_start = BASE + 1;
        let mut input = base_input(clock_start);
        input.dns_send_bytes_total = 100; // unchanged
        detector.tick(input);
        assert!(!detector.cpu_throttle_active());

        let mut input = base_input(clock_start + 749_000);
        input.dns_send_bytes_total = 100;
        detector.tick(input);
        assert!(
            !detector.cpu_throttle_active(),
            "must not engage before 750ms have passed since progress last stopped"
        );

        let mut input = base_input(clock_start + 751_000);
        input.dns_send_bytes_total = 100;
        detector.tick(input);
        assert!(
            detector.cpu_throttle_active(),
            "must engage once 750ms of no progress elapsed"
        );
    }

    #[test]
    fn cpu_throttle_releases_immediately_on_new_send_progress() {
        let mut detector = StallDetector::new();
        let mut input = base_input(BASE);
        input.dns_send_bytes_total = 100;
        detector.tick(input);

        let clock_start = BASE + 1;
        let mut input = base_input(clock_start);
        input.dns_send_bytes_total = 100;
        detector.tick(input);

        let mut input = base_input(clock_start + 751_000);
        input.dns_send_bytes_total = 100;
        detector.tick(input);
        assert!(detector.cpu_throttle_active());

        let mut input = base_input(clock_start + 751_100);
        input.dns_send_bytes_total = 200; // fresh send progress
        detector.tick(input);
        assert!(
            !detector.cpu_throttle_active(),
            "must release the instant sends resume"
        );
    }

    #[test]
    fn resolver_silent_fires_immediately_once_five_seconds_of_true_silence_elapse() {
        // Mirrors the real incident: streams open, client keeps transmitting (dns_send_progress),
        // but the resolver never sends back a single decodable response. Also verifies the fix
        // for the double-wait bug: this must fire at the 5s mark, not ~10s later.
        let mut detector = StallDetector::new();
        let mut now = BASE;
        let step = 200_000u64; // 200ms cadence, matching a lively poll loop
        let mut fatal = None;
        while now < BASE + 5_000_000 {
            let mut input = base_input(now);
            input.dns_send_bytes_total = (now - BASE) / 1_000 + 1; // keeps climbing every tick
            input.enqueued_bytes = (now - BASE) / 1_000; // the app also keeps retrying
            fatal = detector.tick(input).or(fatal);
            now += step;
        }
        assert!(
            fatal.is_none(),
            "must not fire before 5s of silence have elapsed: {fatal:?}"
        );

        let mut input = base_input(BASE + 5_000_000);
        input.dns_send_bytes_total = 5_001;
        input.enqueued_bytes = 5_000;
        let fatal = detector.tick(input);
        let reason = fatal.expect("resolver_silent must fire the instant 5s of silence elapse");
        assert!(reason.contains("resolver_silent"), "reason was: {reason}");
    }

    #[test]
    fn resolver_silent_does_not_fire_while_responses_keep_arriving() {
        let mut detector = StallDetector::new();
        let mut fatal = None;
        let mut now = BASE;
        let step = 200_000u64;
        let mut responses = 0u64;
        while now <= BASE + 6_000_000 {
            responses += 1;
            let mut input = base_input(now);
            input.dns_send_bytes_total = (now - BASE) / 1_000 + 1;
            input.dns_responses_total = responses; // a response every tick -- carrier is alive
            fatal = detector.tick(input).or(fatal);
            now += step;
        }
        assert!(
            fatal.is_none(),
            "must not fire while the resolver keeps answering: {fatal:?}"
        );
    }

    #[test]
    fn resolver_silent_requires_streams_and_ready_connection() {
        // No streams open yet (e.g. still handshaking) -- silence here is normal, not a stall.
        let mut detector = StallDetector::new();
        let mut fatal = None;
        let mut now = BASE;
        while now <= BASE + 6_000_000 {
            let mut input = base_input(now);
            input.streams_len = 0;
            input.dns_send_bytes_total = (now - BASE) / 1_000 + 1;
            fatal = detector.tick(input).or(fatal);
            now += 200_000;
        }
        assert!(
            fatal.is_none(),
            "must not fire with zero streams: {fatal:?}"
        );
    }

    #[test]
    fn large_no_progress_arms_then_fires_a_full_timeout_later() {
        let mut detector = StallDetector::new();
        let last_enqueue_at = BASE;

        // Tick 1: baseline snapshot, not yet stale.
        let mut input = base_input(BASE);
        input.enqueued_bytes = NO_PROGRESS_MIN_ENQUEUED_BYTES;
        input.last_enqueue_at = last_enqueue_at;
        let fatal = detector.tick(input);
        assert!(fatal.is_none());

        // Tick 2, 5s later: no new enqueue since `last_enqueue_at`, not ready, sending nothing --
        // arms the detector (needs local_pressure: enqueued_bytes must have grown since tick 1).
        let arm_at = BASE + NO_PROGRESS_TIMEOUT_US + 1;
        let mut input = base_input(arm_at);
        input.enqueued_bytes = NO_PROGRESS_MIN_ENQUEUED_BYTES + 1;
        input.last_enqueue_at = last_enqueue_at;
        input.has_ready_stream = false;
        input.zero_send_with_streams = DOWNSTREAM_STALE_ZERO_SEND_MIN;
        let fatal = detector.tick(input);
        assert!(
            fatal.is_none(),
            "must arm, not fire, on the first stalled observation"
        );

        // Tick 3, just under one more timeout later: still armed, not yet fired.
        let mut input = base_input(arm_at + NO_PROGRESS_TIMEOUT_US - 1);
        input.enqueued_bytes = NO_PROGRESS_MIN_ENQUEUED_BYTES + 1;
        input.last_enqueue_at = last_enqueue_at;
        input.has_ready_stream = false;
        input.zero_send_with_streams = DOWNSTREAM_STALE_ZERO_SEND_MIN;
        let fatal = detector.tick(input);
        assert!(
            fatal.is_none(),
            "must not fire before the confirmation window elapses"
        );

        // Tick 4: a full NO_PROGRESS_TIMEOUT_US after arming -- fires. This scenario happens to
        // satisfy both large_no_progress and stale_stream's conditions at once (realistic -- a
        // real stall usually trips more than one heuristic); the label isn't the point here, the
        // arm-then-confirm timing is.
        let mut input = base_input(arm_at + NO_PROGRESS_TIMEOUT_US);
        input.enqueued_bytes = NO_PROGRESS_MIN_ENQUEUED_BYTES + 1;
        input.last_enqueue_at = last_enqueue_at;
        input.has_ready_stream = false;
        input.zero_send_with_streams = DOWNSTREAM_STALE_ZERO_SEND_MIN;
        let fatal = detector.tick(input);
        let reason = fatal.expect("expected the heuristic no-progress path to fire");
        assert!(
            reason.contains("large_no_progress") || reason.contains("stale_stream"),
            "reason was: {reason}"
        );
    }

    #[test]
    fn no_progress_detector_does_not_arm_on_a_healthy_connection() {
        let mut detector = StallDetector::new();
        let input = base_input(BASE);
        let fatal = detector.tick(input);
        assert!(fatal.is_none());
    }
}
