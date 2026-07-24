//! Hard ceiling for the **data-bearing** DNS send rate, shared by every crate root.
//!
//! This lives in its own module rather than in `lib.rs` because `runtime.rs` reads it and is
//! compiled into *both* crate roots (`lib.rs` for the Android cdylib, `main.rs` for the CLI binary).
//! A `crate::`-qualified reference to something defined only in `lib.rs` resolves for the library
//! and fails to compile for the binary, which is exactly how the CLI target got broken.

use std::sync::atomic::{AtomicU32, Ordering};

/// Cap on data-bearing DNS queries/sec from the QUIC send loop (0 = unlimited).
/// Keeps multi-stream upload from starving the reverse path (MAX_STREAM_DATA / TLS).
/// Fixed ceiling only — no thrash-adaptive.
/// Default **800** (was 1000): live Spain VPS still saw RcvbufErrors at multi-kQPS peaks; a
/// slightly lower data firehose improves stream survival (TG video parts were stream_reset
/// after ~0.7 MiB). App can still raise via maxDataQps / nativeSetMaxDataQps.
pub(crate) const DEFAULT_MAX_DATA_QPS: u32 = 800;

static MAX_DATA_QPS: AtomicU32 = AtomicU32::new(DEFAULT_MAX_DATA_QPS);

/// Set the ceiling (0 = unlimited). Only the JNI entry point calls this, so it is dead code in the
/// CLI build.
#[allow(dead_code)]
pub(crate) fn set_max_data_qps(value: u32) {
    MAX_DATA_QPS.store(value, Ordering::Relaxed);
}

/// Hard ceiling for data-bearing DNS send rate. Optional live override:
/// `run-as app.vaydns sh -c 'echo N > files/max_data_qps'` (app-readable; not /data/local/tmp).
pub(crate) fn resolve_max_data_qps() -> u32 {
    const CANDIDATES: &[&str] = &[
        "/data/data/app.vaydns/files/max_data_qps",
        "/data/user/0/app.vaydns/files/max_data_qps",
    ];
    for path in CANDIDATES {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(v) = s.trim().parse::<u32>() {
                return v;
            }
        }
    }
    MAX_DATA_QPS.load(Ordering::Relaxed)
}
