mod support;

use std::thread;
use std::time::{Duration, Instant};

use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, server_bin_path, spawn_client,
    spawn_server, test_cert_and_key, wait_for_log, workspace_root, ChildGuard, ClientArgs,
    LogCapture, ServerArgs,
};

const DOMAIN: &str = "test.example.com";
// Deliberately far below the empirically-observed ~5 concurrent failure point (and picoquic's
// default of 64) so picoquic's adaptive Retry-token defense engages during the burst below. This
// value exercises the new --max-half-open-connections plumbing end to end (the flag is accepted,
// the server serves every client and survives). Note this loopback test does NOT by itself prove
// the threshold was applied to picoquic -- all clients reach "Connection ready" either way; that
// discrimination lives in `server_half_open_retry_threshold_is_applied_to_context`
// (slipstream-ffi/src/runtime.rs). The production default (4) is validated by the unit tests in
// main.rs.
const MAX_HALF_OPEN: u32 = 2;
// Number of concurrent connection attempts in the burst. Mirrors the hand-reproduced N=5 case.
const BURST_CLIENTS: usize = 5;
// Generous: on a slow/loaded CI box a DNS-tunnel handshake (plus a Retry round-trip once the
// threshold engages) can take a while. We are proving the server serves everyone across the burst,
// not measuring latency.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

struct BurstClient {
    _guard: ChildGuard,
    logs: LogCapture,
    tcp_port: u16,
}

fn spawn_ready_client(
    client_bin: &std::path::Path,
    dns_port: u16,
    tcp_port: u16,
    cert: &std::path::Path,
) -> BurstClient {
    let (guard, logs) = spawn_client(ClientArgs {
        client_bin,
        dns_port,
        tcp_port,
        domain: DOMAIN,
        cert: Some(cert),
        keep_alive_interval: Some(1),
        envs: &[],
        rust_log: "info",
        capture_logs: true,
    });
    BurstClient {
        _guard: guard,
        logs: logs.expect("client logs"),
        tcp_port,
    }
}

/// Regression coverage for upstream issues #71/#37: a burst of concurrent connection
/// establishment requests must not wedge the single-threaded server. With a deliberately low
/// `--max-half-open-connections`, picoquic's adaptive Retry defense engages during the burst; this
/// asserts (1) the new flag is accepted and plumbed through, (2) every concurrent client still
/// establishes its connection ("Connection ready"), (3) the server process survives the burst, and
/// (4) a fresh, isolated connection made *after* the burst still succeeds -- i.e. the server is not
/// left in the "requires manual restart" state described in the bug reports.
#[test]
fn server_survives_concurrent_connection_burst() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();
    let (cert, key) = test_cert_and_key(&root);

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping burst connections e2e test: {}", err);
            return;
        }
    };

    // Pre-allocate every TCP listen port up front so the burst clients launch back-to-back with no
    // port-picking work interleaved -- keeps the connection attempts as concurrent as possible.
    let mut burst_ports = Vec::with_capacity(BURST_CLIENTS);
    for _ in 0..BURST_CLIENTS {
        match pick_tcp_port() {
            Ok(port) => burst_ports.push(port),
            Err(err) => {
                eprintln!("skipping burst connections e2e test: {}", err);
                return;
            }
        }
    }
    let isolated_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping burst connections e2e test: {}", err);
            return;
        }
    };

    // Dead target (127.0.0.1:1): clients reach "Connection ready" on the QUIC handshake alone and
    // never need to forward a stream, so no target harness is required.
    let (mut server, server_logs) = spawn_server(ServerArgs {
        server_bin: &server_bin,
        dns_listen_host: Some("127.0.0.1"),
        dns_port,
        target_address: "127.0.0.1:1",
        domains: &[DOMAIN],
        cert: &cert,
        key: &key,
        reset_seed_path: None,
        fallback_addr: None,
        idle_timeout_seconds: None,
        max_half_open_connections: Some(MAX_HALF_OPEN),
        envs: &[],
        rust_log: "info",
        capture_logs: true,
    });
    let server_logs = server_logs.expect("server logs");
    thread::sleep(Duration::from_millis(200));
    if server.has_exited() {
        let snapshot = log_snapshot(&server_logs);
        // If the server refused the new flag, it would exit immediately with a clap parse error --
        // surfacing that here makes a plumbing regression obvious rather than a silent skip.
        panic!(
            "server failed to start with --max-half-open-connections {}\n{}",
            MAX_HALF_OPEN, snapshot
        );
    }

    // Launch the whole burst back-to-back, then wait for readiness afterward so the handshakes
    // overlap in the server's single-threaded event loop.
    let burst: Vec<BurstClient> = burst_ports
        .iter()
        .map(|&tcp_port| spawn_ready_client(&client_bin, dns_port, tcp_port, &cert))
        .collect();

    let deadline = Instant::now() + READY_TIMEOUT;
    for client in &burst {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !wait_for_log(&client.logs, "Connection ready", remaining) {
            let client_snapshot = log_snapshot(&client.logs);
            let server_snapshot = log_snapshot(&server_logs);
            panic!(
                "burst client on tcp port {} did not become ready within the burst\n\
                 client logs:\n{}\nserver logs:\n{}",
                client.tcp_port, client_snapshot, server_snapshot
            );
        }
    }

    // The core regression symptom was the server being knocked out by the burst. It must still be
    // running.
    if server.has_exited() {
        let server_snapshot = log_snapshot(&server_logs);
        panic!(
            "server exited during/after the connection burst\nserver logs:\n{}",
            server_snapshot
        );
    }

    // ...and a brand-new, isolated connection made after the burst must still succeed, proving the
    // server recovered/stayed healthy rather than needing a restart.
    let isolated = spawn_ready_client(&client_bin, dns_port, isolated_port, &cert);
    if !wait_for_log(&isolated.logs, "Connection ready", READY_TIMEOUT) {
        let client_snapshot = log_snapshot(&isolated.logs);
        let server_snapshot = log_snapshot(&server_logs);
        panic!(
            "isolated post-burst client did not become ready\nclient logs:\n{}\nserver logs:\n{}",
            client_snapshot, server_snapshot
        );
    }

    assert!(
        !server.has_exited(),
        "server exited before the post-burst isolated connection completed"
    );
}
