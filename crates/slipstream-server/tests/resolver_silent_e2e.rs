#![cfg(unix)]
// SIGSTOP/SIGCONT (unix-only) are how this test simulates a resolver that goes completely
// silent -- no error, no FIN/RST, no ICMP unreachable -- rather than one that crashes or actively
// refuses connections. There's no dependency-free equivalent on Windows, and the CI job that runs
// this suite is Linux-only anyway.
mod support;

use std::time::{Duration, Instant};

use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, poke_client_with_payload,
    resume_process, server_bin_path, spawn_server_client_ready, suspend_process, test_cert_and_key,
    wait_for_log_since, workspace_root, ClientArgs, ServerArgs,
};

/// End-to-end version of the manual iptables test from this session: the resolver (here, the
/// whole server process) goes silent mid-connection while the client keeps a stream open and
/// keeps transmitting. The client's resolver_silent no-progress detector should fire within a
/// few seconds of the 5s NO_PROGRESS_TIMEOUT threshold (not the ~10s the pre-fix arm-then-wait
/// bug caused), and the client must exit promptly rather than hang or spin -- it deliberately
/// does not reconnect on its own for this error (see "leaving native reconnect to Android
/// service" in its own log line); that supervision is the Android service's job in production.
#[test]
fn resolver_silent_detector_resets_and_recovers() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();
    let (cert, key) = test_cert_and_key(&root);

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping resolver_silent e2e test: {}", err);
            return;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping resolver_silent e2e test: {}", err);
            return;
        }
    };
    let domain = "test.example.com";

    let harness = spawn_server_client_ready(
        ServerArgs {
            server_bin: &server_bin,
            dns_listen_host: Some("127.0.0.1"),
            dns_port,
            target_address: "127.0.0.1:1",
            domains: &[domain],
            cert: &cert,
            key: &key,
            reset_seed_path: None,
            fallback_addr: None,
            idle_timeout_seconds: None,
            envs: &[],
            rust_log: "info",
            capture_logs: true,
        },
        ClientArgs {
            client_bin: &client_bin,
            dns_port,
            tcp_port,
            domain,
            cert: Some(&cert),
            keep_alive_interval: Some(0),
            envs: &[],
            rust_log: "info",
            capture_logs: true,
        },
        "skipping resolver_silent e2e test: server failed to start",
        Duration::from_millis(200),
    );
    let Some(harness) = harness else {
        return;
    };

    // Open a stream so the detector's streams_len > 0 gate is satisfied -- the target address is
    // deliberately unroutable (matching restart_reconnect_e2e's convention), the stream just
    // needs to exist, not actually deliver anywhere.
    if !poke_client_with_payload(tcp_port, Duration::from_secs(2), &[0u8; 64]) {
        panic!(
            "client did not accept a TCP payload before the stall\n{}",
            log_snapshot(&harness.client_logs)
        );
    }

    let stall_start = Instant::now();
    suspend_process(&harness.server);

    let delay = wait_for_log_since(
        &harness.client_logs,
        "resolver_silent",
        stall_start,
        Duration::from_secs(9),
    );
    let Some(delay) = delay else {
        resume_process(&harness.server);
        panic!(
            "resolver_silent never fired within 9s of the resolver going silent\n{}",
            log_snapshot(&harness.client_logs)
        );
    };
    assert!(
        delay >= Duration::from_secs(4),
        "fired too early ({:?}) -- should need ~5s of true silence, not react to the initial poke",
        delay
    );
    resume_process(&harness.server);

    // The bare CLI client treats resolver_silent as fatal and exits, deliberately leaving
    // reconnection to whatever supervises it (the Android service's restart-on-native-death
    // logic, in production) rather than looping internally. What matters here is that it
    // actually exits promptly instead of hanging or spinning -- the original incident was a
    // client that never got the chance to reach this point at all.
    let mut client = harness.client;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !client.has_exited() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        client.has_exited(),
        "client did not exit promptly after detecting resolver_silent\n{}",
        log_snapshot(&harness.client_logs)
    );
}
