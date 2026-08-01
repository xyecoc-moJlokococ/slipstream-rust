mod support;

use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, poke_client_with_payload,
    server_bin_path, spawn_client, spawn_server, test_cert_and_key, wait_for_any_log, wait_for_log,
    workspace_root, ClientArgs, ServerArgs,
};

/// Idle GC must tear down a connection that has no application streams, even while the client
/// keeps sending DNS poll packets. After GC, pushing data through the client's TCP port should
/// make the client observe the dead QUIC path (reset / close / no-progress).
#[test]
fn idle_gc_closes_connection() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();

    let (cert, key) = test_cert_and_key(&root);

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping idle gc e2e test: {}", err);
            return;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping idle gc e2e test: {}", err);
            return;
        }
    };
    let domain = "test.example.com";
    let reset_seed_path = temp_path("idle-gc-reset-seed");

    let (mut server, server_logs) = spawn_server(ServerArgs {
        server_bin: &server_bin,
        dns_listen_host: Some("127.0.0.1"),
        dns_port,
        target_address: "127.0.0.1:1",
        domains: &[domain],
        cert: &cert,
        key: &key,
        reset_seed_path: Some(&reset_seed_path),
        fallback_addr: None,
        idle_timeout_seconds: Some(1),
        max_half_open_connections: None,
        envs: &[],
        rust_log: "info",
        capture_logs: true,
    });
    let server_logs = server_logs.expect("server logs");
    thread::sleep(Duration::from_millis(200));
    if server.has_exited() {
        let _ = std::fs::remove_file(&reset_seed_path);
        eprintln!("skipping idle gc e2e test: server failed to start");
        return;
    }

    let (_client, client_logs) = spawn_client(ClientArgs {
        client_bin: &client_bin,
        dns_port,
        tcp_port,
        domain,
        cert: Some(&cert),
        // Disable QUIC keep-alives so the only remaining traffic is DNS polls (which must NOT
        // refresh the server idle timer — see note_active_connections).
        keep_alive_interval: Some(0),
        envs: &[],
        rust_log: "info",
        capture_logs: true,
    });
    let client_logs = client_logs.expect("client logs");
    if !wait_for_log(
        &client_logs,
        "Listening on TCP port",
        Duration::from_secs(5),
    ) {
        let snapshot = log_snapshot(&client_logs);
        let _ = std::fs::remove_file(&reset_seed_path);
        panic!("client did not start listening\n{}", snapshot);
    }
    if !wait_for_log(&client_logs, "Connection ready", Duration::from_secs(10)) {
        let snapshot = log_snapshot(&client_logs);
        let _ = std::fs::remove_file(&reset_seed_path);
        panic!("client did not become ready\n{}", snapshot);
    }

    if !wait_for_log(
        &server_logs,
        "idle gc: closing connection",
        Duration::from_secs(5),
    ) {
        let snapshot = log_snapshot(&server_logs);
        let _ = std::fs::remove_file(&reset_seed_path);
        panic!("expected idle gc close log\n{}", snapshot);
    }

    // Application traffic on the GC'd path: client should notice the connection is gone.
    let payload = [0u8; 128];
    if !poke_client_with_payload(tcp_port, Duration::from_secs(2), &payload) {
        let snapshot = log_snapshot(&client_logs);
        let _ = std::fs::remove_file(&reset_seed_path);
        panic!("client did not accept TCP connection\n{}", snapshot);
    }
    // Wording varies: stateless_reset (with seed), Connection closed, or local no-progress reset.
    if wait_for_any_log(
        &client_logs,
        &[
            "stateless_reset",
            "Connection closed",
            "connection closed",
            "no-progress",
            "resetting connection",
        ],
        Duration::from_secs(8),
    )
    .is_none()
    {
        let snapshot = log_snapshot(&client_logs);
        let server_snapshot = log_snapshot(&server_logs);
        let _ = std::fs::remove_file(&reset_seed_path);
        panic!(
            "expected client to observe connection close after idle GC\n--- client ---\n{}\n--- server ---\n{}",
            snapshot, server_snapshot
        );
    }

    let _ = std::fs::remove_file(&reset_seed_path);
}

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("slipstream-{}-{}", name, nanos));
    path
}
