mod support;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use socket2::SockRef;
use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, server_bin_path,
    spawn_server_client_ready, spawn_single_target, test_cert_and_key, wait_for_log,
    workspace_root, ClientArgs, ServerArgs,
};

const DOMAIN: &str = "test.example.com";
const RESPONSE_BYTES: usize = 64 * 1024;
const RESPONSE_CHUNK_BYTES: usize = 4096;
const RESPONSE_CHUNK_DELAY_MS: u64 = 50;

#[derive(Debug)]
enum TargetEvent {
    Accepted,
    RequestRead { _bytes: usize },
    ResponseSent { _bytes: usize },
    ResponseFailed,
}

#[test]
fn epipe_triggers_quic_reset() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();

    let (cert, key) = test_cert_and_key(&root);

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping epipe reset e2e test: {}", err);
            return;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping epipe reset e2e test: {}", err);
            return;
        }
    };

    let (app_closed_tx, app_closed_rx) = mpsc::channel();
    let target = match spawn_single_target(
        Some(TargetEvent::ResponseFailed),
        move |mut stream, tx, stop_flag| {
            let stop_conn = Arc::clone(&stop_flag);
            Some(thread::spawn(move || {
                let _ = tx.send(TargetEvent::Accepted);
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                let mut buf = [0u8; 4096];
                let mut total = 0usize;
                loop {
                    if stop_conn.load(Ordering::Relaxed) {
                        return;
                    }
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            total = total.saturating_add(n);
                            break;
                        }
                        Err(err)
                            if err.kind() == std::io::ErrorKind::Interrupted
                                || err.kind() == std::io::ErrorKind::WouldBlock
                                || err.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    }
                }
                let _ = tx.send(TargetEvent::RequestRead { _bytes: total });
                if app_closed_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                    let _ = tx.send(TargetEvent::ResponseFailed);
                    return;
                }
                if stop_conn.load(Ordering::Relaxed) {
                    return;
                }
                let response = vec![0u8; RESPONSE_BYTES];
                for chunk in response.chunks(RESPONSE_CHUNK_BYTES) {
                    if stream.write_all(chunk).is_err() {
                        let _ = tx.send(TargetEvent::ResponseFailed);
                        return;
                    }
                    thread::sleep(Duration::from_millis(RESPONSE_CHUNK_DELAY_MS));
                }
                let _ = stream.shutdown(Shutdown::Write);
                let _ = tx.send(TargetEvent::ResponseSent {
                    _bytes: response.len(),
                });
            }))
        },
    ) {
        Ok(target) => target,
        Err(err) => {
            eprintln!("skipping epipe reset e2e test: {}", err);
            return;
        }
    };

    let harness = match spawn_server_client_ready(
        ServerArgs {
            server_bin: &server_bin,
            dns_listen_host: Some("127.0.0.1"),
            dns_port,
            target_address: &format!("127.0.0.1:{}", target.addr.port()),
            domains: &[DOMAIN],
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
            domain: DOMAIN,
            cert: Some(&cert),
            keep_alive_interval: Some(0),
            envs: &[],
            rust_log: "info",
            capture_logs: true,
        },
        "skipping epipe reset e2e test: server failed to start",
        Duration::from_millis(0),
    ) {
        Some(harness) => harness,
        None => return,
    };
    let support::ServerClientHarness {
        server: _server,
        client: _client,
        server_logs,
        client_logs,
    } = harness;

    let client_addr = SocketAddr::from(([127, 0, 0, 1], tcp_port));
    let mut app = TcpStream::connect_timeout(&client_addr, Duration::from_secs(2))
        .expect("connect client tcp port");
    let _ = app.set_nodelay(true);
    app.write_all(b"epipe-reset-test")
        .expect("write app payload");

    let mut saw_accept = false;
    let mut saw_read = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && (!saw_accept || !saw_read) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Some(event) = target.recv_event(remaining) else {
            break;
        };
        match event {
            TargetEvent::Accepted => saw_accept = true,
            TargetEvent::RequestRead { .. } => saw_read = true,
            _ => {}
        }
    }
    if !saw_accept || !saw_read {
        let snapshot = log_snapshot(&server_logs);
        panic!(
            "target did not accept/read request (accepted={} read={})\n{}",
            saw_accept, saw_read, snapshot
        );
    }

    // Issue #60 (STOP_SENDING vs RESET_STREAM half-close): deterministically exercise the local
    // WRITE-error path rather than racing a read error. First send a clean FIN (Shutdown::Write)
    // so the client's reader task sees a graceful EOF (Command::StreamLocalTcpEof -- an unrelated,
    // unchanged path that does NOT abort the stream) instead of ECONNRESET on a pending read. The
    // client's reader then exits and will not observe the subsequent RST. Only then do we fully
    // drop the socket with SO_LINGER=0 (forcing an RST): when the client's WRITER later tries to
    // deliver the delayed response it hits a genuine EPIPE/ECONNRESET write error
    // (Command::StreamWriteError) against a socket that is already gone.
    app.shutdown(Shutdown::Write)
        .expect("half-close app write side (clean FIN)");
    // No client-side log is emitted on local TCP EOF, so wait a short fixed interval for the
    // reader task to process the clean EOF before forcing the RST. This is a test-only timing aid,
    // acceptable here because it is not production code.
    thread::sleep(Duration::from_millis(300));
    let _ = SockRef::from(&app).set_linger(Some(Duration::from_secs(0)));
    drop(app);
    let _ = app_closed_tx.send(());

    let mut response_attempted = false;
    let response_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < response_deadline && !response_attempted {
        let remaining = response_deadline.saturating_duration_since(Instant::now());
        let Some(event) = target.recv_event(remaining) else {
            break;
        };
        match event {
            TargetEvent::ResponseSent { .. } => response_attempted = true,
            TargetEvent::ResponseFailed => response_attempted = true,
            _ => {}
        }
    }
    if !response_attempted {
        let snapshot = log_snapshot(&server_logs);
        panic!("target did not attempt response\n{}", snapshot);
    }

    // Necessary (but on its own NOT sufficient) precondition: the client must take the
    // WRITE-error path specifically ("tcp write error"), not a read-error abort. NOTE: this exact
    // log line is emitted by BOTH the old full-bidi-abort code and the new half-close code, so it
    // only proves the write path was hit -- it does NOT by itself discriminate the fix from a
    // revert. The discriminating proof is the server-side STOP_SENDING/no-RESET_STREAM assertion
    // below.
    if !wait_for_log(&client_logs, "tcp write error", Duration::from_secs(5)) {
        let snapshot = log_snapshot(&client_logs);
        panic!(
            "expected client 'tcp write error' (issue #60 write-error path)\n{}",
            snapshot
        );
    }

    // Hard, DISCRIMINATING regression proof for issue #60 (STOP_SENDING vs RESET_STREAM). The
    // half-close fix issues `picoquic_stop_sending` ONLY, so the server observes a `stop_sending`
    // reset-event and MUST NOT observe a `stream_reset` (RESET_STREAM) reset-event for this
    // stream. The OLD full-bidi-abort code (`abort_stream_bidi` = STOP_SENDING + RESET_STREAM)
    // would make the server log a `stream_reset` event, so this pair of checks fails on a revert.
    //
    // First wait for positive proof the STOP_SENDING reached the server (this is the fix's own
    // signal). Absence of this is itself a failure -- unlike the previous version, which demoted
    // it to a non-failing note and thereby provided no positive evidence at all.
    if !wait_for_log(
        &server_logs,
        "reset event=stop_sending",
        Duration::from_secs(8),
    ) {
        let snapshot = log_snapshot(&server_logs);
        panic!(
            "expected server 'reset event=stop_sending' (issue #60 STOP_SENDING half-close reached \
             the server)\n{}",
            snapshot
        );
    }
    // The old full abort would additionally emit RESET_STREAM (sent together with STOP_SENDING by
    // abort_stream_bidi). Give any such frame time to arrive and be logged, then assert the server
    // never saw a stream_reset for this stream. Under the fix this holds; a revert to
    // abort_stream_bidi fails here. log_snapshot reads the retained line buffer, so it still sees
    // every server line even though wait_for_log above drained the channel.
    thread::sleep(Duration::from_millis(300));
    let server_snapshot = log_snapshot(&server_logs);
    assert!(
        !server_snapshot.contains("reset event=stream_reset"),
        "issue #60 regression: server observed a RESET_STREAM (full bidi abort) rather than a \
         STOP_SENDING-only half-close -- the fix has been reverted or broken\nserver logs:\n{}",
        server_snapshot
    );
}
