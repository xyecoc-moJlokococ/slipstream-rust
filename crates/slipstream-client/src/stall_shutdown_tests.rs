//! Regression test for the production incident analyzed in the vaydns-debug session
//! (2026-07-13): under a real `bridge_failures_accumulated` storm the native client logged
//! `Slipstream client stop timed out after 10s; detaching native thread` -- even though the
//! in-loop `shutdown_requested()` checks added by 91efbed were believed to close this gap
//! entirely (see the comment on `STOP_JOIN_TIMEOUT`: "the thread normally exits in well under a
//! second"). This drives the *real* client loop (the same `run_client_with_control_and_liveness`
//! call the JNI start path uses) against a real `slipstream-server` subprocess, builds genuine
//! backlog (many open streams with queued upload data), then blackholes the resolver (SIGSTOP on
//! the server, mirroring the resolver_silent_e2e convention) and measures how long the same
//! `join_or_detach` primitive `stop_running_client_with_timeout` uses actually takes to return.
//!
//! Deliberately calls `join_or_detach` directly (not `stop_running_client_with_timeout`) so this
//! test touches no process-global state (CLIENT/RUNNING/READY/CLIENT_GENERATION) and can't race
//! the other global-state tests in `lib.rs`'s own `tests` module.
#![cfg(unix)]

use std::io::Write;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant};

use slipstream_core::AddressFamily;
use slipstream_ffi::{
    ClientConfig, ResolverMode, ResolverSpec, ResolverTransport, UpstreamEncoding,
};
use tokio::sync::mpsc;

use crate::join_or_detach;
use crate::pacing::DEFAULT_PACING_GAIN_PROBE;
use crate::runtime::{run_client_with_control_and_liveness, DEFAULT_DNS_TCP_PACKET_LOOP_BURST};

/// How long the backlog-building writers push data, and how long the loop is left spinning
/// against the frozen server before we ask it to stop -- generous enough to build real backlog
/// (many streams, queued sends) without dragging the test out.
const BACKLOG_WRITE_STREAMS: usize = 64;
const BACKLOG_PAYLOAD_BYTES: usize = 128 * 1024;
/// Upper bound on how long `join_or_detach` may take before we conclude the wedge reproduced.
/// Comfortably below the real `STOP_JOIN_TIMEOUT` (10s) and the per-test timeout passed below
/// (5s) so a regression shows up as a clear failure margin, not a coin flip.
const MAX_ACCEPTABLE_STOP_LATENCY: Duration = Duration::from_secs(2);

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        // SIGKILL terminates a SIGSTOPped process too, so no SIGCONT is needed first.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn ensure_server_bin(root: &Path) -> Option<PathBuf> {
    let status = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("slipstream-server")
        .current_dir(root)
        .status();
    match status {
        Ok(status) if status.success() => {}
        _ => return None,
    }
    let mut path = root.join("target").join("debug").join("slipstream-server");
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path.exists().then_some(path)
}

fn pick_udp_port() -> Option<u16> {
    UdpSocket::bind("127.0.0.1:0")
        .ok()
        .and_then(|socket| socket.local_addr().ok())
        .map(|addr| addr.port())
}

fn pick_tcp_port() -> Option<u16> {
    TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|listener| listener.local_addr().ok())
        .map(|addr| addr.port())
}

#[test]
fn stop_returns_promptly_when_resolver_goes_silent_under_heavy_backlog() {
    let root = workspace_root();
    let cert = root.join("fixtures/certs/cert.pem");
    let key = root.join("fixtures/certs/key.pem");
    if !cert.exists() || !key.exists() {
        eprintln!("skipping stall-shutdown test: missing fixtures/certs/{{cert,key}}.pem");
        return;
    }
    let Some(server_bin) = ensure_server_bin(&root) else {
        eprintln!("skipping stall-shutdown test: failed to build slipstream-server");
        return;
    };
    let Some(dns_port) = pick_udp_port() else {
        eprintln!("skipping stall-shutdown test: could not pick a UDP port");
        return;
    };
    let Some(tcp_port) = pick_tcp_port() else {
        eprintln!("skipping stall-shutdown test: could not pick a TCP port");
        return;
    };
    let domain = "test.example.com";

    let server_child = Command::new(&server_bin)
        .arg("--dns-listen-host")
        .arg("127.0.0.1")
        .arg("--dns-listen-port")
        .arg(dns_port.to_string())
        .arg("--target-address")
        .arg("127.0.0.1:1") // deliberately unroutable -- same convention as resolver_silent_e2e
        .arg("--domain")
        .arg(domain)
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key)
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut server_child) = server_child else {
        eprintln!("skipping stall-shutdown test: failed to spawn slipstream-server");
        return;
    };
    thread::sleep(Duration::from_millis(300));
    if matches!(server_child.try_wait(), Ok(Some(_))) {
        eprintln!("skipping stall-shutdown test: slipstream-server exited immediately");
        return;
    }
    let server_pid = server_child.id();
    let _server_guard = KillOnDrop(server_child);

    let (stop_tx, stop_rx) = mpsc::unbounded_channel::<()>();
    let (ready_tx, ready_rx) = std_mpsc::channel::<bool>();
    let cert_str = cert.to_str().expect("cert path is valid utf8").to_string();
    let domain_owned = domain.to_string();
    let resolvers = vec![ResolverSpec {
        resolver: slipstream_core::HostPort {
            host: "127.0.0.1".to_string(),
            port: dns_port,
            family: AddressFamily::V4,
        },
        mode: ResolverMode::Recursive,
    }];

    let client_thread = thread::Builder::new()
        .name("stall-shutdown-test-client".to_string())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("failed to build client tokio runtime");
            let config = ClientConfig {
                tcp_listen_host: "127.0.0.1",
                tcp_listen_port: tcp_port,
                resolvers: &resolvers,
                domain: &domain_owned,
                cert: Some(&cert_str),
                verify_system_ca: false,
                congestion_control: None,
                gso: false,
                resolver_transport: ResolverTransport::Tcp,
                upstream_encoding: UpstreamEncoding::Qname,
                qname_mtu: 0,
                pacing_gain_probe: DEFAULT_PACING_GAIN_PROBE,
                dns_tcp_packet_loop_burst: DEFAULT_DNS_TCP_PACKET_LOOP_BURST,
                keep_alive_interval: 400,
                dns_query_type: 16,
                dns_label_length: 57,
                dns_label_length_jitter: 0,
                max_poll_qps: 0,
                debug_poll: false,
                debug_streams: false,
                base64u_encoding: false,
            };
            let _ = runtime.block_on(run_client_with_control_and_liveness(
                &config,
                Some(stop_rx),
                Some(ready_tx),
                None,
            ));
        })
        .expect("failed to spawn client thread");

    let ready_deadline = Instant::now() + Duration::from_secs(10);
    let mut became_ready = false;
    while Instant::now() < ready_deadline {
        match ready_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(true) => {
                became_ready = true;
                break;
            }
            Ok(false) => {}
            Err(std_mpsc::RecvTimeoutError::Timeout) => {}
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if !became_ready {
        let joined = join_or_detach(stop_tx, client_thread, Duration::from_secs(2));
        panic!(
            "client never became ready against the local test server (joined_on_cleanup={})",
            joined
        );
    }

    // Build genuine, *sustained* backlog: many parallel streams each pushing a large payload
    // continuously, mirroring the real incident's bridgeActive=48-ish storm. Deliberately NOT
    // joined before freezing the server -- the writers must still be actively feeding the tunnel
    // (and blocked on local TCP backpressure once the client can't keep draining them) at the
    // moment the resolver goes silent, otherwise this just measures an idle client, which already
    // worked fine before 91efbed too.
    let _writers: Vec<_> = (0..BACKLOG_WRITE_STREAMS)
        .filter_map(|_| TcpStream::connect(("127.0.0.1", tcp_port)).ok())
        .map(|mut stream| {
            thread::spawn(move || {
                let payload = vec![0xABu8; BACKLOG_PAYLOAD_BYTES];
                // Keep writing until the connection breaks (client stopped) or the thread is
                // torn down with the process -- intentionally never joined.
                loop {
                    if stream.write_all(&payload).is_err() {
                        break;
                    }
                }
            })
        })
        .collect();
    // Let backlog actually build up in the tunnel (streams open, data enqueued) before freezing.
    thread::sleep(Duration::from_millis(800));

    // Blackhole the resolver: SIGSTOP mirrors resolver_silent_e2e's "no error, no FIN/RST,
    // nothing" simulation of a dead/overwhelmed resolver -- not a clean disconnect.
    unsafe {
        let _ = libc::kill(server_pid as i32, libc::SIGSTOP);
    }
    // Writers keep pushing into the now-silent tunnel during this window, so the client is
    // actively backlogged (not idle) at the moment stop is requested below.
    thread::sleep(Duration::from_secs(4));

    let stop_started = Instant::now();
    let joined = join_or_detach(stop_tx, client_thread, Duration::from_secs(5));
    let elapsed = stop_started.elapsed();
    eprintln!(
        "stall_shutdown_tests: stop returned in {:?} (joined={})",
        elapsed, joined
    );

    assert!(
        joined,
        "client thread was detached (stop timed out) instead of joining cleanly -- \
         the wedge from the vaydns-debug incident reproduced under this backlog+silent-resolver \
         scenario; elapsed={:?}",
        elapsed
    );
    assert!(
        elapsed < MAX_ACCEPTABLE_STOP_LATENCY,
        "stop took {:?} to return -- the in-loop shutdown checks should bound this to a small \
         fraction of a second even under backlog + a silent resolver, not approach the 10s \
         STOP_JOIN_TIMEOUT",
        elapsed
    );
}
