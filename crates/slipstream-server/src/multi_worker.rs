//! Multi-worker Slipstream server: scale DNS/QUIC CPU across cores.
//!
//! # Why not plain SO_REUSEPORT?
//!
//! Clients (and recursive resolvers in front of them) spray **source ports**. The kernel's
//! default REUSEPORT hash is the full 4-tuple, so packets that belong to one QUIC connection
//! would land on different OS sockets / different picoquic contexts and break the tunnel.
//!
//! # Design (userspace demux)
//!
//! ```text
//!   UDP :53  ──recvmmsg──►  demux thread  ──hash(src_ip)%N──►  worker 0..N-1
//!                                                    │              │
//!                                                    │   own picoquic + ServerState
//!                                                    │   own current_thread tokio
//!                                                    └──────── sendto/sendmmsg ──►
//! ```
//!
//! - Affinity key is **source IP only** (port ignored). One resolver/client IP stays on one
//!   worker for the lifetime of the process, so picoquic connection state is consistent.
//! - Each worker owns a full picoquic context (picoquic is not thread-safe).
//! - Replies share the same bound `Arc<UdpSocket>` (UDP send is fine from many threads).
//! - `workers == 1` never enters this module (zero channel overhead on the common path).
//!
//! # Limits (intentional v1)
//!
//! - **RX still hits one core** (demux). For ~5–10 clients at a few kQPS each that is fine;
//!   the measured bottleneck was DNS encode/decode + picoquic, not raw recv.
//! - **Multi-resolver multipath** for a *single* client (packets from 1.1.1.1 and 8.8.8.8)
//!   may split across workers. Typical mobile/ISP clients use one recursive resolver IP;
//!   CID-sticky routing is a follow-up if multipath matters.
//! - Demux drops packets when a worker queue is full (DNS is lossy; client retries).

use crate::buf_pool::{BufPool, PooledBuf};
use crate::config::{ensure_cert_key, load_or_create_reset_seed, ResetSeed};
#[cfg(target_os = "linux")]
use crate::mmsg::{recv_ready, send_batch, try_recv_once, RecvMmsgBatch, SendBatchScratch};
use crate::server::{
    bind_tcp_listener, bind_udp_socket, map_io, maybe_gc_idle_connections, note_active_connections,
    ServerConfig, ServerError, Slot, DNS_MAX_QUERY_SIZE, FLOW_BLOCKED_LOG_INTERVAL_US,
    IDLE_SLEEP_MS, RETRANSMIT_REPLAY_WINDOW, SHOULD_SHUTDOWN, SLIPSTREAM_ALPN,
};
#[cfg(target_os = "linux")]
use crate::server::RECVMMSG_BATCH;
use crate::streams::{
    drain_commands, handle_command, handle_shutdown, maybe_report_command_stats, server_callback,
    ServerState,
};
use crate::target::TargetMode;
use crate::udp_fallback::{handle_packet, FallbackManager, PacketContext, MAX_UDP_PACKET_SIZE};
use slipstream_core::{
    net::is_transient_udp_error, normalize_dual_stack_addr, resolve_host_port,
};
use slipstream_dns::{encode_response_with_ttl_into, ResponseParams};
#[cfg(not(target_os = "linux"))]
use slipstream_ffi::picoquic::PICOQUIC_PACKET_LOOP_RECV_MAX;
use slipstream_ffi::picoquic::{
    picoquic_create, picoquic_current_time, picoquic_get_first_cnx, picoquic_get_next_cnx,
    picoquic_prepare_packet_ex, picoquic_quic_t, slipstream_has_ready_stream,
    slipstream_is_flow_blocked, slipstream_server_cc_algorithm,
    PICOQUIC_MAX_PACKET_SIZE,
};
use slipstream_ffi::{
    configure_quic_with_custom, set_server_half_open_retry_threshold, set_server_stream_data_control,
    socket_addr_to_storage, take_crypto_errors, QuicGuard,
};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::ffi::CString;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;

/// Per-worker inbound queue depth. DNS is lossy — prefer drop over unbounded RAM growth when a
/// worker is stuck or overloaded.
const WORKER_QUEUE_CAP: usize = 8192;
/// Soft cap on recycled DNS response buffers per worker (encode hot path).
const RESPONSE_BUF_POOL_CAP: usize = 256;

/// Packet handed from the demux thread to a worker.
///
/// `data` is a pooled slab (not a fresh malloc per packet) — live profiling under video
/// upload showed demux `to_vec` + glibc malloc as a measurable share of CPU.
struct DemuxPacket {
    data: PooledBuf,
    peer: SocketAddr,
    /// Present for DNS-over-TCP requests accepted on the shared listener.
    tcp_response: Option<oneshot::Sender<Vec<u8>>>,
}

/// Shared knobs cloned into each worker thread (no raw pointers / picoquic state).
#[derive(Clone)]
struct WorkerSpawnConfig {
    worker_id: usize,
    workers: usize,
    cert: String,
    key: String,
    reset_seed: Option<ResetSeed>,
    domains: Vec<String>,
    max_connections: u32,
    max_half_open_connections: u32,
    max_mtu: u32,
    idle_timeout_seconds: u64,
    debug_streams: bool,
    debug_commands: bool,
    target_mode: TargetMode,
    fallback_addr: Option<SocketAddr>,
    response_ttl: u32,
    response_ttl_jitter: u32,
    accepted_query_type: u16,
    map_ipv4_peers: bool,
    local_addr: SocketAddr,
}

/// Sticky worker index: hash(source IP) % N. Port is intentionally ignored.
pub(crate) fn affinity_worker(peer: SocketAddr, workers: usize) -> usize {
    debug_assert!(workers > 0);
    let ip = affinity_ip(peer);
    let mut hasher = DefaultHasher::new();
    ip.hash(&mut hasher);
    (hasher.finish() as usize) % workers
}

fn affinity_ip(peer: SocketAddr) -> IpAddr {
    match peer.ip() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            // Keep v4-mapped and native v4 of the same host on the same worker.
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
    }
}

pub(crate) async fn run_server_multi(config: &ServerConfig) -> Result<i32, ServerError> {
    let workers = config.workers;
    if workers < 2 {
        return Err(ServerError::new(
            "run_server_multi requires workers >= 2 (use run_server for single-threaded)",
        ));
    }

    let cert_path = Path::new(&config.cert);
    let key_path = Path::new(&config.key);
    let generated = ensure_cert_key(cert_path, key_path).map_err(ServerError::new)?;
    if generated {
        tracing::warn!(
            "Generated self-signed TLS cert/key at {} and {} (ECDSA P-256, 1000y validity); replace for production use",
            cert_path.display(),
            key_path.display()
        );
    }

    let reset_seed: Option<ResetSeed> = if let Some(path) = &config.reset_seed_path {
        let seed = load_or_create_reset_seed(Path::new(path)).map_err(ServerError::new)?;
        if seed.created {
            tracing::warn!(
                "Reset seed created at {}; stateless resets will now survive restarts",
                path
            );
        } else {
            tracing::debug!("Loaded reset seed from {}", path);
        }
        Some(seed)
    } else {
        tracing::warn!(
            "Reset seed not configured; stateless resets will not survive server restarts"
        );
        None
    };

    let target_mode = if config.socks_proxy_target {
        TargetMode::SocksProxy(
            resolve_host_port(&config.target_address)
                .map_err(|err| ServerError::new(err.to_string()))?,
        )
    } else if config.direct_socks_target {
        TargetMode::DirectSocks
    } else {
        TargetMode::Tcp(
            resolve_host_port(&config.target_address)
                .map_err(|err| ServerError::new(err.to_string()))?,
        )
    };
    let fallback_addr = match &config.fallback_address {
        Some(address) => {
            Some(resolve_host_port(address).map_err(|err| ServerError::new(err.to_string()))?)
        }
        None => None,
    };

    if config.domains.is_empty() {
        return Err(ServerError::new("At least one domain must be configured"));
    }
    crate::server::warn_overlapping_domains(&config.domains);

    let udp = Arc::new(bind_udp_socket(&config.dns_listen_host, config.dns_listen_port).await?);
    let tcp = bind_tcp_listener(&config.dns_listen_host, config.dns_listen_port).await?;
    let udp_local_addr = udp.local_addr().map_err(map_io)?;
    let tcp_local_addr = tcp.local_addr().map_err(map_io)?;
    tracing::info!(
        "DNS listeners ready udp={} tcp={} multi-worker workers={} affinity=src_ip",
        udp_local_addr,
        tcp_local_addr,
        workers
    );
    let map_ipv4_peers = matches!(udp_local_addr, SocketAddr::V6(_));
    if let Some(addr) = fallback_addr {
        if addr == udp_local_addr {
            tracing::warn!(
                "Fallback address matches DNS listen address ({}); non-DNS packets will loop. \
                 Configure a different fallback address.",
                addr
            );
        }
    }

    unsafe {
        let handler = handle_sigterm as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
    }

    let dropped = Arc::new(AtomicU64::new(0));
    let mut worker_txs = Vec::with_capacity(workers);
    let mut joins = Vec::with_capacity(workers);

    for worker_id in 0..workers {
        let (tx, rx) = mpsc::channel::<DemuxPacket>(WORKER_QUEUE_CAP);
        worker_txs.push(tx);

        let spawn_cfg = WorkerSpawnConfig {
            worker_id,
            workers,
            cert: config.cert.clone(),
            key: config.key.clone(),
            reset_seed: reset_seed.clone(),
            domains: config.domains.clone(),
            max_connections: config.max_connections,
            max_half_open_connections: config.max_half_open_connections,
            max_mtu: config.max_mtu,
            idle_timeout_seconds: config.idle_timeout_seconds,
            debug_streams: config.debug_streams,
            debug_commands: config.debug_commands,
            target_mode,
            fallback_addr,
            response_ttl: config.response_ttl,
            response_ttl_jitter: config.response_ttl_jitter,
            accepted_query_type: config.accepted_query_type,
            map_ipv4_peers,
            local_addr: udp_local_addr,
        };
        let udp_send = udp.clone();
        let name = format!("ss-worker-{worker_id}");
        let handle = std::thread::Builder::new()
            .name(name)
            .spawn(move || {
                let rt = Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .expect("Failed to build worker Tokio runtime");
                if let Err(err) = rt.block_on(run_worker(spawn_cfg, udp_send, rx)) {
                    tracing::error!("worker fatal: {}", err);
                }
            })
            .map_err(|err| ServerError::new(format!("Failed to spawn worker thread: {err}")))?;
        joins.push(handle);
    }

    let recv_buf_len = if fallback_addr.is_some() {
        MAX_UDP_PACKET_SIZE
    } else {
        DNS_MAX_QUERY_SIZE
    };
    let buf_pool = BufPool::new(recv_buf_len);
    tracing::info!(
        "multi-worker demux buffer pool slab_cap={} (steady-state path recycles Vec slabs)",
        recv_buf_len
    );

    let (tcp_dns_tx, mut tcp_dns_rx) = mpsc::unbounded_channel::<DemuxPacket>();
    tokio::spawn(accept_tcp_dns_demux(tcp, tcp_dns_tx, buf_pool.clone()));

    let demux_result = run_demux(
        udp,
        &worker_txs,
        &mut tcp_dns_rx,
        workers,
        fallback_addr.is_some(),
        dropped.clone(),
        buf_pool,
    )
    .await;

    // Tear down: close queues so workers drain and exit on SHOULD_SHUTDOWN / channel close.
    drop(worker_txs);
    for handle in joins {
        if let Err(err) = handle.join() {
            tracing::warn!("worker thread panicked: {:?}", err);
        }
    }

    demux_result
}

extern "C" fn handle_sigterm(_signum: libc::c_int) {
    SHOULD_SHUTDOWN.store(true, Ordering::Relaxed);
}

async fn run_demux(
    udp: Arc<tokio::net::UdpSocket>,
    worker_txs: &[mpsc::Sender<DemuxPacket>],
    tcp_dns_rx: &mut mpsc::UnboundedReceiver<DemuxPacket>,
    workers: usize,
    fallback_enabled: bool,
    dropped: Arc<AtomicU64>,
    buf_pool: BufPool,
) -> Result<i32, ServerError> {
    let recv_buf_len = if fallback_enabled {
        MAX_UDP_PACKET_SIZE
    } else {
        DNS_MAX_QUERY_SIZE
    };

    #[cfg(target_os = "linux")]
    let recvmmsg_batch = std::env::var("SLIPSTREAM_RECVMMSG_BATCH")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&v| v >= 1)
        .unwrap_or(RECVMMSG_BATCH);
    #[cfg(target_os = "linux")]
    tracing::info!("multi-worker demux recvmmsg batch size = {}", recvmmsg_batch);
    #[cfg(target_os = "linux")]
    let mut recv_batch = RecvMmsgBatch::new(recvmmsg_batch, recv_buf_len);
    #[cfg(not(target_os = "linux"))]
    let mut recv_buf = vec![0u8; recv_buf_len];

    let mut last_drop_log = Instant::now();
    let mut last_drop_count = 0u64;

    loop {
        if SHOULD_SHUTDOWN.load(Ordering::Relaxed) {
            tracing::info!("multi-worker demux shutting down");
            break;
        }

        #[cfg(target_os = "linux")]
        {
            tokio::select! {
                recv = recv_ready(&udp, &mut recv_batch) => {
                    match recv {
                        Ok(n) => {
                            for i in 0..n {
                                let (data, peer) = recv_batch.datagram(i);
                                dispatch_packet(
                                    worker_txs,
                                    workers,
                                    buf_pool.copy_from(data),
                                    peer,
                                    None,
                                    &dropped,
                                );
                            }
                            // Greedy drain: full batch ⇒ kernel likely has more. Keep pulling
                            // without another select sleep (cuts RcvbufErrors under TG upload peaks).
                            if n == recvmmsg_batch {
                                for _ in 0..8 {
                                    let more = match try_recv_once(&udp, &mut recv_batch) {
                                        Ok(m) => m,
                                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                                            break;
                                        }
                                        Err(err) if is_transient_udp_error(&err) => break,
                                        Err(err) => return Err(map_io(err)),
                                    };
                                    if more == 0 {
                                        break;
                                    }
                                    for i in 0..more {
                                        let (data, peer) = recv_batch.datagram(i);
                                        dispatch_packet(
                                            worker_txs,
                                            workers,
                                            buf_pool.copy_from(data),
                                            peer,
                                            None,
                                            &dropped,
                                        );
                                    }
                                    if more < recvmmsg_batch {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            if !is_transient_udp_error(&err) {
                                return Err(map_io(err));
                            }
                        }
                    }
                }
                tcp_req = tcp_dns_rx.recv() => {
                    if let Some(req) = tcp_req {
                        dispatch_packet(
                            worker_txs,
                            workers,
                            req.data,
                            req.peer,
                            req.tcp_response,
                            &dropped,
                        );
                    }
                }
                _ = sleep(Duration::from_millis(IDLE_SLEEP_MS)) => {}
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            tokio::select! {
                recv = udp.recv_from(&mut recv_buf) => {
                    match recv {
                        Ok((size, peer)) => {
                            dispatch_packet(
                                worker_txs,
                                workers,
                                buf_pool.copy_from(&recv_buf[..size]),
                                peer,
                                None,
                                &dropped,
                            );
                            for _ in 1..PICOQUIC_PACKET_LOOP_RECV_MAX {
                                match udp.try_recv_from(&mut recv_buf) {
                                    Ok((size, peer)) => {
                                        dispatch_packet(
                                            worker_txs,
                                            workers,
                                            buf_pool.copy_from(&recv_buf[..size]),
                                            peer,
                                            None,
                                            &dropped,
                                        );
                                    }
                                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                                    Err(err) => {
                                        if is_transient_udp_error(&err) {
                                            break;
                                        }
                                        return Err(map_io(err));
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            if !is_transient_udp_error(&err) {
                                return Err(map_io(err));
                            }
                        }
                    }
                }
                tcp_req = tcp_dns_rx.recv() => {
                    if let Some(req) = tcp_req {
                        dispatch_packet(
                            worker_txs,
                            workers,
                            req.data,
                            req.peer,
                            req.tcp_response,
                            &dropped,
                        );
                    }
                }
                _ = sleep(Duration::from_millis(IDLE_SLEEP_MS)) => {}
            }
        }

        // Periodic drop telemetry (info when non-zero so ops sees overload without RUST_LOG=debug).
        if last_drop_log.elapsed() >= Duration::from_secs(5) {
            let total = dropped.load(Ordering::Relaxed);
            let delta = total.saturating_sub(last_drop_count);
            if delta > 0 {
                tracing::warn!(
                    "multi-worker demux: dropped {} packets in last {}s (total={}) — worker queues full",
                    delta,
                    last_drop_log.elapsed().as_secs(),
                    total
                );
            }
            last_drop_count = total;
            last_drop_log = Instant::now();
        }
    }

    Ok(0)
}

fn dispatch_packet(
    worker_txs: &[mpsc::Sender<DemuxPacket>],
    workers: usize,
    data: PooledBuf,
    peer: SocketAddr,
    tcp_response: Option<oneshot::Sender<Vec<u8>>>,
    dropped: &AtomicU64,
) {
    let idx = affinity_worker(peer, workers);
    let packet = DemuxPacket {
        data,
        peer,
        tcp_response,
    };
    match worker_txs[idx].try_send(packet) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(packet)) => {
            dropped.fetch_add(1, Ordering::Relaxed);
            // Drop returns the slab to BufPool; TCP oneshot closes.
            drop(packet);
        }
        Err(mpsc::error::TrySendError::Closed(packet)) => {
            // Worker died; count as drop. Demux will exit on next shutdown check or fatal.
            dropped.fetch_add(1, Ordering::Relaxed);
            drop(packet);
        }
    }
}

async fn accept_tcp_dns_demux(
    listener: tokio::net::TcpListener,
    tx: mpsc::UnboundedSender<DemuxPacket>,
    buf_pool: BufPool,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let tx = tx.clone();
                let buf_pool = buf_pool.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_tcp_dns_connection(stream, peer, tx, buf_pool).await {
                        tracing::debug!("DNS TCP connection {} closed: {}", peer, err);
                    }
                });
            }
            Err(err) => {
                tracing::warn!("DNS TCP accept failed: {}", err);
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_tcp_dns_connection(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    tx: mpsc::UnboundedSender<DemuxPacket>,
    buf_pool: BufPool,
) -> Result<(), std::io::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    const DNS_TCP_MAX_QUERY_SIZE: usize = 4096;
    const DNS_TCP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(());
            }
            Err(err) => return Err(err),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > DNS_TCP_MAX_QUERY_SIZE {
            tracing::warn!("Rejecting DNS TCP query from {} with length {}", peer, len);
            return Ok(());
        }

        let mut packet = buf_pool.take(len);
        stream.read_exact(packet.as_mut_sized(len)).await?;
        let (response_tx, response_rx) = oneshot::channel();
        if tx
            .send(DemuxPacket {
                data: packet,
                peer,
                tcp_response: Some(response_tx),
            })
            .is_err()
        {
            return Ok(());
        }
        let response = match timeout(DNS_TCP_RESPONSE_TIMEOUT, response_rx).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => return Ok(()),
            Err(_) => {
                tracing::warn!("DNS TCP response timed out for {}", peer);
                return Ok(());
            }
        };
        if response.len() > u16::MAX as usize {
            tracing::warn!(
                "DNS TCP response too large for {}: {} bytes",
                peer,
                response.len()
            );
            return Ok(());
        }
        let mut frame = Vec::with_capacity(response.len() + 2);
        frame.extend_from_slice(&(response.len() as u16).to_be_bytes());
        frame.extend_from_slice(&response);
        stream.write_all(&frame).await?;
    }
}

async fn run_worker(
    cfg: WorkerSpawnConfig,
    udp: Arc<tokio::net::UdpSocket>,
    mut packet_rx: mpsc::Receiver<DemuxPacket>,
) -> Result<(), ServerError> {
    let worker_id = cfg.worker_id;
    tracing::info!(
        "multi-worker worker {}/{} starting (max_connections={})",
        worker_id + 1,
        cfg.workers,
        cfg.max_connections
    );

    let alpn = CString::new(SLIPSTREAM_ALPN)
        .map_err(|_| ServerError::new("ALPN contains an unexpected null byte"))?;
    let cert = CString::new(cfg.cert.clone())
        .map_err(|_| ServerError::new("Cert path contains an unexpected null byte"))?;
    let key = CString::new(cfg.key.clone())
        .map_err(|_| ServerError::new("Key path contains an unexpected null byte"))?;

    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let mut state = Box::new(ServerState::new(
        cfg.target_mode,
        command_tx,
        cfg.debug_streams,
        cfg.debug_commands,
    ));
    let state_ptr: *mut ServerState = &mut *state;
    let _state = state;

    let current_time = unsafe { picoquic_current_time() };
    let reset_seed_ptr = cfg
        .reset_seed
        .as_ref()
        .map(|seed| seed.bytes.as_ptr())
        .unwrap_or(std::ptr::null());
    let quic = unsafe {
        picoquic_create(
            cfg.max_connections,
            cert.as_ptr(),
            key.as_ptr(),
            std::ptr::null(),
            alpn.as_ptr(),
            Some(server_callback),
            state_ptr as *mut _,
            None,
            std::ptr::null_mut(),
            reset_seed_ptr,
            current_time,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    if quic.is_null() {
        let crypto_errors = take_crypto_errors();
        if crypto_errors.is_empty() {
            return Err(ServerError::new(format!(
                "worker {worker_id}: Could not create QUIC context"
            )));
        }
        return Err(ServerError::new(format!(
            "worker {worker_id}: Could not create QUIC context (TLS errors: {})",
            crypto_errors.join("; ")
        )));
    }
    let _quic_guard = QuicGuard::new(quic);
    unsafe {
        if slipstream_server_cc_algorithm.is_null() {
            return Err(ServerError::new(
                "Slipstream server congestion algorithm is unavailable",
            ));
        }
        configure_quic_with_custom(quic, slipstream_server_cc_algorithm, cfg.max_mtu);
        set_server_stream_data_control(quic);
        set_server_half_open_retry_threshold(quic, cfg.max_half_open_connections);
    }

    let local_addr_storage = socket_addr_to_storage(cfg.local_addr);
    let mut fallback_mgr = cfg
        .fallback_addr
        .map(|addr| FallbackManager::new(udp.clone(), addr, cfg.map_ipv4_peers));
    let domains: Vec<&str> = cfg.domains.iter().map(String::as_str).collect();
    let idle_timeout = Duration::from_secs(cfg.idle_timeout_seconds);

    let mut send_buf = vec![0u8; PICOQUIC_MAX_PACKET_SIZE];
    let mut last_seen = HashMap::new();
    let mut last_response: HashMap<usize, (Instant, Vec<u8>)> = HashMap::new();
    let mut last_idle_gc = Instant::now();
    let mut last_flow_block_log_at: u64 = 0;
    // Recycled DNS answer buffers + sendmmsg scratch (malloc was top-N in live perf).
    let mut response_free: Vec<Vec<u8>> = Vec::with_capacity(RESPONSE_BUF_POOL_CAP);
    #[cfg(target_os = "linux")]
    let mut send_scratch = SendBatchScratch::new();

    // UDP lazy-response hold (see the same block in server.rs::run_server_single). Parks an empty
    // poll for up to this long so downlink data rides back on it instead of costing the client a
    // whole extra round-trip. 0 = disabled. Env-tunable so rollout/rollback is a restart.
    let udp_lazy_hold_us: u64 = std::env::var("SLIPSTREAM_UDP_LAZY_HOLD_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        .saturating_mul(1000);
    let mut held: Vec<(Slot, u64)> = Vec::new();
    if udp_lazy_hold_us > 0 && worker_id == 0 {
        tracing::info!("UDP lazy-response hold enabled: {} us", udp_lazy_hold_us);
    }

    loop {
        drain_commands(state_ptr, &mut command_rx);

        if SHOULD_SHUTDOWN.load(Ordering::Relaxed) {
            let state = unsafe { &mut *state_ptr };
            if handle_shutdown(quic, state) {
                tracing::info!("multi-worker worker {} shutdown complete", worker_id);
                break;
            }
        }

        let mut slots = Vec::new();
        if let Some(manager) = fallback_mgr.as_mut() {
            manager.cleanup();
        }

        tokio::select! {
            command = command_rx.recv() => {
                if let Some(command) = command {
                    handle_command(state_ptr, command);
                }
            }
            packet = packet_rx.recv() => {
                match packet {
                    Some(packet) => {
                        let loop_time = unsafe { picoquic_current_time() };
                        let context = PacketContext {
                            domains: &domains,
                            quic,
                            current_time: loop_time,
                            local_addr_storage: &local_addr_storage,
                            accepted_query_type: cfg.accepted_query_type,
                        };
                        let slot_start = slots.len();
                        handle_packet(
                            &mut slots,
                            &packet.data,
                            packet.peer,
                            &context,
                            &mut fallback_mgr,
                        )
                        .await?;
                        if let Some(response_tx) = packet.tcp_response {
                            if let Some(slot) = slots.get_mut(slot_start) {
                                slot.tcp_response = Some(response_tx);
                            }
                        }
                        // Drain a burst already queued for this worker (same affinity) without
                        // waiting another select tick — cuts per-packet select overhead under load.
                        while slots.len() < 64 {
                            match packet_rx.try_recv() {
                                Ok(packet) => {
                                    let loop_time = unsafe { picoquic_current_time() };
                                    let context = PacketContext {
                                        domains: &domains,
                                        quic,
                                        current_time: loop_time,
                                        local_addr_storage: &local_addr_storage,
                                        accepted_query_type: cfg.accepted_query_type,
                                    };
                                    let slot_start = slots.len();
                                    handle_packet(
                                        &mut slots,
                                        &packet.data,
                                        packet.peer,
                                        &context,
                                        &mut fallback_mgr,
                                    )
                                    .await?;
                                    if let Some(response_tx) = packet.tcp_response {
                                        if let Some(slot) = slots.get_mut(slot_start) {
                                            slot.tcp_response = Some(response_tx);
                                        }
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    None => {
                        // Demux closed all senders — exit after graceful shutdown attempt.
                        SHOULD_SHUTDOWN.store(true, Ordering::Relaxed);
                        let state = unsafe { &mut *state_ptr };
                        if handle_shutdown(quic, state) {
                            break;
                        }
                    }
                }
            }
            _ = sleep(Duration::from_millis(IDLE_SLEEP_MS)) => {}
        }

        let now = Instant::now();
        if idle_timeout != Duration::ZERO {
            {
                let state = unsafe { &*state_ptr };
                note_active_connections(&mut last_seen, state, &slots, now);
            }
            maybe_gc_idle_connections(
                quic,
                state_ptr,
                &mut last_seen,
                &mut last_response,
                idle_timeout,
                &mut last_idle_gc,
                now,
            );
        }

        drain_commands(state_ptr, &mut command_rx);
        maybe_report_command_stats(state_ptr);

        if slots.is_empty() && held.is_empty() {
            continue;
        }

        respond_slots(
            &mut slots,
            &mut held,
            udp_lazy_hold_us,
            quic,
            state_ptr,
            &udp,
            &mut send_buf,
            &mut last_response,
            &mut last_flow_block_log_at,
            &mut response_free,
            #[cfg(target_os = "linux")]
            &mut send_scratch,
            cfg.response_ttl,
            cfg.response_ttl_jitter,
            cfg.map_ipv4_peers,
        )
        .await?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn respond_slots(
    slots: &mut Vec<Slot>,
    held: &mut Vec<(Slot, u64)>,
    udp_lazy_hold_us: u64,
    quic: *mut picoquic_quic_t,
    state_ptr: *mut ServerState,
    udp: &tokio::net::UdpSocket,
    send_buf: &mut [u8],
    last_response: &mut HashMap<usize, (Instant, Vec<u8>)>,
    last_flow_block_log_at: &mut u64,
    response_free: &mut Vec<Vec<u8>>,
    #[cfg(target_os = "linux")] send_scratch: &mut SendBatchScratch,
    response_ttl: u32,
    response_ttl_jitter: u32,
    map_ipv4_peers: bool,
) -> Result<(), ServerError> {
    const MAX_HELD_SLOTS: usize = 1024;
    let loop_time = unsafe { picoquic_current_time() };
    #[cfg(target_os = "linux")]
    let mut udp_responses: Vec<(Vec<u8>, SocketAddr)> =
        Vec::with_capacity(slots.len() + held.len());

    // Live-connection set so a held poll never prepares on a cnx that idle-GC freed mid-hold.
    let live_cnxs: std::collections::HashSet<usize> = if udp_lazy_hold_us > 0 && !held.is_empty() {
        let mut set = std::collections::HashSet::with_capacity(held.len());
        let mut c = unsafe { picoquic_get_first_cnx(quic) };
        while !c.is_null() {
            set.insert(c as usize);
            c = unsafe { picoquic_get_next_cnx(c) };
        }
        set
    } else {
        std::collections::HashSet::new()
    };

    // Working set = carried-over held polls (with their deadlines) + this iteration's fresh slots.
    let mut work: Vec<(Slot, Option<u64>)> = Vec::with_capacity(held.len() + slots.len());
    for (slot, deadline) in held.drain(..) {
        work.push((slot, Some(deadline)));
    }
    for slot in slots.drain(..) {
        work.push((slot, None));
    }
    let mut next_held: Vec<(Slot, u64)> = Vec::new();

    for (mut slot, carried_deadline) in work.drain(..) {
        let mut send_length = 0usize;
        let mut addr_to: slipstream_ffi::SockaddrStorage = unsafe { std::mem::zeroed() };
        let mut addr_from: slipstream_ffi::SockaddrStorage = unsafe { std::mem::zeroed() };
        let mut if_index: libc::c_int = 0;

        let cnx_dead = carried_deadline.is_some()
            && !slot.cnx.is_null()
            && !live_cnxs.contains(&(slot.cnx as usize));

        if slot.payload_override.is_none()
            && slot.rcode.is_none()
            && !slot.cnx.is_null()
            && !cnx_dead
        {
            let ret = unsafe {
                picoquic_prepare_packet_ex(
                    slot.cnx,
                    slot.path_id,
                    loop_time,
                    send_buf.as_mut_ptr(),
                    send_buf.len(),
                    &mut send_length,
                    &mut addr_to,
                    &mut addr_from,
                    &mut if_index,
                    std::ptr::null_mut(),
                )
            };
            if ret < 0 {
                return Err(ServerError::new("Failed to prepare QUIC packet"));
            }

            if send_length == 0 {
                let cnx_id = slot.cnx as usize;
                let metrics = unsafe { (&*state_ptr).stream_debug_metrics(cnx_id) };
                if metrics.streams_total > 0
                    && metrics.has_send_backlog()
                    && loop_time.saturating_sub(*last_flow_block_log_at)
                        >= FLOW_BLOCKED_LOG_INTERVAL_US
                {
                    let flow_blocked = unsafe { slipstream_is_flow_blocked(slot.cnx) != 0 };
                    let has_ready_stream = unsafe { slipstream_has_ready_stream(slot.cnx) != 0 };
                    let send_backlog =
                        unsafe { (&*state_ptr).stream_send_backlog_summaries(cnx_id, 8) };
                    tracing::warn!(
                        "server connection stalled: cnx={} streams={} streams_with_write_tx={} streams_with_data_rx={} queued_bytes_total={} streams_with_pending_data={} pending_chunks_total={} pending_bytes_total={} streams_with_pending_fin={} streams_with_fin_enqueued={} streams_with_target_fin_pending={} streams_with_send_pending={} streams_with_send_stash={} send_stash_bytes_total={} streams_discarding={} streams_close_after_flush={} multi_stream={} flow_blocked={} has_ready_stream={} send_backlog={:?}",
                        cnx_id,
                        metrics.streams_total,
                        metrics.streams_with_write_tx,
                        metrics.streams_with_data_rx,
                        metrics.queued_bytes_total,
                        metrics.streams_with_pending_data,
                        metrics.pending_chunks_total,
                        metrics.pending_bytes_total,
                        metrics.streams_with_pending_fin,
                        metrics.streams_with_fin_enqueued,
                        metrics.streams_with_target_fin_pending,
                        metrics.streams_with_send_pending,
                        metrics.streams_with_send_stash,
                        metrics.send_stash_bytes_total,
                        metrics.streams_discarding,
                        metrics.streams_close_after_flush,
                        metrics.multi_stream,
                        flow_blocked,
                        has_ready_stream,
                        send_backlog
                    );
                    *last_flow_block_log_at = loop_time;
                }
            }
        }

        // LAZY HOLD (v1): nothing at all to send for this poll -- park it (up to udp_lazy_hold_us)
        // instead of burning it on an empty answer, so the client doesn't have to spend another
        // query to collect whatever lands a moment later. Measured ~6x fewer client queries
        // (500 -> 85 q/s), relieving the mobile return path, the radio and the server.
        // Covers the TCP carrier too — see the matching comment in server.rs::respond_slots.
        if udp_lazy_hold_us > 0
            && send_length == 0
            && slot.payload_override.is_none()
            && slot.rcode.is_none()
            && !slot.cnx.is_null()
            && !cnx_dead
        {
            let deadline =
                carried_deadline.unwrap_or_else(|| loop_time.saturating_add(udp_lazy_hold_us));
            if loop_time < deadline && next_held.len() < MAX_HELD_SLOTS {
                next_held.push((slot, deadline));
                continue;
            }
        }

        let cnx_id = slot.cnx as usize;
        // Cache QUIC payload in last_response with clear+extend (no fresh to_vec alloc).
        if slot.payload_override.is_none() && send_length > 0 {
            let bytes = &send_buf[..send_length];
            let entry = last_response
                .entry(cnx_id)
                .or_insert_with(|| (Instant::now(), Vec::with_capacity(bytes.len())));
            entry.0 = Instant::now();
            entry.1.clear();
            entry.1.extend_from_slice(bytes);
        }

        let (payload, rcode) = if let Some(payload) = slot.payload_override.as_deref() {
            (Some(payload), slot.rcode)
        } else if send_length > 0 {
            (
                last_response.get(&cnx_id).map(|(_, v)| v.as_slice()),
                slot.rcode,
            )
        } else if slot.rcode.is_none() {
            match last_response.get(&cnx_id) {
                Some((sent_at, cached)) if sent_at.elapsed() < RETRANSMIT_REPLAY_WINDOW => {
                    (Some(cached.as_slice()), Some(slipstream_dns::Rcode::Ok))
                }
                _ => (None, Some(slipstream_dns::Rcode::Ok)),
            }
        } else {
            (None, slot.rcode)
        };
        let answer_ttl = if response_ttl_jitter > 0 {
            response_ttl.saturating_add((slot.id as u32) % (response_ttl_jitter + 1))
        } else {
            response_ttl
        };
        let mut response = response_free.pop().unwrap_or_else(|| Vec::with_capacity(512));
        encode_response_with_ttl_into(
            &ResponseParams {
                id: slot.id,
                rd: slot.rd,
                cd: slot.cd,
                question: &slot.question,
                payload,
                rcode,
                encoding: slot.encoding,
            },
            answer_ttl,
            &mut response,
        )
        .map_err(|err| ServerError::new(err.to_string()))?;
        if let Some(response_tx) = slot.tcp_response.take() {
            // TCP owns the buffer; do not recycle.
            let _ = response_tx.send(response);
        } else {
            let peer = if map_ipv4_peers {
                normalize_dual_stack_addr(slot.peer)
            } else {
                slot.peer
            };
            #[cfg(target_os = "linux")]
            {
                udp_responses.push((response, peer));
            }
            #[cfg(not(target_os = "linux"))]
            {
                if let Err(err) = udp.send_to(&response, peer).await {
                    if !is_transient_udp_error(&err) {
                        return Err(map_io(err));
                    }
                }
                if response_free.len() < RESPONSE_BUF_POOL_CAP {
                    response.clear();
                    response_free.push(response);
                }
            }
        }
    }
    *held = next_held;
    #[cfg(target_os = "linux")]
    {
        send_batch(udp, &mut udp_responses, send_scratch)
            .await
            .map_err(map_io)?;
        // Recycle answer buffers after send.
        for (mut buf, _) in udp_responses.drain(..) {
            if response_free.len() < RESPONSE_BUF_POOL_CAP && buf.capacity() <= 4096 {
                buf.clear();
                response_free.push(buf);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn affinity_ignores_port() {
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 1000));
        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 2000));
        assert_eq!(affinity_worker(a, 4), affinity_worker(b, 4));
    }

    #[test]
    fn affinity_differs_by_ip() {
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 53));
        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), 53));
        // Extremely unlikely to collide with DefaultHasher for these fixed inputs across 4 workers,
        // but if they do the test still checks determinism rather than strict inequality.
        let wa = affinity_worker(a, 64);
        let wb = affinity_worker(b, 64);
        assert_ne!(wa, wb);
    }

    #[test]
    fn affinity_maps_ipv4_mapped_to_same_bucket() {
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 4000));
        let v6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(203, 0, 113, 10).to_ipv6_mapped(),
            5000,
            0,
            0,
        ));
        assert_eq!(affinity_worker(v4, 8), affinity_worker(v6, 8));
    }

    #[test]
    fn affinity_stable() {
        let a = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0));
        assert_eq!(affinity_worker(a, 3), affinity_worker(a, 3));
    }
}
