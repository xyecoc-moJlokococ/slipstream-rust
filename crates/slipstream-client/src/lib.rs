mod dns;
mod error;
mod pacing;
mod pinning;
mod platform;
mod runtime;
#[cfg(test)]
mod stall_shutdown_tests;
mod streams;
mod system_ca;

use jni::objects::{JBooleanArray, JIntArray, JObject, JObjectArray, JString};
use jni::sys::{jdouble, jint, jstring, JNI_VERSION_1_6};
use jni::{JNIEnv, JavaVM};
use slipstream_core::{normalize_domain, parse_host_port_parts, AddressKind};
use slipstream_ffi::{
    ClientConfig, ResolverMode, ResolverSpec, ResolverTransport, UpstreamEncoding,
};
use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::runtime::Builder;
use tokio::sync::mpsc;

use pacing::sanitize_pacing_gain_probe;
use runtime::{sanitize_dns_tcp_packet_loop_burst, DEFAULT_DNS_TCP_PACKET_LOOP_BURST};

struct ClientHandle {
    stop_tx: mpsc::UnboundedSender<()>,
    thread: JoinHandle<()>,
    generation: u64,
}

struct ProbeClientHandle {
    stop_tx: mpsc::UnboundedSender<()>,
    thread: JoinHandle<()>,
    running: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
}

static CLIENT: OnceLock<Mutex<Option<ClientHandle>>> = OnceLock::new();
static PROBE_CLIENTS: OnceLock<Mutex<HashMap<u16, ProbeClientHandle>>> = OnceLock::new();
static CLIENT_GENERATION: AtomicU64 = AtomicU64::new(0);
static RUNNING: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
/// DNS query type (RR type) the client sends in poll queries. Default 16 = TXT (unchanged behavior).
/// Set from Kotlin via nativeSetDnsQueryType before starting a client; applies to the main + probe
/// clients. Used as an anti-fingerprinting knob (e.g. 65 = HTTPS/SVCB).
static DNS_QUERY_TYPE: AtomicU16 = AtomicU16::new(16);
/// DNS label length (chars) for the encoded subdomain. Default = slipstream_dns::DEFAULT_LABEL_LEN
/// (57). Client-only fingerprint knob: the server strips dots before decoding, so this never needs
/// to match a server setting. Set from Kotlin via nativeSetDnsLabelLength.
static DNS_LABEL_LENGTH: AtomicU32 = AtomicU32::new(57);
/// Optional cap on DNS poll queries per second (0 = unlimited). Purely a client-side pacing choice
/// with no server-side counterpart. Set from Kotlin via nativeSetMaxPollQps.
static MAX_POLL_QPS: AtomicU32 = AtomicU32::new(0);
/// Cap on **data-bearing** DNS queries/sec from the QUIC send loop (0 = unlimited).
/// Keeps multi-stream upload from starving the reverse path (MAX_STREAM_DATA / TLS).
/// Fixed ceiling only — no thrash-adaptive.
/// Default **800** (was 1000): live Spain VPS still saw RcvbufErrors at multi-kQPS peaks; a
/// slightly lower data firehose improves stream survival (TG video parts were stream_reset
/// after ~0.7 MiB). App can still raise via maxDataQps / nativeSetMaxDataQps.
pub(crate) const DEFAULT_MAX_DATA_QPS: u32 = 800;
static MAX_DATA_QPS: AtomicU32 = AtomicU32::new(DEFAULT_MAX_DATA_QPS);
/// Encode the tunnel payload with base64u instead of base32 (default false). Purely a client
/// choice, no server config needed -- see slipstream_ffi::ClientConfig::base64u_encoding for the
/// case-sensitivity caveat. Set from Kotlin via nativeSetBase64uEncoding.
static BASE64U_ENCODING: AtomicBool = AtomicBool::new(false);
static LAST_ERROR: OnceLock<Mutex<Option<String>>> = OnceLock::new();
// Wait long enough for the client thread to actually finish before giving up and detaching it.
// A detached thread keeps holding the local listen socket, so the next start fails with EADDRINUSE
// and the tunnel wedges until the whole app is killed. With the prompt in-loop shutdown check the
// thread normally exits in well under a second; this ceiling only matters if a single paced send is
// stuck, and waiting a bit longer to reclaim the port beats leaking it.
const STOP_JOIN_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_JOIN_POLL: Duration = Duration::from_millis(25);

fn client_slot() -> &'static Mutex<Option<ClientHandle>> {
    CLIENT.get_or_init(|| Mutex::new(None))
}

fn probe_clients_slot() -> &'static Mutex<HashMap<u16, ProbeClientHandle>> {
    PROBE_CLIENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn last_error_slot() -> &'static Mutex<Option<String>> {
    LAST_ERROR.get_or_init(|| Mutex::new(None))
}

fn set_last_error(message: impl Into<String>) {
    if let Ok(mut last_error) = last_error_slot().lock() {
        *last_error = Some(message.into());
    }
}

fn clear_last_error() {
    if let Ok(mut last_error) = last_error_slot().lock() {
        *last_error = None;
    }
}

fn is_current_generation(generation: u64) -> bool {
    CLIENT_GENERATION.load(Ordering::SeqCst) == generation
}

fn store_running(generation: u64, value: bool) {
    if is_current_generation(generation) {
        RUNNING.store(value, Ordering::SeqCst);
    }
}

fn store_ready(generation: u64, value: bool) {
    if is_current_generation(generation) {
        READY.store(value, Ordering::SeqCst);
    }
}

#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
    #[cfg(target_os = "android")]
    {
        if let Ok(mut env) = vm.get_env() {
            if let Ok(class) = env.find_class("app/slipnet/tunnel/SlipstreamBridge") {
                platform::set_bridge_class(&mut env, class);
            }
        }
        platform::set_java_vm(vm);
        platform::init_android_logging();
        platform::install_panic_hook();
    }
    #[cfg(not(target_os = "android"))]
    let _ = vm;
    JNI_VERSION_1_6
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeSetDnsQueryType(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
    qtype: jint,
) {
    // Clamp to a valid RR type range; 0 or out-of-range falls back to TXT.
    let value = if qtype > 0 && qtype <= u16::MAX as jint {
        qtype as u16
    } else {
        16
    };
    DNS_QUERY_TYPE.store(value, Ordering::Relaxed);
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeSetDnsLabelLength(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
    label_len: jint,
) {
    // Clamp to the valid DNS label range (1..=63); 0/out-of-range falls back to the default (57).
    let value = if (1..=63).contains(&label_len) {
        label_len as u32
    } else {
        57
    };
    DNS_LABEL_LENGTH.store(value, Ordering::Relaxed);
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeSetMaxPollQps(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
    qps: jint,
) {
    // 0 (or negative) means unlimited.
    let value = if qps > 0 { qps as u32 } else { 0 };
    MAX_POLL_QPS.store(value, Ordering::Relaxed);
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeSetMaxDataQps(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
    qps: jint,
) {
    let value = if qps > 0 { qps as u32 } else { 0 };
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

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeSetBase64uEncoding(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
    enabled: bool,
) {
    BASE64U_ENCODING.store(enabled, Ordering::Relaxed);
}

#[no_mangle]
#[allow(unused_mut)]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeSetLogFilePath(
    mut env: JNIEnv<'_>,
    _this: JObject<'_>,
    path: JString<'_>,
) {
    #[cfg(target_os = "android")]
    {
        let path = java_string(&mut env, &path).ok();
        platform::set_log_file_path(path);
    }
    #[cfg(not(target_os = "android"))]
    let _ = (env, path);
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeStartSlipstreamClient(
    mut env: JNIEnv<'_>,
    _this: JObject<'_>,
    domain: JString<'_>,
    resolver_hosts: JObjectArray<'_>,
    resolver_ports: JIntArray<'_>,
    resolver_authoritative: JBooleanArray<'_>,
    listen_port: jint,
    listen_host: JString<'_>,
    congestion_control: JString<'_>,
    keep_alive_interval: jint,
    gso_enabled: bool,
    debug_poll: bool,
    debug_streams: bool,
    _idle_poll_interval: jint,
    _idle_timeout_ms: jint,
    resolver_transport: JString<'_>,
    pacing_gain_probe: jdouble,
    dns_tcp_packet_loop_burst: jint,
    qname_compatibility_mode: bool,
    qname_mtu: jint,
) -> jint {
    clear_last_error();
    if RUNNING.load(Ordering::SeqCst) {
        set_last_error("Slipstream client is already running");
        return -10;
    }
    let _ = stop_running_client();

    let domain = match java_string(&mut env, &domain)
        .and_then(|value| normalize_domain(&value).map_err(|err| err.to_string()))
    {
        Ok(domain) => domain,
        Err(err) => {
            set_last_error(err);
            return -1;
        }
    };
    let listen_host = match java_string(&mut env, &listen_host) {
        Ok(host) => host,
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    let congestion_control = match java_string(&mut env, &congestion_control) {
        Ok(value) if value.trim().is_empty() => None,
        Ok(value) => Some(value),
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    let resolver_transport = match java_string(&mut env, &resolver_transport) {
        Ok(value) => parse_resolver_transport(&value),
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    let mut resolvers = match read_resolvers(
        &mut env,
        resolver_hosts,
        resolver_ports,
        resolver_authoritative,
    ) {
        Ok(resolvers) => resolvers,
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    if resolver_transport == ResolverTransport::Tcp && resolvers.len() > 1 {
        resolvers.truncate(1);
    }
    if resolvers.is_empty() || !(1..=u16::MAX as jint).contains(&listen_port) {
        set_last_error("invalid Slipstream resolver or listen port configuration");
        return -2;
    }
    let pacing_gain_probe = sanitize_pacing_gain_probe(pacing_gain_probe);
    let dns_tcp_packet_loop_burst = if dns_tcp_packet_loop_burst > 0 {
        sanitize_dns_tcp_packet_loop_burst(dns_tcp_packet_loop_burst as usize)
    } else {
        DEFAULT_DNS_TCP_PACKET_LOOP_BURST
    };

    let (stop_tx, stop_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (started_tx, started_rx) = std_mpsc::channel();
    let generation = CLIENT_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    let thread = match thread::Builder::new()
        .name("slipstream-client".to_string())
        .spawn(move || {
            store_running(generation, true);
            store_ready(generation, false);
            let _ = started_tx.send(());
            let runtime = match Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    set_last_error(format!("failed to build Tokio runtime: {}", err));
                    store_running(generation, false);
                    return;
                }
            };
            let config = ClientConfig {
                tcp_listen_host: &listen_host,
                tcp_listen_port: listen_port as u16,
                resolvers: &resolvers,
                congestion_control: congestion_control.as_deref(),
                gso: gso_enabled,
                domain: &domain,
                cert: None,
                verify_system_ca: false,
                keep_alive_interval: keep_alive_interval.max(0) as usize,
                resolver_transport,
                upstream_encoding: if qname_compatibility_mode {
                    UpstreamEncoding::Qname
                } else {
                    UpstreamEncoding::EdnsRaw
                },
                qname_mtu: qname_mtu.max(0) as u32,
                pacing_gain_probe,
                dns_tcp_packet_loop_burst,
                // Anti-fingerprinting / pacing knobs: set from Kotlin via the nativeSet* setters
                // (called right before each native start); defaults preserve historical behavior.
                dns_query_type: DNS_QUERY_TYPE.load(Ordering::Relaxed),
                dns_label_length: DNS_LABEL_LENGTH.load(Ordering::Relaxed) as usize,
                max_poll_qps: MAX_POLL_QPS.load(Ordering::Relaxed),
                debug_poll,
                debug_streams,
                base64u_encoding: BASE64U_ENCODING.load(Ordering::Relaxed),
            };
            if let Err(err) = runtime.block_on(runtime::run_client_with_control_and_liveness(
                &config,
                Some(stop_rx),
                Some(ready_tx),
                // Self-terminate if this generation is superseded. A recovery restart (stop+start)
                // bumps CLIENT_GENERATION, and stop_running_client bumps it too, so a thread that
                // missed its mpsc stop signal (busy-spinning) still exits instead of orphaning at
                // 100% CPU until the app is force-killed.
                Some(Box::new(move || !is_current_generation(generation))),
            )) {
                set_last_error(err.to_string());
            }
            store_ready(generation, false);
            store_running(generation, false);
        }) {
        Ok(thread) => thread,
        Err(err) => {
            set_last_error(format!("failed to spawn Slipstream client thread: {}", err));
            if is_current_generation(generation) {
                RUNNING.store(false, Ordering::SeqCst);
                READY.store(false, Ordering::SeqCst);
            }
            return -10;
        }
    };
    let _ = started_rx.recv_timeout(Duration::from_secs(1));
    thread::sleep(Duration::from_millis(150));
    if !RUNNING.load(Ordering::SeqCst) {
        let _ = thread.join();
        return -11;
    }

    thread::spawn(move || {
        while let Ok(ready) = ready_rx.recv() {
            store_ready(generation, ready);
        }
        store_ready(generation, false);
    });

    if let Ok(mut client) = client_slot().lock() {
        *client = Some(ClientHandle {
            stop_tx,
            thread,
            generation,
        });
        0
    } else {
        set_last_error("failed to lock Slipstream client state");
        -10
    }
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeStartProbeClient(
    mut env: JNIEnv<'_>,
    _this: JObject<'_>,
    domain: JString<'_>,
    resolver_hosts: JObjectArray<'_>,
    resolver_ports: JIntArray<'_>,
    resolver_authoritative: JBooleanArray<'_>,
    listen_port: jint,
    listen_host: JString<'_>,
    congestion_control: JString<'_>,
    keep_alive_interval: jint,
    gso_enabled: bool,
    debug_poll: bool,
    debug_streams: bool,
    _idle_poll_interval: jint,
    _idle_timeout_ms: jint,
    resolver_transport: JString<'_>,
    pacing_gain_probe: jdouble,
    dns_tcp_packet_loop_burst: jint,
    qname_compatibility_mode: bool,
    qname_mtu: jint,
) -> jint {
    clear_last_error();

    let domain = match java_string(&mut env, &domain)
        .and_then(|value| normalize_domain(&value).map_err(|err| err.to_string()))
    {
        Ok(domain) => domain,
        Err(err) => {
            set_last_error(err);
            return -1;
        }
    };
    let listen_host = match java_string(&mut env, &listen_host) {
        Ok(host) => host,
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    let congestion_control = match java_string(&mut env, &congestion_control) {
        Ok(value) if value.trim().is_empty() => None,
        Ok(value) => Some(value),
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    let resolver_transport = match java_string(&mut env, &resolver_transport) {
        Ok(value) => parse_resolver_transport(&value),
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    let mut resolvers = match read_resolvers(
        &mut env,
        resolver_hosts,
        resolver_ports,
        resolver_authoritative,
    ) {
        Ok(resolvers) => resolvers,
        Err(err) => {
            set_last_error(err);
            return -2;
        }
    };
    if resolver_transport == ResolverTransport::Tcp && resolvers.len() > 1 {
        resolvers.truncate(1);
    }
    if resolvers.is_empty() || !(1..=u16::MAX as jint).contains(&listen_port) {
        set_last_error("invalid Slipstream probe resolver or listen port configuration");
        return -2;
    }
    let listen_port_u16 = listen_port as u16;
    let _ = stop_probe_client_by_port(listen_port_u16);
    let pacing_gain_probe = sanitize_pacing_gain_probe(pacing_gain_probe);
    let dns_tcp_packet_loop_burst = if dns_tcp_packet_loop_burst > 0 {
        sanitize_dns_tcp_packet_loop_burst(dns_tcp_packet_loop_burst as usize)
    } else {
        DEFAULT_DNS_TCP_PACKET_LOOP_BURST
    };

    let (stop_tx, stop_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (started_tx, started_rx) = std_mpsc::channel();
    let running_flag = Arc::new(AtomicBool::new(false));
    let ready_flag = Arc::new(AtomicBool::new(false));
    let thread_running = Arc::clone(&running_flag);
    let thread_ready = Arc::clone(&ready_flag);
    let thread = match thread::Builder::new()
        .name(format!("slipstream-probe-client-{}", listen_port_u16))
        .spawn(move || {
            thread_running.store(true, Ordering::SeqCst);
            thread_ready.store(false, Ordering::SeqCst);
            let _ = started_tx.send(());
            let runtime = match Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    set_last_error(format!("failed to build probe Tokio runtime: {}", err));
                    thread_running.store(false, Ordering::SeqCst);
                    return;
                }
            };
            let config = ClientConfig {
                tcp_listen_host: &listen_host,
                tcp_listen_port: listen_port as u16,
                resolvers: &resolvers,
                congestion_control: congestion_control.as_deref(),
                gso: gso_enabled,
                domain: &domain,
                cert: None,
                verify_system_ca: false,
                keep_alive_interval: keep_alive_interval.max(0) as usize,
                resolver_transport,
                upstream_encoding: if qname_compatibility_mode {
                    UpstreamEncoding::Qname
                } else {
                    UpstreamEncoding::EdnsRaw
                },
                qname_mtu: qname_mtu.max(0) as u32,
                pacing_gain_probe,
                dns_tcp_packet_loop_burst,
                // Anti-fingerprinting / pacing knobs: set from Kotlin via the nativeSet* setters
                // (called right before each native start); defaults preserve historical behavior.
                dns_query_type: DNS_QUERY_TYPE.load(Ordering::Relaxed),
                dns_label_length: DNS_LABEL_LENGTH.load(Ordering::Relaxed) as usize,
                max_poll_qps: MAX_POLL_QPS.load(Ordering::Relaxed),
                debug_poll,
                debug_streams,
                base64u_encoding: BASE64U_ENCODING.load(Ordering::Relaxed),
            };
            if let Err(err) = runtime.block_on(runtime::run_client_with_control(
                &config,
                Some(stop_rx),
                Some(ready_tx),
            )) {
                set_last_error(err.to_string());
            }
            thread_ready.store(false, Ordering::SeqCst);
            thread_running.store(false, Ordering::SeqCst);
        }) {
        Ok(thread) => thread,
        Err(err) => {
            set_last_error(format!("failed to spawn Slipstream probe thread: {}", err));
            return -10;
        }
    };
    let _ = started_rx.recv_timeout(Duration::from_secs(1));
    thread::sleep(Duration::from_millis(150));
    if !running_flag.load(Ordering::SeqCst) {
        let _ = thread.join();
        return -11;
    }

    let ready_watcher = Arc::clone(&ready_flag);
    thread::spawn(move || {
        while let Ok(ready) = ready_rx.recv() {
            ready_watcher.store(ready, Ordering::SeqCst);
        }
        ready_watcher.store(false, Ordering::SeqCst);
    });

    if let Ok(mut clients) = probe_clients_slot().lock() {
        clients.insert(
            listen_port_u16,
            ProbeClientHandle {
                stop_tx,
                thread,
                running: running_flag,
                ready: ready_flag,
            },
        );
        0
    } else {
        set_last_error("failed to lock Slipstream probe client state");
        -10
    }
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeStopSlipstreamClient(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
) {
    let _ = stop_running_client();
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeStopProbeClient(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
    listen_port: jint,
) {
    if (1..=u16::MAX as jint).contains(&listen_port) {
        let _ = stop_probe_client_by_port(listen_port as u16);
    } else {
        let _ = stop_all_probe_clients();
    }
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeIsClientRunning(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
) -> bool {
    RUNNING.load(Ordering::SeqCst)
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeIsProbeRunning(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
    listen_port: jint,
) -> bool {
    if let Ok(clients) = probe_clients_slot().lock() {
        if (1..=u16::MAX as jint).contains(&listen_port) {
            clients
                .get(&(listen_port as u16))
                .map(|client| client.running.load(Ordering::SeqCst))
                .unwrap_or(false)
        } else {
            clients
                .values()
                .any(|client| client.running.load(Ordering::SeqCst))
        }
    } else {
        false
    }
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeIsQuicReady(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
) -> bool {
    READY.load(Ordering::SeqCst)
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeIsProbeReady(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
    listen_port: jint,
) -> bool {
    if let Ok(clients) = probe_clients_slot().lock() {
        if (1..=u16::MAX as jint).contains(&listen_port) {
            clients
                .get(&(listen_port as u16))
                .map(|client| client.ready.load(Ordering::SeqCst))
                .unwrap_or(false)
        } else {
            clients
                .values()
                .any(|client| client.ready.load(Ordering::SeqCst))
        }
    } else {
        false
    }
}

#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeGetLastError(
    env: JNIEnv<'_>,
    _this: JObject<'_>,
) -> jstring {
    let message = last_error_slot()
        .lock()
        .ok()
        .and_then(|last_error| last_error.clone());
    match message {
        Some(message) => env
            .new_string(message)
            .map(|value| value.into_raw())
            .unwrap_or(ptr::null_mut()),
        None => ptr::null_mut(),
    }
}

// Send the stop signal and wait up to `timeout` for the thread to finish on its own; if it does,
// join it and return true. If not, the thread is left running (its socket/transport resources
// leak until process exit) and this returns false so the caller can log/report accordingly. This
// is the exact mechanism behind the incident where a slow-to-stop client got detached and then
// span forever pegging a CPU core: the timeout here doesn't prevent that on its own (that needed
// the shutdown-check fixes in runtime.rs's poll loop), it only decides whether this call gets to
// reclaim the thread's resources (like the local listen port) or has to give up and leak them.
fn join_or_detach(
    stop_tx: mpsc::UnboundedSender<()>,
    thread: JoinHandle<()>,
    timeout: Duration,
) -> bool {
    let _ = stop_tx.send(());
    let deadline = Instant::now() + timeout;
    while !thread.is_finished() && Instant::now() < deadline {
        thread::sleep(STOP_JOIN_POLL);
    }
    if thread.is_finished() {
        let _ = thread.join();
        true
    } else {
        false
    }
}

fn stop_running_client() -> Result<(), String> {
    stop_running_client_with_timeout(STOP_JOIN_TIMEOUT)
}

// Timeout is a parameter (rather than always using STOP_JOIN_TIMEOUT directly) purely so tests
// can exercise this function's real logic -- global RUNNING/READY/CLIENT_GENERATION handling
// included -- without waiting out the real 10s production timeout.
fn stop_running_client_with_timeout(timeout: Duration) -> Result<(), String> {
    let handle = client_slot()
        .lock()
        .map_err(|_| "failed to lock Slipstream client state".to_string())?
        .take();
    let generation = handle.as_ref().map(|handle| handle.generation);
    let was_current = generation.is_none_or(is_current_generation);
    if let Some(handle) = handle {
        // Invalidate this generation BEFORE joining so a thread that missed its mpsc stop signal
        // (busy-spinning) sees its generation is no longer current and self-terminates, letting the
        // join succeed instead of detaching into a 100%-CPU orphan. Only bump when this is still the
        // current generation, so a concurrently-started newer client isn't killed.
        if was_current {
            CLIENT_GENERATION.fetch_add(1, Ordering::SeqCst);
        }
        if !join_or_detach(handle.stop_tx, handle.thread, timeout) {
            tracing::error!(
                "Slipstream client stop timed out after {:?}; detaching native thread \
                 (its socket/transport resources will leak until the process exits)",
                timeout
            );
            set_last_error("Slipstream client stop timed out; detached native thread");
        }
    }
    if was_current {
        RUNNING.store(false, Ordering::SeqCst);
        READY.store(false, Ordering::SeqCst);
    }
    Ok(())
}

fn stop_probe_handle(handle: ProbeClientHandle, timeout: Duration) {
    if !join_or_detach(handle.stop_tx, handle.thread, timeout) {
        tracing::error!(
            "Slipstream probe client stop timed out after {:?}; detaching native thread \
             (its socket/transport resources will leak until the process exits)",
            timeout
        );
        set_last_error("Slipstream probe client stop timed out; detached native thread");
    }
    handle.running.store(false, Ordering::SeqCst);
    handle.ready.store(false, Ordering::SeqCst);
}

fn stop_probe_client_by_port(port: u16) -> Result<(), String> {
    let handle = probe_clients_slot()
        .lock()
        .map_err(|_| "failed to lock Slipstream probe client state".to_string())?
        .remove(&port);
    if let Some(handle) = handle {
        stop_probe_handle(handle, STOP_JOIN_TIMEOUT);
    }
    Ok(())
}

fn stop_all_probe_clients() -> Result<(), String> {
    let handles: Vec<ProbeClientHandle> = probe_clients_slot()
        .lock()
        .map_err(|_| "failed to lock Slipstream probe client state".to_string())?
        .drain()
        .map(|(_, handle)| handle)
        .collect();
    let per_client_timeout = Duration::from_secs(2);
    for handle in handles {
        stop_probe_handle(handle, per_client_timeout);
    }
    Ok(())
}

fn java_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Result<String, String> {
    env.get_string(value)
        .map(|value| value.into())
        .map_err(|err| err.to_string())
}

fn parse_resolver_transport(value: &str) -> ResolverTransport {
    if value.trim().eq_ignore_ascii_case("tcp") {
        ResolverTransport::Tcp
    } else {
        ResolverTransport::Udp
    }
}

fn read_resolvers(
    env: &mut JNIEnv<'_>,
    resolver_hosts: JObjectArray<'_>,
    resolver_ports: JIntArray<'_>,
    resolver_authoritative: JBooleanArray<'_>,
) -> Result<Vec<ResolverSpec>, String> {
    let len = env
        .get_array_length(&resolver_hosts)
        .map_err(|err| err.to_string())?;
    if len == 0
        || env
            .get_array_length(&resolver_ports)
            .map_err(|err| err.to_string())?
            != len
        || env
            .get_array_length(&resolver_authoritative)
            .map_err(|err| err.to_string())?
            != len
    {
        return Err("resolver arrays must be non-empty and have the same length".to_string());
    }

    let mut ports = vec![0; len as usize];
    env.get_int_array_region(&resolver_ports, 0, &mut ports)
        .map_err(|err| err.to_string())?;
    let mut authoritative = vec![0u8; len as usize];
    env.get_boolean_array_region(&resolver_authoritative, 0, &mut authoritative)
        .map_err(|err| err.to_string())?;

    let mut resolvers = Vec::with_capacity(len as usize);
    for index in 0..len {
        let host_obj = env
            .get_object_array_element(&resolver_hosts, index)
            .map_err(|err| err.to_string())?;
        let host = java_string(env, &JString::from(host_obj))?;
        let port = ports[index as usize];
        if !(1..=u16::MAX as jint).contains(&port) {
            return Err(format!("invalid resolver port at index {}", index));
        }
        let resolver = parse_host_port_parts(&host, port as u16, AddressKind::Resolver)
            .map_err(|err| err.to_string())?;
        let mode = if authoritative[index as usize] != 0 {
            ResolverMode::Authoritative
        } else {
            ResolverMode::Recursive
        };
        resolvers.push(ResolverSpec { resolver, mode });
    }
    Ok(resolvers)
}

#[cfg(test)]
mod tests {
    use super::*;

    // join_or_detach doesn't touch any global state (unlike stop_running_client, which owns the
    // process-wide CLIENT/RUNNING/READY statics) so it's safe to exercise directly and repeatedly.

    #[test]
    fn join_or_detach_joins_a_thread_that_honors_the_stop_signal() {
        let (stop_tx, mut stop_rx) = mpsc::unbounded_channel::<()>();
        let thread = thread::spawn(move || {
            let _ = stop_rx.blocking_recv();
        });
        let joined = join_or_detach(stop_tx, thread, Duration::from_secs(2));
        assert!(
            joined,
            "a thread that exits promptly on stop must be joined, not detached"
        );
    }

    #[test]
    fn join_or_detach_gives_up_and_detaches_a_stuck_thread() {
        // Mirrors the real incident: the thread never checks the stop signal and just keeps
        // running. join_or_detach must not block past `timeout` waiting for it.
        let (stop_tx, _stop_rx) = mpsc::unbounded_channel::<()>();
        let thread = thread::spawn(|| {
            thread::sleep(Duration::from_secs(5));
        });
        let started = Instant::now();
        let joined = join_or_detach(stop_tx, thread, Duration::from_millis(200));
        assert!(
            !joined,
            "a thread that ignores the stop signal must be reported as detached"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "must give up at ~timeout, not wait for the stuck thread: took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn stop_probe_handle_clears_state_on_a_clean_stop() {
        clear_last_error();
        let (stop_tx, mut stop_rx) = mpsc::unbounded_channel::<()>();
        let thread = thread::spawn(move || {
            let _ = stop_rx.blocking_recv();
        });
        let handle = ProbeClientHandle {
            stop_tx,
            thread,
            running: Arc::new(AtomicBool::new(true)),
            ready: Arc::new(AtomicBool::new(true)),
        };
        let running = handle.running.clone();
        let ready = handle.ready.clone();
        stop_probe_handle(handle, Duration::from_secs(2));

        assert!(!running.load(Ordering::SeqCst));
        assert!(!ready.load(Ordering::SeqCst));
        assert!(
            last_error_slot().lock().unwrap().is_none(),
            "a clean stop must not set an error"
        );
    }

    #[test]
    fn stop_probe_handle_reports_an_error_and_clears_state_on_timeout() {
        clear_last_error();
        let (stop_tx, _stop_rx) = mpsc::unbounded_channel::<()>();
        let thread = thread::spawn(|| {
            thread::sleep(Duration::from_secs(5));
        });
        let handle = ProbeClientHandle {
            stop_tx,
            thread,
            running: Arc::new(AtomicBool::new(true)),
            ready: Arc::new(AtomicBool::new(true)),
        };
        let running = handle.running.clone();
        let ready = handle.ready.clone();
        stop_probe_handle(handle, Duration::from_millis(200));

        // Even though the thread is left detached (leaked), the handle's own state must still
        // reflect "stopped" -- the caller (Kotlin) has already moved on and must not keep waiting
        // on a probe that will never report ready again.
        assert!(!running.load(Ordering::SeqCst));
        assert!(!ready.load(Ordering::SeqCst));
        let last_error = last_error_slot().lock().unwrap().clone();
        assert_eq!(
            last_error.as_deref(),
            Some("Slipstream probe client stop timed out; detached native thread")
        );
    }

    #[test]
    fn stop_running_client_reports_an_error_on_timeout_and_still_clears_running() {
        // This is the exact end-to-end path behind the original incident: stop_running_client
        // gives up on a stuck client thread, and RUNNING must still flip false so the app doesn't
        // think a (now-leaked) client is still usable.
        clear_last_error();
        RUNNING.store(true, Ordering::SeqCst);
        READY.store(true, Ordering::SeqCst);
        let generation = CLIENT_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;

        let (stop_tx, _stop_rx) = mpsc::unbounded_channel::<()>();
        let thread = thread::spawn(|| {
            thread::sleep(Duration::from_secs(5)); // ignores the stop signal
        });
        *client_slot().lock().unwrap() = Some(ClientHandle {
            stop_tx,
            thread,
            generation,
        });

        // A short timeout here (real callers always use STOP_JOIN_TIMEOUT) keeps this test fast
        // while still exercising stop_running_client's real RUNNING/READY/generation handling.
        stop_running_client_with_timeout(Duration::from_millis(200)).unwrap();

        assert!(!RUNNING.load(Ordering::SeqCst));
        assert!(!READY.load(Ordering::SeqCst));
        let last_error = last_error_slot().lock().unwrap().clone();
        assert_eq!(
            last_error.as_deref(),
            Some("Slipstream client stop timed out; detached native thread")
        );
    }
}
