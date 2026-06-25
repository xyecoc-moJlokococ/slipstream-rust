use crate::streams::{acceptor::ClientAcceptor, Command, DownstreamStream};
use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tracing::{debug, info, warn};

const MAX_PACKET_SIZE: usize = 65_535;
const MAX_TCP_PAYLOAD: usize = 1460;
const DUPLEX_BUFFER_BYTES: usize = 512 * 1024;

static FLOW_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) struct TunEngine {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for TunEngine {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn start_tun_engine(
    tun_fd: i32,
    dns_server: &str,
    command_tx: mpsc::UnboundedSender<Command>,
    acceptor: ClientAcceptor,
    debug_streams: bool,
) -> io::Result<TunEngine> {
    let read_fd = dup_nonblocking(tun_fd)?;
    let write_fd = dup_nonblocking(tun_fd)?;
    let mut read_file = unsafe { File::from_raw_fd(read_fd) };
    let write_file = Arc::new(Mutex::new(unsafe { File::from_raw_fd(write_fd) }));
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread_write = Arc::clone(&write_file);
    let dns_server = dns_server
        .parse::<Ipv4Addr>()
        .unwrap_or_else(|_| Ipv4Addr::new(8, 8, 8, 8));
    let (cleanup_tx, cleanup_rx) = std_mpsc::channel::<FlowKey>();

    let thread = thread::Builder::new()
        .name("slipstream-tun".to_string())
        .spawn(move || {
            info!("native TUN packet engine started dns_server={}", dns_server);
            let mut flows: HashMap<FlowKey, FlowHandle> = HashMap::new();
            let mut packet = vec![0u8; MAX_PACKET_SIZE];
            while !thread_stop.load(Ordering::SeqCst) {
                while let Ok(key) = cleanup_rx.try_recv() {
                    flows.remove(&key);
                }
                match read_file.read(&mut packet) {
                    Ok(0) => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Ok(n) => {
                        if let Some(parsed) = parse_ipv4_tcp(&packet[..n]) {
                            handle_tcp_packet(
                                parsed,
                                &mut flows,
                                Arc::clone(&thread_write),
                                command_tx.clone(),
                                acceptor.clone(),
                                cleanup_tx.clone(),
                                debug_streams,
                            );
                        } else if let Some(parsed) = parse_ipv4_udp(&packet[..n]) {
                            if parsed.dst_port == 53 {
                                spawn_dns_query(
                                    parsed,
                                    dns_server,
                                    Arc::clone(&thread_write),
                                    command_tx.clone(),
                                    acceptor.clone(),
                                    debug_streams,
                                );
                            }
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => {
                        warn!("native TUN read failed: {}", err);
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
            for (_, flow) in flows.drain() {
                let _ = flow.tx.send(FlowEvent::Reset);
            }
            info!("native TUN packet engine stopped");
        })?;

    Ok(TunEngine {
        stop,
        thread: Some(thread),
    })
}

fn dup_nonblocking(fd: i32) -> io::Result<i32> {
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = unsafe { fcntl(dup_fd, F_GETFL) };
    if flags < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(dup_fd) };
        return Err(err);
    }
    if unsafe { fcntl(dup_fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(dup_fd) };
        return Err(err);
    }
    Ok(dup_fd)
}

fn handle_tcp_packet(
    packet: TcpPacket,
    flows: &mut HashMap<FlowKey, FlowHandle>,
    tun_writer: Arc<Mutex<File>>,
    command_tx: mpsc::UnboundedSender<Command>,
    acceptor: ClientAcceptor,
    cleanup_tx: std_mpsc::Sender<FlowKey>,
    debug_streams: bool,
) {
    let key = packet.key;
    if packet.syn && !packet.ack {
        if let Some(flow) = flows.get(&key) {
            send_syn_ack(&tun_writer, &key, flow.server_isn, packet.seq.wrapping_add(1));
            return;
        }
        let server_isn = initial_seq();
        let flow = spawn_flow(
            key,
            packet.seq,
            server_isn,
            Arc::clone(&tun_writer),
            command_tx,
            acceptor,
            cleanup_tx,
            debug_streams,
        );
        send_syn_ack(&tun_writer, &key, server_isn, packet.seq.wrapping_add(1));
        flows.insert(key, flow);
        return;
    }

    let Some(flow) = flows.get(&key) else {
        return;
    };

    if !packet.payload.is_empty() {
        let _ = flow.tx.send(FlowEvent::Data {
            seq: packet.seq,
            data: packet.payload,
        });
    }
    if packet.fin {
        let _ = flow.tx.send(FlowEvent::Fin { seq: packet.seq });
    }
    if packet.rst {
        let _ = flow.tx.send(FlowEvent::Reset);
        flows.remove(&key);
    }
}

fn spawn_flow(
    key: FlowKey,
    client_isn: u32,
    server_isn: u32,
    tun_writer: Arc<Mutex<File>>,
    command_tx: mpsc::UnboundedSender<Command>,
    acceptor: ClientAcceptor,
    cleanup_tx: std_mpsc::Sender<FlowKey>,
    debug_streams: bool,
) -> FlowHandle {
    let (tx, rx) = mpsc::unbounded_channel();
    let flow_id = FLOW_ID.fetch_add(1, Ordering::SeqCst);
    let handle = FlowHandle { tx, server_isn };
    tokio::spawn(run_flow(
        flow_id,
        key,
        client_isn,
        server_isn,
        rx,
        tun_writer,
        command_tx,
        acceptor,
        cleanup_tx,
        debug_streams,
    ));
    handle
}

#[allow(clippy::too_many_arguments)]
async fn run_flow(
    flow_id: u64,
    key: FlowKey,
    client_isn: u32,
    server_isn: u32,
    mut rx: mpsc::UnboundedReceiver<FlowEvent>,
    tun_writer: Arc<Mutex<File>>,
    command_tx: mpsc::UnboundedSender<Command>,
    acceptor: ClientAcceptor,
    cleanup_tx: std_mpsc::Sender<FlowKey>,
    debug_streams: bool,
) {
    let _cleanup = FlowCleanup { key, tx: cleanup_tx };
    if debug_streams {
        debug!(
            "native TUN flow {} {}:{} -> {}:{}",
            flow_id, key.src, key.src_port, key.dst, key.dst_port
        );
    }

    let (mut app_to_core_write, app_to_core_read) = duplex(DUPLEX_BUFFER_BYTES);
    let (core_to_app_write, mut core_to_app_read) = duplex(DUPLEX_BUFFER_BYTES);
    let downstream = DownstreamStream::from_halves(
        Box::new(app_to_core_read),
        Box::new(core_to_app_write),
        Some(256 * 1024),
    );

    let reservation = acceptor.reserve().await;
    if command_tx
        .send(Command::NewStream {
            stream: downstream,
            reservation,
        })
        .is_err()
    {
        send_rst(&tun_writer, &key, server_isn, client_isn.wrapping_add(1));
        return;
    }

    let (connected_tx, mut connected_rx) = oneshot::channel::<bool>();
    let response_tun = Arc::clone(&tun_writer);
    tokio::spawn(async move {
        read_downstream_to_tun(
            flow_id,
            key,
            client_isn,
            server_isn,
            &mut core_to_app_read,
            response_tun,
            connected_tx,
            debug_streams,
        )
        .await;
    });

    if write_socks_preface(&mut app_to_core_write, key.dst, key.dst_port)
        .await
        .is_err()
    {
        send_rst(&tun_writer, &key, server_isn, client_isn.wrapping_add(1));
        return;
    }

    let mut client_next = client_isn.wrapping_add(1);
    let mut connected = false;
    let mut pending = Vec::<Vec<u8>>::new();
    loop {
        tokio::select! {
            connected_result = &mut connected_rx, if !connected => {
                connected = connected_result.unwrap_or(false);
                if !connected {
                    send_rst(&tun_writer, &key, server_isn, client_next);
                    return;
                }
                for data in pending.drain(..) {
                    if app_to_core_write.write_all(&data).await.is_err() {
                        send_rst(&tun_writer, &key, server_isn, client_next);
                        return;
                    }
                }
                let _ = app_to_core_write.flush().await;
            }
            event = rx.recv() => {
                match event {
                    Some(FlowEvent::Data { seq, data }) => {
                        let end = seq.wrapping_add(data.len() as u32);
                        if seq == client_next || end.wrapping_gt(client_next) {
                            client_next = end;
                        }
                        send_ack(&tun_writer, &key, server_isn.wrapping_add(1), client_next);
                        if connected {
                            if app_to_core_write.write_all(&data).await.is_err() {
                                send_rst(&tun_writer, &key, server_isn, client_next);
                                return;
                            }
                            let _ = app_to_core_write.flush().await;
                        } else {
                            pending.push(data);
                        }
                    }
                    Some(FlowEvent::Fin { seq }) => {
                        if seq.wrapping_add(1).wrapping_gt(client_next) {
                            client_next = seq.wrapping_add(1);
                        }
                        send_ack(&tun_writer, &key, server_isn.wrapping_add(1), client_next);
                        let _ = app_to_core_write.shutdown().await;
                        return;
                    }
                    Some(FlowEvent::Reset) | None => {
                        return;
                    }
                }
            }
        }
    }
}

async fn write_socks_preface<W>(
    writer: &mut W,
    dst: Ipv4Addr,
    dst_port: u16,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&[0x05, 0x01, 0x00]).await?;
    let octets = dst.octets();
    let mut connect = [0u8; 10];
    connect[0] = 0x05;
    connect[1] = 0x01;
    connect[2] = 0x00;
    connect[3] = 0x01;
    connect[4..8].copy_from_slice(&octets);
    connect[8..10].copy_from_slice(&dst_port.to_be_bytes());
    writer.write_all(&connect).await?;
    writer.flush().await
}

async fn read_downstream_to_tun(
    flow_id: u64,
    key: FlowKey,
    client_isn: u32,
    server_isn: u32,
    reader: &mut tokio::io::DuplexStream,
    tun_writer: Arc<Mutex<File>>,
    connected_tx: oneshot::Sender<bool>,
    debug_streams: bool,
) {
    let mut connected_tx = Some(connected_tx);
    let client_next = client_isn.wrapping_add(1);
    if read_socks_response(reader).await.is_err() {
        if let Some(tx) = connected_tx.take() {
            let _ = tx.send(false);
        }
        send_rst(&tun_writer, &key, server_isn, client_next);
        return;
    }
    if let Some(tx) = connected_tx.take() {
        let _ = tx.send(true);
    }

    let mut server_next = server_isn.wrapping_add(1);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                send_fin_ack(&tun_writer, &key, server_next, client_next);
                return;
            }
            Ok(n) => {
                if debug_streams {
                    debug!("native TUN flow {} downstream {} bytes", flow_id, n);
                }
                for chunk in buf[..n].chunks(MAX_TCP_PAYLOAD) {
                    send_data(&tun_writer, &key, server_next, client_next, chunk);
                    server_next = server_next.wrapping_add(chunk.len() as u32);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                send_rst(&tun_writer, &key, server_next, client_next);
                return;
            }
        }
    }
}

async fn read_socks_response<R>(reader: &mut R) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut auth = [0u8; 2];
    reader.read_exact(&mut auth).await?;
    if auth != [0x05, 0x00] {
        return Err(io::Error::new(io::ErrorKind::Other, "SOCKS auth rejected"));
    }

    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("SOCKS connect failed status={}", header[1]),
        ));
    }
    let remaining = match header[3] {
        0x01 => 6,
        0x04 => 18,
        0x03 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        _ => return Err(io::Error::new(io::ErrorKind::Other, "bad SOCKS address type")),
    };
    let mut discard = vec![0u8; remaining];
    reader.read_exact(&mut discard).await?;
    Ok(())
}

fn send_syn_ack(writer: &Arc<Mutex<File>>, key: &FlowKey, seq: u32, ack: u32) {
    send_tcp_packet(writer, key, seq, ack, TCP_SYN | TCP_ACK, &[]);
}

fn send_ack(writer: &Arc<Mutex<File>>, key: &FlowKey, seq: u32, ack: u32) {
    send_tcp_packet(writer, key, seq, ack, TCP_ACK, &[]);
}

fn send_data(writer: &Arc<Mutex<File>>, key: &FlowKey, seq: u32, ack: u32, payload: &[u8]) {
    send_tcp_packet(writer, key, seq, ack, TCP_ACK | TCP_PSH, payload);
}

fn send_fin_ack(writer: &Arc<Mutex<File>>, key: &FlowKey, seq: u32, ack: u32) {
    send_tcp_packet(writer, key, seq, ack, TCP_FIN | TCP_ACK, &[]);
}

fn send_rst(writer: &Arc<Mutex<File>>, key: &FlowKey, seq: u32, ack: u32) {
    send_tcp_packet(writer, key, seq, ack, TCP_RST | TCP_ACK, &[]);
}

fn send_tcp_packet(
    writer: &Arc<Mutex<File>>,
    key: &FlowKey,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) {
    let packet = build_tcp_packet(key.dst, key.dst_port, key.src, key.src_port, seq, ack, flags, payload);
    if let Ok(mut writer) = writer.lock() {
        if let Err(err) = writer.write_all(&packet) {
            warn!("native TUN write failed: {}", err);
        }
    }
}

fn spawn_dns_query(
    packet: UdpPacket,
    dns_server: Ipv4Addr,
    tun_writer: Arc<Mutex<File>>,
    command_tx: mpsc::UnboundedSender<Command>,
    acceptor: ClientAcceptor,
    debug_streams: bool,
) {
    tokio::spawn(async move {
        if packet.payload.is_empty() {
            return;
        }
        match run_dns_query(
            packet.payload,
            dns_server,
            command_tx,
            acceptor,
            debug_streams,
        )
        .await
        {
            Ok(response) => {
                let response_packet = build_udp_packet(
                    packet.dst,
                    packet.dst_port,
                    packet.src,
                    packet.src_port,
                    &response,
                );
                write_tun_packet(&tun_writer, &response_packet);
            }
            Err(err) => {
                if debug_streams {
                    debug!(
                        "native TUN DNS {}:{} -> {} failed: {}",
                        packet.src, packet.src_port, dns_server, err
                    );
                }
            }
        }
    });
}

async fn run_dns_query(
    query: Vec<u8>,
    dns_server: Ipv4Addr,
    command_tx: mpsc::UnboundedSender<Command>,
    acceptor: ClientAcceptor,
    debug_streams: bool,
) -> io::Result<Vec<u8>> {
    timeout(Duration::from_secs(5), async move {
        let (mut app_to_core_write, app_to_core_read) = duplex(64 * 1024);
        let (core_to_app_write, mut core_to_app_read) = duplex(64 * 1024);
        let downstream = DownstreamStream::from_halves(
            Box::new(app_to_core_read),
            Box::new(core_to_app_write),
            Some(64 * 1024),
        );
        let reservation = acceptor.reserve().await;
        command_tx
            .send(Command::NewStream {
                stream: downstream,
                reservation,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Slipstream command closed"))?;

        write_socks_preface(&mut app_to_core_write, dns_server, 53).await?;
        read_socks_response(&mut core_to_app_read).await?;

        let len = query.len();
        if len > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "DNS query too large"));
        }
        app_to_core_write
            .write_all(&(len as u16).to_be_bytes())
            .await?;
        app_to_core_write.write_all(&query).await?;
        app_to_core_write.flush().await?;

        let mut len_buf = [0u8; 2];
        core_to_app_read.read_exact(&mut len_buf).await?;
        let response_len = u16::from_be_bytes(len_buf) as usize;
        if response_len == 0 || response_len > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad DNS response length {}", response_len),
            ));
        }
        let mut response = vec![0u8; response_len];
        core_to_app_read.read_exact(&mut response).await?;
        if debug_streams {
            debug!(
                "native TUN DNS-over-Slipstream query={} response={} server={}",
                len, response_len, dns_server
            );
        }
        Ok(response)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS-over-Slipstream timeout"))?
}

fn write_tun_packet(writer: &Arc<Mutex<File>>, packet: &[u8]) {
    if let Ok(mut writer) = writer.lock() {
        if let Err(err) = writer.write_all(packet) {
            warn!("native TUN write failed: {}", err);
        }
    }
}

fn build_tcp_packet(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let ip_len = 20usize;
    let tcp_len = 20usize;
    let total_len = ip_len + tcp_len + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let ip_sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let tcp = 20;
    packet[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    packet[tcp + 8..tcp + 12].copy_from_slice(&ack.to_be_bytes());
    packet[tcp + 12] = 5u8 << 4;
    packet[tcp + 13] = flags;
    packet[tcp + 14..tcp + 16].copy_from_slice(&65535u16.to_be_bytes());
    packet[tcp + 20..].copy_from_slice(payload);
    let tcp_sum = tcp_checksum(src, dst, &packet[tcp..]);
    packet[tcp + 16..tcp + 18].copy_from_slice(&tcp_sum.to_be_bytes());
    packet
}

fn build_udp_packet(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ip_len = 20usize;
    let udp_len = 8usize;
    let total_len = ip_len + udp_len + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let ip_sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let udp = 20;
    packet[udp..udp + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[udp + 2..udp + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[udp + 4..udp + 6].copy_from_slice(&((udp_len + payload.len()) as u16).to_be_bytes());
    packet[udp + 8..].copy_from_slice(payload);
    let udp_sum = udp_checksum(src, dst, &packet[udp..]);
    packet[udp + 6..udp + 8].copy_from_slice(&udp_sum.to_be_bytes());
    packet
}

fn parse_ipv4_tcp(packet: &[u8]) -> Option<TcpPacket> {
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 20 {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let total_len = total_len.min(packet.len());
    let tcp = ihl;
    let data_offset = ((packet[tcp + 12] >> 4) as usize) * 4;
    if data_offset < 20 || total_len < tcp + data_offset {
        return None;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let src_port = u16::from_be_bytes([packet[tcp], packet[tcp + 1]]);
    let dst_port = u16::from_be_bytes([packet[tcp + 2], packet[tcp + 3]]);
    let seq = u32::from_be_bytes([packet[tcp + 4], packet[tcp + 5], packet[tcp + 6], packet[tcp + 7]]);
    let ack_num = u32::from_be_bytes([packet[tcp + 8], packet[tcp + 9], packet[tcp + 10], packet[tcp + 11]]);
    let flags = packet[tcp + 13];
    let payload = packet[tcp + data_offset..total_len].to_vec();
    Some(TcpPacket {
        key: FlowKey {
            src,
            src_port,
            dst,
            dst_port,
        },
        seq,
        ack_num,
        syn: flags & TCP_SYN != 0,
        ack: flags & TCP_ACK != 0,
        fin: flags & TCP_FIN != 0,
        rst: flags & TCP_RST != 0,
        payload,
    })
}

fn parse_ipv4_udp(packet: &[u8]) -> Option<UdpPacket> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let total_len = total_len.min(packet.len());
    if total_len < ihl + 8 {
        return None;
    }
    let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
    if udp_len < 8 || total_len < ihl + udp_len {
        return None;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    let payload_end = ihl + udp_len;
    Some(UdpPacket {
        src,
        src_port,
        dst,
        dst_port,
        payload: packet[ihl + 8..payload_end].to_vec(),
    })
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum = sum.wrapping_add((byte as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    checksum(&pseudo)
}

fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp_datagram: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_datagram.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_datagram.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_datagram);
    let sum = checksum(&pseudo);
    if sum == 0 { 0xffff } else { sum }
}

fn initial_seq() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.subsec_nanos())
        .unwrap_or(0);
    nanos ^ (FLOW_ID.load(Ordering::SeqCst) as u32).wrapping_mul(1103515245)
}

trait WrappingGt {
    fn wrapping_gt(self, other: Self) -> bool;
}

impl WrappingGt for u32 {
    fn wrapping_gt(self, other: Self) -> bool {
        self != other && self.wrapping_sub(other) < 0x8000_0000
    }
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
}

#[derive(Clone)]
struct FlowHandle {
    tx: mpsc::UnboundedSender<FlowEvent>,
    server_isn: u32,
}

struct FlowCleanup {
    key: FlowKey,
    tx: std_mpsc::Sender<FlowKey>,
}

impl Drop for FlowCleanup {
    fn drop(&mut self) {
        let _ = self.tx.send(self.key);
    }
}

enum FlowEvent {
    Data { seq: u32, data: Vec<u8> },
    Fin { seq: u32 },
    Reset,
}

struct TcpPacket {
    key: FlowKey,
    seq: u32,
    #[allow(dead_code)]
    ack_num: u32,
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    payload: Vec<u8>,
}

struct UdpPacket {
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    payload: Vec<u8>,
}
