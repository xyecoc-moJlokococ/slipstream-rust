//! Linux `recvmmsg`/`sendmmsg` batching for the UDP DNS-tunnel hot path.
//!
//! The stock loop did one `recv_from`/`send_to` syscall per datagram. Under a real
//! DNS-tunnel load this is a firehose of tiny datagrams (recursive resolvers relay each
//! query from a fresh source port), so per-datagram syscall overhead dominates CPU —
//! this is the single biggest lever on UDP-vs-TCP server CPU cost. Batching many
//! datagrams into one `recvmmsg`/`sendmmsg` call cuts that per-datagram syscall count
//! directly. GRO/GSO were deliberately left out: both require multiple datagrams
//! to/from the *same* peer to coalesce/segment, which doesn't hold here (every query can
//! come from a different relayed source port) — recvmmsg/sendmmsg's win doesn't depend
//! on that and applies regardless of how scattered the peers are.
//!
//! Linux-only (recvmmsg/sendmmsg are Linux syscalls); non-Linux builds keep the plain
//! per-packet path in `server.rs`.

use slipstream_core::net::is_transient_udp_error;
use slipstream_ffi::{sockaddr_storage_to_socket_addr, socket_addr_to_storage};
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Pre-allocated buffers for a batch of `recvmmsg` calls, reused for the life of the
/// server loop. The `iovec`/`mmsghdr` arrays hold raw pointers into `bufs`/`names`, so
/// those backing `Vec`s must never be reallocated after construction (no push/resize).
pub(crate) struct RecvMmsgBatch {
    bufs: Vec<Box<[u8]>>,
    #[allow(dead_code)]
    iovecs: Vec<libc::iovec>,
    names: Vec<libc::sockaddr_storage>,
    msgs: Vec<libc::mmsghdr>,
}

// SAFETY: the raw pointers stored in `iovecs`/`msgs` only ever point into `bufs`/`names`,
// which live as long as the `RecvMmsgBatch` itself and are never moved (no reallocation
// after `new()`), so moving/sharing the struct across an await point (single-threaded
// runtime, never actually sent to another OS thread) is sound.
unsafe impl Send for RecvMmsgBatch {}

impl RecvMmsgBatch {
    pub(crate) fn new(batch_len: usize, datagram_cap: usize) -> Self {
        assert!(batch_len > 0, "recvmmsg batch must be non-empty");
        let mut bufs: Vec<Box<[u8]>> = (0..batch_len)
            .map(|_| vec![0u8; datagram_cap].into_boxed_slice())
            .collect();
        let mut iovecs: Vec<libc::iovec> = bufs
            .iter_mut()
            .map(|buf| libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            })
            .collect();
        let mut names: Vec<libc::sockaddr_storage> = (0..batch_len)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();
        let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(batch_len);
        for i in 0..batch_len {
            let mut msg_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            msg_hdr.msg_name = &mut names[i] as *mut libc::sockaddr_storage as *mut libc::c_void;
            msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg_hdr.msg_iov = &mut iovecs[i] as *mut libc::iovec;
            msg_hdr.msg_iovlen = 1;
            msgs.push(libc::mmsghdr {
                msg_hdr,
                msg_len: 0,
            });
        }
        Self {
            bufs,
            iovecs,
            names,
            msgs,
        }
    }

    /// One non-blocking `recvmmsg` syscall. Must only be invoked via `UdpSocket::try_io`
    /// while the socket has been confirmed readable (tokio's raw-fd I/O contract).
    fn recv_once(&mut self, fd: RawFd) -> io::Result<usize> {
        for msg in self.msgs.iter_mut() {
            msg.msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        }
        let n = unsafe {
            libc::recvmmsg(
                fd,
                self.msgs.as_mut_ptr(),
                self.msgs.len() as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// The datagram at `index` from the most recent successful `recv_once`/`recv_ready` call.
    pub(crate) fn datagram(&self, index: usize) -> (&[u8], SocketAddr) {
        let len = (self.msgs[index].msg_len as usize).min(self.bufs[index].len());
        let addr = sockaddr_storage_to_socket_addr(&self.names[index])
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        (&self.bufs[index][..len], addr)
    }
}

/// Waits for the socket to be readable, then does one batched `recvmmsg` call and
/// returns how many datagrams landed (0..=batch capacity). Mirrors the old single
/// `recv_from().await`, just filling many slots per syscall instead of one.
pub(crate) async fn recv_ready(socket: &UdpSocket, batch: &mut RecvMmsgBatch) -> io::Result<usize> {
    loop {
        socket.readable().await?;
        match socket.try_io(Interest::READABLE, || batch.recv_once(socket.as_raw_fd())) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Sends every `(datagram, destination)` pair in one or more batched `sendmmsg` calls.
/// A destination-specific transient failure (e.g. a rejected/unreachable send) only
/// drops that one datagram — matches the old per-datagram `send_to` error handling,
/// which likewise logged/ignored a single transient error instead of aborting the batch.
pub(crate) async fn send_batch(
    socket: &UdpSocket,
    entries: &mut [(Vec<u8>, SocketAddr)],
) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let names: Vec<libc::sockaddr_storage> = entries
        .iter()
        .map(|(_, addr)| socket_addr_to_storage(*addr))
        .collect();
    let mut iovecs: Vec<libc::iovec> = entries
        .iter_mut()
        .map(|(buf, _)| libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        })
        .collect();
    let mut msgs: Vec<libc::mmsghdr> = (0..entries.len())
        .map(|i| {
            let mut msg_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            msg_hdr.msg_name = &names[i] as *const libc::sockaddr_storage as *mut libc::c_void;
            msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg_hdr.msg_iov = &mut iovecs[i] as *mut libc::iovec;
            msg_hdr.msg_iovlen = 1;
            libc::mmsghdr {
                msg_hdr,
                msg_len: 0,
            }
        })
        .collect();

    let fd = socket.as_raw_fd();
    let mut sent = 0usize;
    while sent < msgs.len() {
        socket.writable().await?;
        let remaining = &mut msgs[sent..];
        match socket.try_io(Interest::WRITABLE, || {
            let n = unsafe {
                libc::sendmmsg(
                    fd,
                    remaining.as_mut_ptr(),
                    remaining.len() as libc::c_uint,
                    0,
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(0) => break,
            Ok(n) => sent += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if is_transient_udp_error(&e) => {
                // sendmmsg stops at the first failing message in the batch; skip just
                // that one destination and resume the rest from the next slot.
                sent += 1;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
