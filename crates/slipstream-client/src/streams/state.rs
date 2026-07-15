use super::acceptor;
use super::io_tasks::StreamWrite;
use slipstream_core::flow_control::{FlowControlState, HasFlowControlState};
use slipstream_ffi::picoquic::{picoquic_cnx_t, slipstream_get_stream_send_debug};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, info};

pub(super) const DEFAULT_TCP_RCVBUF_BYTES: usize = 256 * 1024;
pub(super) const CLIENT_WRITE_COALESCE_DEFAULT_BYTES: usize = 256 * 1024;
/// After the local SOCKS peer FINs (TCP read EOF), the write half is kept open so a slow QUIC
/// download can still finish. On a degraded DNS carrier the remote FIN may never arrive, so the
/// accepted TCP socket stays in CLOSE-WAIT forever (field: 100+ fds on :1081 with empty queues).
/// Cap that wait; aligned with the Java bridge HALF_MAX_MS.
pub(crate) const TCP_HALF_CLOSED_MAX_US: u64 = 45_000_000;

pub(crate) struct ClientState {
    pub(super) ready: bool,
    pub(super) closing: bool,
    pub(super) connection_generation: usize,
    pub(super) streams: HashMap<u64, ClientStream>,
    pub(super) multi_stream_mode: bool,
    pub(super) command_tx: mpsc::UnboundedSender<Command>,
    pub(super) data_notify: Arc<Notify>,
    pub(super) path_events: Vec<PathEvent>,
    pub(super) debug_streams: bool,
    pub(super) acceptor: acceptor::ClientAcceptor,
    pub(super) debug_enqueued_bytes: u64,
    pub(super) debug_last_enqueue_at: u64,
    pub(super) acceptor_limit_logged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamSendState {
    Open,
    Closing,
    FinQueued,
}

impl StreamSendState {
    pub(super) fn is_closed(self) -> bool {
        matches!(self, StreamSendState::FinQueued)
    }

    pub(super) fn can_queue_fin(self) -> bool {
        matches!(self, StreamSendState::Open | StreamSendState::Closing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamRecvState {
    Open,
    FinReceived,
}

impl StreamRecvState {
    pub(super) fn is_closed(self) -> bool {
        matches!(self, StreamRecvState::FinReceived)
    }
}

#[derive(Default)]
pub(crate) struct ClientStreamMetrics {
    pub(crate) streams_with_rx_queued: usize,
    pub(crate) queued_bytes_total: u64,
    pub(crate) streams_with_recv_fin: usize,
    pub(crate) streams_with_send_fin: usize,
    pub(crate) streams_discarding: usize,
    pub(crate) streams_with_unconsumed_rx: usize,
    pub(crate) streams_with_data_rx_queued: usize,
    pub(crate) data_rx_queued_chunks_total: u64,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct ClientBacklogSummary {
    pub(crate) stream_id: u64,
    pub(crate) queued_bytes: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) consumed_offset: u64,
    pub(crate) fin_offset: Option<u64>,
    pub(crate) recv_state: StreamRecvState,
    pub(crate) send_state: StreamSendState,
    pub(crate) stop_sending_sent: bool,
    pub(crate) discarding: bool,
    pub(crate) has_data_rx: bool,
    pub(crate) data_rx_len: usize,
    pub(crate) tx_bytes: u64,
    /// How much picoquic has actually put on the wire for this stream (vs `tx_bytes`, the
    /// cumulative amount we've handed to picoquic_add_to_stream) -- the gap is data queued
    /// inside picoquic itself, stuck behind this stream's own flow control. None if the
    /// stream/connection lookup failed (e.g. connection already torn down).
    pub(crate) send_sent_offset: Option<u64>,
    /// This stream's own send-side flow control ceiling (picoquic's `maxdata_remote` for the
    /// stream): once `send_sent_offset` reaches this, the stream can't send more until the
    /// peer grants a higher window via MAX_STREAM_DATA.
    pub(crate) send_maxdata_remote: Option<u64>,
}

impl ClientState {
    pub(crate) fn new(
        command_tx: mpsc::UnboundedSender<Command>,
        data_notify: Arc<Notify>,
        debug_streams: bool,
        acceptor: acceptor::ClientAcceptor,
    ) -> Self {
        Self {
            ready: false,
            closing: false,
            connection_generation: 0,
            streams: HashMap::new(),
            multi_stream_mode: false,
            command_tx,
            data_notify,
            path_events: Vec::new(),
            debug_streams,
            acceptor,
            debug_enqueued_bytes: 0,
            debug_last_enqueue_at: 0,
            acceptor_limit_logged: false,
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.ready
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.closing
    }

    pub(crate) fn streams_len(&self) -> usize {
        self.streams.len()
    }

    pub(crate) fn update_acceptor_limit(&mut self, cnx: *mut picoquic_cnx_t) {
        let max_streams = self.acceptor.update_limit(cnx);
        if !self.acceptor_limit_logged && max_streams > 0 {
            self.acceptor_limit_logged = true;
            info!("acceptor: initial_max_streams_bidir_remote={}", max_streams);
        }
    }

    pub(crate) fn debug_snapshot(&self) -> (u64, u64) {
        (self.debug_enqueued_bytes, self.debug_last_enqueue_at)
    }

    pub(super) fn remove_stream(&mut self, stream_id: u64) -> Option<ClientStream> {
        let mut removed = self.streams.remove(&stream_id)?;
        // Release the accepted TCP socket promptly: abort the reader and FIN the writer so the
        // kernel leaves CLOSE-WAIT instead of holding the fd until task drop races settle.
        if let Some(read_abort_tx) = removed.read_abort_tx.take() {
            let _ = read_abort_tx.send(());
        }
        let _ = removed.write_tx.send(StreamWrite::Fin);
        if self.streams.is_empty() && self.multi_stream_mode {
            self.multi_stream_mode = false;
            if self.debug_streams {
                debug!("stream {}: leaving multi-stream mode", stream_id);
            }
        }
        Some(removed)
    }

    /// Streams whose local SOCKS peer already FINed but whose QUIC half is still open past
    /// [TCP_HALF_CLOSED_MAX_US]. Returns their ids for the caller to abort+remove.
    pub(crate) fn stale_half_closed_tcp_streams(&self, now_us: u64, max_us: u64) -> Vec<u64> {
        self.streams
            .iter()
            .filter_map(|(stream_id, stream)| {
                let eof_at = stream.tcp_local_eof_at_us?;
                if now_us.saturating_sub(eof_at) >= max_us {
                    Some(*stream_id)
                } else {
                    None
                }
            })
            .collect()
    }

    pub(crate) fn stream_debug_metrics(&self) -> ClientStreamMetrics {
        let mut metrics = ClientStreamMetrics::default();
        for stream in self.streams.values() {
            let queued = stream.flow.queued_bytes as u64;
            let unconsumed = stream
                .flow
                .rx_bytes
                .saturating_sub(stream.flow.consumed_offset);
            metrics.queued_bytes_total = metrics.queued_bytes_total.saturating_add(queued);
            if queued > 0 {
                metrics.streams_with_rx_queued = metrics.streams_with_rx_queued.saturating_add(1);
            }
            if stream.recv_state == StreamRecvState::FinReceived {
                metrics.streams_with_recv_fin = metrics.streams_with_recv_fin.saturating_add(1);
            }
            if stream.send_state == StreamSendState::FinQueued {
                metrics.streams_with_send_fin = metrics.streams_with_send_fin.saturating_add(1);
            }
            if stream.flow.discarding {
                metrics.streams_discarding = metrics.streams_discarding.saturating_add(1);
            }
            if unconsumed > 0 {
                metrics.streams_with_unconsumed_rx =
                    metrics.streams_with_unconsumed_rx.saturating_add(1);
            }
            if let Some(data_rx) = &stream.data_rx {
                let data_rx_len = data_rx.len();
                if data_rx_len > 0 {
                    metrics.streams_with_data_rx_queued =
                        metrics.streams_with_data_rx_queued.saturating_add(1);
                    metrics.data_rx_queued_chunks_total = metrics
                        .data_rx_queued_chunks_total
                        .saturating_add(data_rx_len as u64);
                }
            }
        }
        metrics
    }

    /// # Safety
    /// `cnx` must be a valid picoquic connection (or null) matching the connection these
    /// streams belong to.
    pub(crate) unsafe fn stream_backlog_summaries(
        &self,
        cnx: *mut picoquic_cnx_t,
        limit: usize,
    ) -> Vec<ClientBacklogSummary> {
        let mut summaries = Vec::new();
        for (stream_id, stream) in self.streams.iter() {
            let queued_bytes = stream.flow.queued_bytes as u64;
            let has_data_rx = stream.data_rx.is_some();
            let data_rx_len = stream
                .data_rx
                .as_ref()
                .map(|data_rx| data_rx.len())
                .unwrap_or(0);
            let unconsumed = stream
                .flow
                .rx_bytes
                .saturating_sub(stream.flow.consumed_offset);
            let mut sent_offset = 0u64;
            let mut maxdata_remote = 0u64;
            let send_debug_ok = !cnx.is_null()
                && slipstream_get_stream_send_debug(
                    cnx,
                    *stream_id,
                    &mut sent_offset,
                    std::ptr::null_mut(),
                    &mut maxdata_remote,
                ) == 0;
            let send_backlog = if send_debug_ok {
                stream.tx_bytes.saturating_sub(sent_offset)
            } else {
                0
            };
            if queued_bytes > 0
                || stream.recv_state != StreamRecvState::Open
                || stream.send_state != StreamSendState::Open
                || stream.flow.discarding
                || unconsumed > 0
                || data_rx_len > 0
                || send_backlog > 0
            {
                summaries.push(ClientBacklogSummary {
                    stream_id: *stream_id,
                    queued_bytes,
                    rx_bytes: stream.flow.rx_bytes,
                    consumed_offset: stream.flow.consumed_offset,
                    fin_offset: stream.flow.fin_offset,
                    recv_state: stream.recv_state,
                    send_state: stream.send_state,
                    stop_sending_sent: stream.flow.stop_sending_sent,
                    discarding: stream.flow.discarding,
                    has_data_rx,
                    data_rx_len,
                    tx_bytes: stream.tx_bytes,
                    send_sent_offset: send_debug_ok.then_some(sent_offset),
                    send_maxdata_remote: send_debug_ok.then_some(maxdata_remote),
                });
            }
        }
        summaries.sort_by(|left, right| {
            let left_backlog = left
                .queued_bytes
                .saturating_add(left.data_rx_len as u64)
                .max(
                    left.tx_bytes
                        .saturating_sub(left.send_sent_offset.unwrap_or(left.tx_bytes)),
                );
            let right_backlog = right
                .queued_bytes
                .saturating_add(right.data_rx_len as u64)
                .max(
                    right
                        .tx_bytes
                        .saturating_sub(right.send_sent_offset.unwrap_or(right.tx_bytes)),
                );
            right_backlog.cmp(&left_backlog)
        });
        summaries.truncate(limit);
        summaries
    }

    pub(crate) fn take_path_events(&mut self) -> Vec<PathEvent> {
        std::mem::take(&mut self.path_events)
    }

    pub(crate) fn reset_for_reconnect(&mut self) {
        let debug_streams = self.debug_streams;
        for (stream_id, mut stream) in self.streams.drain() {
            if let Some(read_abort_tx) = stream.read_abort_tx.take() {
                let _ = read_abort_tx.send(());
            }
            let _ = stream.write_tx.send(StreamWrite::Fin);
            if debug_streams {
                debug!("stream {}: closing due to reconnect", stream_id);
            }
        }
        self.ready = false;
        self.closing = false;
        self.connection_generation = self.connection_generation.wrapping_add(1);
        self.multi_stream_mode = false;
        self.path_events.clear();
        self.acceptor.reset();
        self.debug_enqueued_bytes = 0;
        self.debug_last_enqueue_at = 0;
        self.acceptor_limit_logged = false;
    }
}

pub(super) struct ClientStream {
    pub(super) write_tx: mpsc::UnboundedSender<StreamWrite>,
    pub(super) read_abort_tx: Option<oneshot::Sender<()>>,
    pub(super) data_rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub(super) tx_bytes: u64,
    pub(super) recv_state: StreamRecvState,
    pub(super) send_state: StreamSendState,
    pub(super) flow: FlowControlState,
    /// `picoquic_current_time()` when local TCP read hit EOF (peer FIN). `None` while fully open.
    /// Used to reap CLOSE-WAIT sockets whose remote QUIC half never completes.
    pub(super) tcp_local_eof_at_us: Option<u64>,
}

impl ClientStream {
    /// EPIPE-class local write failure: we can no longer deliver inbound QUIC data to the local
    /// peer, but the local peer may still be sending data upstream (`send_state` may still be
    /// `Open`). This is a true half-close, not a full bidi abort (issue #60, STOP_SENDING vs
    /// RESET_STREAM): mark this stream as discarding future inbound data -- mirroring the
    /// queue-overflow discarding path in `flow_control::handle_stream_receive`, so subsequent
    /// inbound QUIC data is silently consumed instead of routed to the now-dead local write
    /// channel -- and report whether the caller still needs to invoke `picoquic_stop_sending`
    /// (i.e. it was not already sent).
    ///
    /// Pure state mutation with no FFI/unsafe, so it is unit-testable without a live picoquic
    /// connection (calling `picoquic_stop_sending`/`picoquic_reset_stream` with a null cnx is
    /// undefined behavior).
    pub(super) fn mark_write_error_half_closed(&mut self) -> bool {
        let should_stop_sending = !self.flow.stop_sending_sent;
        self.flow.discarding = true;
        self.flow.queued_bytes = 0;
        self.flow.stop_sending_sent = true;
        should_stop_sending
    }
}

impl HasFlowControlState for ClientStream {
    fn flow_control(&self) -> &FlowControlState {
        &self.flow
    }

    fn flow_control_mut(&mut self) -> &mut FlowControlState {
        &mut self.flow
    }
}

pub(crate) enum Command {
    NewStream {
        stream: TokioTcpStream,
        reservation: acceptor::AcceptorReservation,
    },
    StreamData {
        stream_id: u64,
        data: Vec<u8>,
    },
    StreamClosed {
        stream_id: u64,
    },
    /// Local SOCKS peer FINed (TCP read returned 0). Armed immediately from the reader task so the
    /// CLOSE-WAIT reaper clock starts even when `drain_stream_data` is paused under upstream
    /// backpressure (which would otherwise leave `tcp_local_eof_at_us` unset forever).
    StreamLocalTcpEof {
        stream_id: u64,
        generation: usize,
    },
    StreamReadError {
        stream_id: u64,
        generation: usize,
    },
    StreamWriteError {
        stream_id: u64,
        generation: usize,
    },
    StreamWriteDrained {
        stream_id: u64,
        bytes: usize,
        generation: usize,
    },
}

pub(crate) enum PathEvent {
    Available(u64),
    Deleted(u64),
}
