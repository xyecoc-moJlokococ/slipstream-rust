use super::invariants::check_stream_invariants;
use super::io_tasks::{spawn_client_reader, spawn_client_writer, STREAM_READ_CHUNK_BYTES};
use super::state::{
    ClientState, ClientStream, Command, StreamRecvState, StreamSendState,
    CLIENT_WRITE_COALESCE_DEFAULT_BYTES, DEFAULT_TCP_RCVBUF_BYTES, TCP_HALF_CLOSED_MAX_US,
};
#[cfg(test)]
use super::test_hooks;
use slipstream_core::flow_control::{
    conn_reserve_bytes, consume_error_log_message, consume_stream_data, promote_error_log_message,
    promote_streams, reserve_target_offset, FlowControlState, PromoteEntry,
};
use slipstream_core::tcp::{stream_read_limit_chunks, tcp_send_buffer_bytes};
use slipstream_ffi::picoquic::{
    picoquic_add_to_stream, picoquic_cnx_t, picoquic_current_time,
    picoquic_get_next_local_stream_id, picoquic_mark_active_stream, picoquic_stop_sending,
    picoquic_stream_data_consumed,
};
use slipstream_ffi::{abort_stream_bidi, SLIPSTREAM_INTERNAL_ERROR};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

fn command_generation_matches(
    state: &ClientState,
    stream_id: u64,
    generation: usize,
    label: &str,
) -> bool {
    if generation == state.connection_generation {
        return true;
    }
    debug!(
        "stream {}: ignoring stale {} generation={} current_generation={}",
        stream_id, label, generation, state.connection_generation
    );
    false
}

pub(crate) fn drain_commands(
    cnx: *mut picoquic_cnx_t,
    state_ptr: *mut ClientState,
    command_rx: &mut mpsc::UnboundedReceiver<Command>,
) {
    while let Ok(command) = command_rx.try_recv() {
        handle_command(cnx, state_ptr, command);
    }
}

pub(crate) fn drain_stream_data(cnx: *mut picoquic_cnx_t, state_ptr: *mut ClientState) {
    let mut pending = Vec::new();
    let mut closed_streams = Vec::new();
    let now_us = unsafe { picoquic_current_time() };
    {
        let state = unsafe { &mut *state_ptr };
        slipstream_core::drain_stream_data!(state.streams, data_rx, pending, closed_streams);
        for stream_id in &closed_streams {
            if let Some(stream) = state.streams.get_mut(stream_id) {
                if stream.send_state == StreamSendState::Open {
                    stream.send_state = StreamSendState::Closing;
                }
                // Local SOCKS peer FINed: arm the CLOSE-WAIT reaper clock.
                if stream.tcp_local_eof_at_us.is_none() {
                    stream.tcp_local_eof_at_us = Some(now_us);
                }
            }
        }
    }
    for (stream_id, data) in pending {
        handle_command(cnx, state_ptr, Command::StreamData { stream_id, data });
    }
    for stream_id in closed_streams {
        handle_command(cnx, state_ptr, Command::StreamClosed { stream_id });
    }
}

/// Force-close accepted TCP sockets that have been half-closed (peer FIN) longer than
/// [TCP_HALF_CLOSED_MAX_US] without the QUIC half finishing. Without this, CLOSE-WAIT fds
/// accumulate on the native SOCKS listen port under a slow/dead DNS carrier.
pub(crate) fn reap_half_closed_tcp_streams(
    cnx: *mut picoquic_cnx_t,
    state_ptr: *mut ClientState,
    now_us: u64,
) {
    let stale = {
        let state = unsafe { &*state_ptr };
        state.stale_half_closed_tcp_streams(now_us, TCP_HALF_CLOSED_MAX_US)
    };
    if stale.is_empty() {
        return;
    }
    warn!(
        "reaping {} half-closed TCP stream(s) past {}ms (CLOSE-WAIT guard)",
        stale.len(),
        TCP_HALF_CLOSED_MAX_US / 1_000
    );
    for stream_id in stale {
        warn!(
            "stream {}: reaping half-closed TCP (local peer FIN, remote QUIC still open)",
            stream_id
        );
        if !cnx.is_null() {
            unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
        }
        let state = unsafe { &mut *state_ptr };
        state.remove_stream(stream_id);
    }
}

pub(crate) fn handle_command(
    cnx: *mut picoquic_cnx_t,
    state_ptr: *mut ClientState,
    command: Command,
) {
    let state = unsafe { &mut *state_ptr };
    match command {
        Command::NewStream {
            stream,
            reservation,
        } => {
            if !reservation.is_fresh() {
                drop(stream);
                return;
            }
            let _ = stream.set_nodelay(true);
            #[cfg(test)]
            let forced_failure = test_hooks::take_mark_active_stream_failure();
            #[cfg(not(test))]
            let forced_failure = false;
            #[cfg(test)]
            let stream_id = if forced_failure {
                4
            } else {
                assert!(
                    !cnx.is_null(),
                    "picoquic connection must be non-null when not forcing failures in tests"
                );
                unsafe { picoquic_get_next_local_stream_id(cnx, 0) }
            };
            #[cfg(not(test))]
            let stream_id = unsafe { picoquic_get_next_local_stream_id(cnx, 0) };
            #[cfg(test)]
            let ret = if forced_failure {
                test_hooks::FORCED_MARK_ACTIVE_STREAM_ERROR
            } else {
                unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) }
            };
            #[cfg(not(test))]
            let ret =
                unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) };
            if ret != 0 {
                warn!(
                    "stream {}: mark_active_stream failed ret={}",
                    stream_id, ret
                );
                if !forced_failure {
                    unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                }
                return;
            }
            if !reservation.commit() {
                warn!(
                    "stream {}: acceptor generation changed during activation",
                    stream_id
                );
                if !forced_failure {
                    unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                }
                return;
            }
            let read_limit = stream_read_limit_chunks(
                &stream,
                DEFAULT_TCP_RCVBUF_BYTES,
                STREAM_READ_CHUNK_BYTES,
            );
            let (data_tx, data_rx) = mpsc::channel(read_limit);
            let data_notify = state.data_notify.clone();
            let send_buffer_bytes = tcp_send_buffer_bytes(&stream)
                .filter(|bytes| *bytes > 0)
                .unwrap_or(CLIENT_WRITE_COALESCE_DEFAULT_BYTES);
            let (read_half, write_half) = stream.into_split();
            let (write_tx, write_rx) = mpsc::unbounded_channel();
            let command_tx = state.command_tx.clone();
            let (read_abort_tx, read_abort_rx) = oneshot::channel();
            let generation = state.connection_generation;
            state.streams.insert(
                stream_id,
                ClientStream {
                    write_tx,
                    read_abort_tx: Some(read_abort_tx),
                    data_rx: Some(data_rx),
                    tx_bytes: 0,
                    recv_state: StreamRecvState::Open,
                    send_state: StreamSendState::Open,
                    flow: FlowControlState::default(),
                    tcp_local_eof_at_us: None,
                },
            );
            state.debug_last_enqueue_at = unsafe { picoquic_current_time() };
            spawn_client_reader(
                stream_id,
                read_half,
                read_abort_rx,
                generation,
                command_tx.clone(),
                data_tx,
                data_notify,
            );
            spawn_client_writer(
                stream_id,
                write_half,
                write_rx,
                generation,
                command_tx,
                send_buffer_bytes,
            );
            if !state.multi_stream_mode && state.streams.len() > 1 {
                state.multi_stream_mode = true;
                promote_streams(
                    state
                        .streams
                        .iter_mut()
                        .map(|(stream_id, stream)| PromoteEntry {
                            stream_id: *stream_id,
                            rx_bytes: stream.flow.rx_bytes,
                            consumed_offset: &mut stream.flow.consumed_offset,
                            discarding: stream.flow.discarding,
                        }),
                    |stream_id, new_offset| unsafe {
                        picoquic_stream_data_consumed(cnx, stream_id, new_offset)
                    },
                    |stream_id, ret, consumed_offset, rx_bytes| {
                        warn!(
                            "{}",
                            promote_error_log_message(stream_id, ret, consumed_offset, rx_bytes)
                        );
                    },
                );
            }
            if state.debug_streams {
                debug!("stream {}: accepted", stream_id);
            } else {
                debug!("Accepted TCP stream {}", stream_id);
            }
            check_stream_invariants(state, stream_id, "NewStream");
        }
        Command::StreamData { stream_id, data } => {
            let ret =
                unsafe { picoquic_add_to_stream(cnx, stream_id, data.as_ptr(), data.len(), 0) };
            if ret < 0 {
                warn!(
                    "stream {}: add_to_stream failed ret={} chunk_len={}",
                    stream_id,
                    ret,
                    data.len()
                );
                unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                state.remove_stream(stream_id);
            } else if let Some(stream) = state.streams.get_mut(&stream_id) {
                stream.tx_bytes = stream.tx_bytes.saturating_add(data.len() as u64);
                let now = unsafe { picoquic_current_time() };
                state.debug_enqueued_bytes =
                    state.debug_enqueued_bytes.saturating_add(data.len() as u64);
                state.debug_last_enqueue_at = now;
            }
            check_stream_invariants(state, stream_id, "StreamData");
        }
        Command::StreamLocalTcpEof {
            stream_id,
            generation,
        } => {
            if !command_generation_matches(state, stream_id, generation, "StreamLocalTcpEof") {
                return;
            }
            if let Some(stream) = state.streams.get_mut(&stream_id) {
                // Only arm the clock here. Do NOT flip send_state to Closing while data_rx is
                // still live -- that violates the "closed send with data_rx" invariant. Closing
                // is applied when drain_stream_data sees data_tx drop (Disconnected).
                if stream.tcp_local_eof_at_us.is_none() {
                    stream.tcp_local_eof_at_us = Some(unsafe { picoquic_current_time() });
                }
            }
            check_stream_invariants(state, stream_id, "StreamLocalTcpEof");
        }
        Command::StreamClosed { stream_id } => {
            let should_send_fin = state
                .streams
                .get(&stream_id)
                .is_some_and(|stream| stream.send_state.can_queue_fin());
            if !should_send_fin {
                return;
            }
            #[cfg(test)]
            let forced_failure = test_hooks::take_add_to_stream_failure();
            #[cfg(not(test))]
            let forced_failure = false;
            #[cfg(test)]
            let ret = if forced_failure {
                test_hooks::FORCED_ADD_TO_STREAM_ERROR
            } else {
                assert!(
                    !cnx.is_null(),
                    "picoquic connection must be non-null when not forcing failures in tests"
                );
                unsafe { picoquic_add_to_stream(cnx, stream_id, std::ptr::null(), 0, 1) }
            };
            #[cfg(not(test))]
            let ret = unsafe { picoquic_add_to_stream(cnx, stream_id, std::ptr::null(), 0, 1) };
            state.debug_last_enqueue_at = unsafe { picoquic_current_time() };
            if ret < 0 {
                warn!(
                    "stream {}: add_to_stream(fin) failed ret={}",
                    stream_id, ret
                );
                if !forced_failure {
                    unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                }
                state.remove_stream(stream_id);
            } else if let Some(stream) = state.streams.get_mut(&stream_id) {
                stream.send_state = StreamSendState::FinQueued;
                if stream.tcp_local_eof_at_us.is_none() {
                    stream.tcp_local_eof_at_us = Some(unsafe { picoquic_current_time() });
                }
                if stream.recv_state.is_closed() && stream.flow.queued_bytes == 0 {
                    state.remove_stream(stream_id);
                }
            }
            check_stream_invariants(state, stream_id, "StreamClosed");
        }
        Command::StreamReadError {
            stream_id,
            generation,
        } => {
            if !command_generation_matches(state, stream_id, generation, "StreamReadError") {
                return;
            }
            if let Some(stream) = state.remove_stream(stream_id) {
                warn!(
                    "stream {}: tcp read error rx_bytes={} tx_bytes={} queued={} consumed_offset={} fin_offset={:?}",
                    stream_id,
                    stream.flow.rx_bytes,
                    stream.tx_bytes,
                    stream.flow.queued_bytes,
                    stream.flow.consumed_offset,
                    stream.flow.fin_offset
                );
            } else {
                warn!("stream {}: tcp read error (unknown stream)", stream_id);
            }
            unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
        }
        Command::StreamWriteError {
            stream_id,
            generation,
        } => {
            if !command_generation_matches(state, stream_id, generation, "StreamWriteError") {
                return;
            }
            // Issue #60 (STOP_SENDING vs RESET_STREAM): an EPIPE-class local write failure only
            // means we can no longer deliver INBOUND (remote->local) data to the local peer. It
            // does NOT mean the local peer has stopped SENDING upstream, so this is a half-close,
            // not a full bidi abort. Keep the stream alive (do NOT remove_stream) so the
            // local->remote upload direction can finish via the normal StreamClosed /
            // StreamLocalTcpEof path; mark it discarding so further inbound QUIC data is dropped
            // instead of re-delivered to the dead write channel; and send picoquic_stop_sending
            // (receiver-side abort) -- NOT picoquic_reset_stream, which would also kill our own
            // send direction.
            if let Some(stream) = state.streams.get_mut(&stream_id) {
                warn!(
                    "stream {}: tcp write error rx_bytes={} tx_bytes={} queued={} consumed_offset={} fin_offset={:?}",
                    stream_id,
                    stream.flow.rx_bytes,
                    stream.tx_bytes,
                    stream.flow.queued_bytes,
                    stream.flow.consumed_offset,
                    stream.flow.fin_offset
                );
                if stream.mark_write_error_half_closed() {
                    unsafe { picoquic_stop_sending(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                }
            } else {
                warn!("stream {}: tcp write error (unknown stream)", stream_id);
            }
            check_stream_invariants(state, stream_id, "StreamWriteError");
        }
        Command::StreamWriteDrained {
            stream_id,
            bytes,
            generation,
        } => {
            if !command_generation_matches(state, stream_id, generation, "StreamWriteDrained") {
                return;
            }
            let mut remove_stream = false;
            if let Some(stream) = state.streams.get_mut(&stream_id) {
                if stream.flow.discarding {
                    return;
                }
                stream.flow.queued_bytes = stream.flow.queued_bytes.saturating_sub(bytes);
                if !state.multi_stream_mode {
                    let new_offset = reserve_target_offset(
                        stream.flow.rx_bytes,
                        stream.flow.queued_bytes,
                        stream.flow.fin_offset,
                        conn_reserve_bytes(),
                    );
                    if !consume_stream_data(
                        &mut stream.flow.consumed_offset,
                        new_offset,
                        |new_offset| unsafe {
                            picoquic_stream_data_consumed(cnx, stream_id, new_offset)
                        },
                        |ret, current, target| {
                            warn!(
                                "{}",
                                consume_error_log_message(stream_id, "", ret, current, target)
                            );
                        },
                    ) {
                        unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                        state.remove_stream(stream_id);
                        return;
                    }
                }
                if stream.recv_state.is_closed()
                    && stream.send_state.is_closed()
                    && stream.flow.queued_bytes == 0
                {
                    remove_stream = true;
                }
            }
            if remove_stream {
                state.remove_stream(stream_id);
            }
            check_stream_invariants(state, stream_id, "StreamWriteDrained");
        }
    }
}
