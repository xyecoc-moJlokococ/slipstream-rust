use super::callback::handle_stream_data;
use super::state::{ClientStream, StreamRecvState, StreamSendState};
use super::test_hooks;
use super::*;
use slipstream_core::flow_control::FlowControlState;
use slipstream_core::test_support::ResetOnDrop;
use std::sync::Arc;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::{sleep, timeout, Duration};

#[test]
fn add_to_stream_fin_failure_removes_stream() {
    let _guard = ResetOnDrop::new(|| test_hooks::set_add_to_stream_failures(0));
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: None,
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::Open,
            flow: FlowControlState::default(),
            tcp_local_eof_at_us: None,
        },
    );

    test_hooks::set_add_to_stream_failures(1);

    handle_command(
        std::ptr::null_mut(),
        &mut state as *mut _,
        Command::StreamClosed { stream_id },
    );

    assert!(
        !state.streams.contains_key(&stream_id),
        "stream state should be removed when add_to_stream(fin) fails"
    );
}

#[test]
fn remote_fin_keeps_local_read_open() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, mut write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();
    let (_data_tx, data_rx) = mpsc::channel(1);

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

    handle_stream_data(std::ptr::null_mut(), &mut state, stream_id, true, &[]);

    let stream = state
        .streams
        .get(&stream_id)
        .expect("stream should remain after remote fin");
    assert_eq!(stream.recv_state, StreamRecvState::FinReceived);
    assert_eq!(stream.send_state, StreamSendState::Open);
    assert!(
        stream.data_rx.is_some(),
        "local TCP read side should stay open after remote fin"
    );
    assert!(
        matches!(write_rx.try_recv(), Ok(super::io_tasks::StreamWrite::Fin)),
        "expected a TCP fin to be enqueued"
    );
}

#[test]
fn stream_removal_requires_both_halves_closed() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();
    let (_data_tx, data_rx) = mpsc::channel(1);

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

    handle_stream_data(std::ptr::null_mut(), &mut state, stream_id, true, &[]);
    assert!(
        state.streams.contains_key(&stream_id),
        "stream should remain when only recv side is closed"
    );

    if let Some(stream) = state.streams.get_mut(&stream_id) {
        stream.send_state = StreamSendState::FinQueued;
    }
    handle_command(
        std::ptr::null_mut(),
        &mut state as *mut _,
        Command::StreamWriteDrained {
            stream_id,
            bytes: 0,
            generation: 0,
        },
    );
    assert!(
        !state.streams.contains_key(&stream_id),
        "stream should be removed once both halves are closed"
    );
}

#[test]
fn local_fin_does_not_remove_until_recv_fin() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: None,
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::FinQueued,
            flow: FlowControlState::default(),
            tcp_local_eof_at_us: None,
        },
    );

    handle_command(
        std::ptr::null_mut(),
        &mut state as *mut _,
        Command::StreamWriteDrained {
            stream_id,
            bytes: 0,
            generation: 0,
        },
    );

    assert!(
        state.streams.contains_key(&stream_id),
        "stream should remain when only send side is closed"
    );
}

#[test]
fn multi_stream_mode_resets_when_last_stream_is_removed() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);

    for stream_id in [4, 8] {
        let (write_tx, _write_rx) = mpsc::unbounded_channel();
        let (read_abort_tx, _read_abort_rx) = oneshot::channel();
        state.streams.insert(
            stream_id,
            ClientStream {
                write_tx,
                read_abort_tx: Some(read_abort_tx),
                data_rx: None,
                tx_bytes: 0,
                recv_state: StreamRecvState::Open,
                send_state: StreamSendState::Open,
                flow: FlowControlState::default(),
                tcp_local_eof_at_us: None,
            },
        );
    }
    state.multi_stream_mode = true;

    assert!(state.remove_stream(4).is_some());
    assert!(
        state.multi_stream_mode,
        "multi-stream mode should remain while another stream is active"
    );

    assert!(state.remove_stream(8).is_some());
    assert!(
        !state.multi_stream_mode,
        "multi-stream mode must reset when the connection has no active streams"
    );
}

#[test]
fn backlog_summaries_are_sorted_by_backlog() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);

    for (stream_id, queued_bytes) in [(4, 128usize), (8, 4096usize), (12, 1024usize)] {
        let (write_tx, _write_rx) = mpsc::unbounded_channel();
        let (read_abort_tx, _read_abort_rx) = oneshot::channel();
        state.streams.insert(
            stream_id,
            ClientStream {
                write_tx,
                read_abort_tx: Some(read_abort_tx),
                data_rx: None,
                tx_bytes: 0,
                recv_state: StreamRecvState::Open,
                send_state: StreamSendState::Open,
                flow: FlowControlState {
                    queued_bytes,
                    ..FlowControlState::default()
                },
                tcp_local_eof_at_us: None,
            },
        );
    }

    let summaries = unsafe { state.stream_backlog_summaries(std::ptr::null_mut(), 2) };
    let stream_ids: Vec<u64> = summaries.iter().map(|summary| summary.stream_id).collect();

    assert_eq!(stream_ids, vec![8, 12]);
}

#[test]
fn mark_active_stream_failure_removes_stream() {
    let _guard = ResetOnDrop::new(|| test_hooks::set_mark_active_stream_failures(0));
    let _limit_guard = ResetOnDrop::new(|| acceptor::ClientAcceptor::set_test_limit(0));
    acceptor::ClientAcceptor::set_test_limit(1);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("build tokio runtime");
    rt.block_on(async {
        let listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            stream
        });
        let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let stream = accept.await.expect("accept join");

        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let data_notify = Arc::new(Notify::new());
        let acceptor = acceptor::ClientAcceptor::new();
        let reservation = acceptor.reserve_for_test().await;
        let mut state = ClientState::new(command_tx, data_notify, false, acceptor);

        test_hooks::set_mark_active_stream_failures(1);

        handle_command(
            std::ptr::null_mut(),
            &mut state as *mut _,
            Command::NewStream {
                stream,
                reservation,
            },
        );

        assert!(
            state.streams.is_empty(),
            "stream state should be removed when mark_active_stream fails"
        );
    });
}

#[test]
fn stale_task_command_is_ignored_after_reconnect() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: None,
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::Open,
            flow: FlowControlState::default(),
            tcp_local_eof_at_us: None,
        },
    );
    state.connection_generation = 1;

    handle_command(
        std::ptr::null_mut(),
        &mut state as *mut _,
        Command::StreamReadError {
            stream_id,
            generation: 0,
        },
    );

    assert!(
        state.streams.contains_key(&stream_id),
        "stale task command from old generation must not mutate current stream state"
    );
}

#[test]
fn acceptor_backpressure_blocks_new_connections() {
    let _guard = ResetOnDrop::new(|| acceptor::ClientAcceptor::set_test_limit(0));
    acceptor::ClientAcceptor::set_test_limit(1);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("build tokio runtime");
    rt.block_on(async {
        let listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let acceptor = acceptor::ClientAcceptor::new();
        acceptor.spawn(listener, command_tx);

        let mut clients = Vec::new();
        for _ in 0..3 {
            clients.push(tokio::net::TcpStream::connect(addr).await.expect("connect"));
        }

        sleep(Duration::from_millis(50)).await;

        let _first = timeout(Duration::from_secs(1), command_rx.recv())
            .await
            .expect("first accept")
            .expect("first command");
        let second = timeout(Duration::from_millis(200), command_rx.recv()).await;

        assert!(
            second.is_err(),
            "expected acceptor backpressure to block additional accepts while at limit"
        );

        drop(clients);
    });
}

#[test]
fn stream_local_tcp_eof_arms_reaper_clock() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();
    let (_data_tx, data_rx) = mpsc::channel(1);
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

    handle_command(
        std::ptr::null_mut(),
        &mut state as *mut _,
        Command::StreamLocalTcpEof {
            stream_id,
            generation: 0,
        },
    );

    let stream = state.streams.get(&stream_id).expect("stream remains");
    assert!(
        stream.tcp_local_eof_at_us.is_some(),
        "StreamLocalTcpEof must arm CLOSE-WAIT clock without waiting for drain_stream_data"
    );
    assert_eq!(
        stream.send_state,
        StreamSendState::Open,
        "send_state stays Open until data_rx is dropped by drain_stream_data"
    );
}

#[test]
fn fully_open_streams_are_not_half_closed_stale() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();
    state.streams.insert(
        4,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: None,
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::Open,
            flow: FlowControlState::default(),
            tcp_local_eof_at_us: None,
        },
    );
    assert!(
        state
            .stale_half_closed_tcp_streams(50_000_000, TCP_HALF_CLOSED_MAX_US)
            .is_empty(),
        "fully-open streams must not be reaped by the CLOSE-WAIT guard"
    );
}

#[test]
fn stale_half_closed_tcp_selector_respects_deadline() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);

    for (stream_id, eof_at) in [
        (4u64, Some(1_000u64)),
        (8u64, Some(40_000_000u64)),
        (12u64, None),
    ] {
        let (write_tx, _write_rx) = mpsc::unbounded_channel();
        let (read_abort_tx, _read_abort_rx) = oneshot::channel();
        state.streams.insert(
            stream_id,
            ClientStream {
                write_tx,
                read_abort_tx: Some(read_abort_tx),
                data_rx: None,
                tx_bytes: 0,
                recv_state: StreamRecvState::Open,
                send_state: StreamSendState::FinQueued,
                flow: FlowControlState::default(),
                tcp_local_eof_at_us: eof_at,
            },
        );
    }

    let now = 50_000_000u64; // 50s
    let stale = state.stale_half_closed_tcp_streams(now, TCP_HALF_CLOSED_MAX_US);
    assert_eq!(
        stale,
        vec![4],
        "only the stream past 45s half-closed window should be stale (eof_at=1ms)"
    );
}

#[test]
fn reap_half_closed_tcp_streams_removes_stale() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, mut write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: None,
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::FinQueued,
            flow: FlowControlState::default(),
            // Far in the past relative to now below.
            tcp_local_eof_at_us: Some(1_000),
        },
    );

    let now = 50_000_000u64;
    reap_half_closed_tcp_streams(std::ptr::null_mut(), &mut state as *mut _, now);

    assert!(
        !state.streams.contains_key(&stream_id),
        "stale half-closed stream must be removed to release CLOSE-WAIT fd"
    );
    assert!(
        matches!(write_rx.try_recv(), Ok(super::io_tasks::StreamWrite::Fin)),
        "remove_stream should FIN the local TCP writer"
    );
}

#[test]
fn write_error_half_close_marks_discarding_and_is_idempotent() {
    // Issue #60: the pure half-close helper is a state-only mutation (no FFI), so it is
    // testable without a live picoquic connection.
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();
    let (_data_tx, data_rx) = mpsc::channel(1);
    let mut stream = ClientStream {
        write_tx,
        read_abort_tx: Some(read_abort_tx),
        data_rx: Some(data_rx),
        tx_bytes: 0,
        recv_state: StreamRecvState::Open,
        send_state: StreamSendState::Open,
        flow: FlowControlState {
            queued_bytes: 4096,
            ..FlowControlState::default()
        },
        tcp_local_eof_at_us: None,
    };

    // First write failure: caller must send STOP_SENDING, and the stream flips to discarding
    // with its inbound queue accounting zeroed.
    assert!(
        stream.mark_write_error_half_closed(),
        "first write-error half-close must request STOP_SENDING"
    );
    assert!(stream.flow.discarding, "stream must be marked discarding");
    assert_eq!(stream.flow.queued_bytes, 0, "queued bytes must be zeroed");
    assert!(
        stream.flow.stop_sending_sent,
        "stop_sending_sent must latch true"
    );
    // Half-close must not touch the send side or the local read channel.
    assert_eq!(
        stream.send_state,
        StreamSendState::Open,
        "half-close must not touch the send side"
    );
    assert!(
        stream.data_rx.is_some(),
        "half-close must not drop the local read channel"
    );

    // Idempotent: a second write failure must not re-request STOP_SENDING.
    assert!(
        !stream.mark_write_error_half_closed(),
        "second write-error half-close must not re-request STOP_SENDING"
    );
    assert!(stream.flow.discarding);
    assert_eq!(stream.flow.queued_bytes, 0);
}

#[test]
fn stream_write_error_preserves_half_close() {
    // Issue #60: dispatching StreamWriteError must NOT remove the stream and must leave the
    // send side / local read channel intact (half-close, not a full bidi abort). We pre-set
    // stop_sending_sent so the dispatch path's helper returns false and never reaches the
    // null-cnx picoquic_stop_sending FFI call in this unit test.
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();
    let (_data_tx, data_rx) = mpsc::channel(1);

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: Some(data_rx),
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::Open,
            flow: FlowControlState {
                queued_bytes: 8192,
                stop_sending_sent: true,
                ..FlowControlState::default()
            },
            tcp_local_eof_at_us: None,
        },
    );

    handle_command(
        std::ptr::null_mut(),
        &mut state as *mut _,
        Command::StreamWriteError {
            stream_id,
            generation: 0,
        },
    );

    let stream = state
        .streams
        .get(&stream_id)
        .expect("write error must NOT remove the stream (half-close keeps upload alive)");
    assert_eq!(
        stream.send_state,
        StreamSendState::Open,
        "write error must not touch the send side"
    );
    assert!(
        stream.data_rx.is_some(),
        "write error must not drop the local read channel"
    );
    assert_eq!(stream.recv_state, StreamRecvState::Open);
    assert!(
        stream.flow.discarding,
        "write error must mark the stream discarding"
    );
    assert_eq!(
        stream.flow.queued_bytes, 0,
        "write error must zero the inbound queue accounting"
    );
}

#[test]
fn stream_write_error_discards_subsequent_inbound_data() {
    // Issue #60: after the write-error half-close marks the stream discarding, a later inbound
    // QUIC data event must be silently dropped by the discarding short-circuit in
    // flow_control::handle_stream_receive -- NOT enqueued to the (now-dead) local write channel,
    // and NOT resetting/removing the stream (the upload half stays alive).
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, mut write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();
    let (_data_tx, data_rx) = mpsc::channel(1);

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: Some(data_rx),
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::Open,
            // consumed_offset pre-set past any inbound bytes so the discarding-branch consume in
            // handle_stream_receive short-circuits (target <= consumed_offset) and never invokes
            // picoquic_stream_data_consumed with the null cnx passed below.
            flow: FlowControlState {
                consumed_offset: u64::MAX,
                ..FlowControlState::default()
            },
            tcp_local_eof_at_us: None,
        },
    );

    // Half-close via the write-error path (call the pure helper directly to set up discarding
    // without touching the null-cnx FFI).
    assert!(state
        .streams
        .get_mut(&stream_id)
        .expect("stream present")
        .mark_write_error_half_closed());

    handle_stream_data(
        std::ptr::null_mut(),
        &mut state,
        stream_id,
        false,
        &[1, 2, 3, 4],
    );

    assert!(
        state.streams.contains_key(&stream_id),
        "discarded inbound data must not reset/remove the half-closed stream"
    );
    let stream = state.streams.get(&stream_id).expect("stream present");
    assert!(stream.flow.discarding, "stream must remain discarding");
    assert_eq!(
        stream.send_state,
        StreamSendState::Open,
        "discarding inbound data must not touch the send side"
    );
    assert!(
        stream.data_rx.is_some(),
        "discarding inbound data must not drop the local read channel"
    );
    assert!(
        matches!(write_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "inbound data must NOT be enqueued to the dead local write channel"
    );
}

#[test]
fn write_error_half_close_survives_inbound_fin() {
    // Issue #60: after the write-error half-close marks the stream discarding, an inbound
    // (download) FIN must NOT tear the stream down while the local upload side is still open --
    // doing so would abort the send/upload half the half-close exists to preserve. The FIN is
    // recorded (recv_state -> FinReceived, fin_offset set) but the stream stays alive so the
    // upload can finish later via the normal StreamClosed path. (Before the fix, discarding + FIN
    // unconditionally removed the stream, so this test fails on a revert.)
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, mut write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();
    let (_data_tx, data_rx) = mpsc::channel(1);

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: Some(data_rx),
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::Open,
            // consumed_offset past any inbound bytes so the discarding-branch consume in
            // handle_stream_receive short-circuits (target <= consumed_offset) and never invokes
            // picoquic_stream_data_consumed with the null cnx passed below.
            flow: FlowControlState {
                consumed_offset: u64::MAX,
                ..FlowControlState::default()
            },
            tcp_local_eof_at_us: None,
        },
    );

    assert!(state
        .streams
        .get_mut(&stream_id)
        .expect("stream present")
        .mark_write_error_half_closed());

    // Inbound data carrying a FIN while discarding, with the upload/send side still open.
    handle_stream_data(
        std::ptr::null_mut(),
        &mut state,
        stream_id,
        true,
        &[1, 2, 3, 4],
    );

    let stream = state
        .streams
        .get(&stream_id)
        .expect("inbound FIN while discarding must NOT remove a stream whose upload is still open");
    assert_eq!(
        stream.send_state,
        StreamSendState::Open,
        "upload/send half must stay alive across the inbound FIN"
    );
    assert_eq!(
        stream.recv_state,
        StreamRecvState::FinReceived,
        "inbound FIN must be recorded as received"
    );
    assert!(
        stream.flow.fin_offset.is_some(),
        "recv FinReceived requires fin_offset (invariant)"
    );
    assert!(stream.flow.discarding, "stream must remain discarding");
    assert!(
        stream.data_rx.is_some(),
        "inbound FIN must not drop the local read channel while send is open"
    );
    assert!(
        matches!(write_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "discarded inbound data/FIN must NOT be forwarded to the dead local write channel"
    );
}

#[test]
fn write_error_half_close_removed_on_inbound_fin_after_upload_closed() {
    // Issue #60 (complement of the above): once the upload side has already closed (FinQueued),
    // an inbound FIN while discarding removes the stream -- both directions are now done, so the
    // immediate teardown is the correct outcome.
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, _write_rx) = mpsc::unbounded_channel();

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: None,
            // send closed => data_rx must be None (invariant).
            data_rx: None,
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::FinQueued,
            flow: FlowControlState {
                discarding: true,
                stop_sending_sent: true,
                consumed_offset: u64::MAX,
                ..FlowControlState::default()
            },
            tcp_local_eof_at_us: Some(1),
        },
    );

    // Pure-FIN event (length 0) while discarding and the upload already FinQueued.
    handle_stream_data(std::ptr::null_mut(), &mut state, stream_id, true, &[]);

    assert!(
        !state.streams.contains_key(&stream_id),
        "inbound FIN while discarding must remove the stream once the upload side is closed"
    );
}
