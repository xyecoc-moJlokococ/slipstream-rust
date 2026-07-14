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

    for (stream_id, eof_at) in [(4u64, Some(1_000u64)), (8u64, Some(40_000_000u64)), (12u64, None)] {
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
