# Configuration

This page documents runtime knobs and environment variables.

## Client and server environment variables

- SLIPSTREAM_STREAM_WRITE_BUFFER_BYTES
  Overrides the connection-level QUIC max_data limit used for backpressure.
  Default is 8 MiB. Values must be positive integers.
- SLIPSTREAM_STREAM_QUEUE_MAX_BYTES
  Per-stream receive queue cap enforced when multiple QUIC streams are active.
  Default is 2 MiB. Values must be positive integers.
- SLIPSTREAM_CONN_RESERVE_BYTES
  Minimum connection-level receive window to keep available for new streams in
  single-stream mode. Default is 64 KiB. Set to 0 to disable the reserve.

## TLS certificates

Sample certs live in `fixtures/certs/` for local testing only. The server
requires explicit `--cert` and `--key` paths; provide your own cert/key pair
for real deployments. If the configured cert/key paths do not exist, the
server auto-generates an ECDSA P-256 self-signed certificate (1000-year
validity) and writes the key with 0600 permissions. The client can pass
`--cert` to pin the server leaf certificate (PEM); the PEM must contain a
single certificate, and a CA bundle is not accepted there. Alternatively,
`--verify-system-ca` verifies the server's certificate chain against the
OS's default CA bundle (full chain + hostname check), like a normal HTTPS
client -- useful for a server certificate issued by a real CA rather than
pinned or self-signed. `--cert` and `--verify-system-ca` are mutually
exclusive. If neither is given, server certificates are not verified.

## Logging and debug knobs

- Logging uses `tracing` with `RUST_LOG` (default `info`). Example:
  `RUST_LOG=debug cargo run -p slipstream-client -- --resolver=IP:PORT --domain=example.com`.
- `--debug-poll` (client) enables periodic poll/pacing metrics.
- `--debug-streams` (client/server) logs stream lifecycle details.
- `--debug-commands` (server) reports command counts once per second.

## Protocol defaults

- Client ALPN: `picoquic_sample` (must match server ALPN).
- Client SNI: `test.example.com`.
- Server ALPN: `picoquic_sample`.
- Server QUIC MTU: `900`.
  Update `crates/slipstream-client/src/client.rs` and `crates/slipstream-server/src/server.rs`
  together to keep client/server ALPN in sync.

## Server runtime knobs

- `--max-connections`
  Caps concurrent QUIC connections and sizes internal connection tables (default: 256).
  In multi-worker mode each worker gets this cap independently (total capacity ≈ N × cap).
- `--idle-timeout-seconds`
  Closes idle QUIC connections after the given number of seconds (default: 60).
  Set to 0 to disable idle GC.
- `--reset-seed`
  Path to a 32-hex-char (16-byte) stateless reset seed. If the file does not
  exist, the server generates one and writes it with 0600 permissions. If not
  provided, the server uses an ephemeral seed and stateless resets will not
  survive restarts.
- `--workers <N>` (default: 1; SIP003 option `workers`)
  Number of independent worker threads, each with its own picoquic context and
  Tokio current-thread runtime. `1` is the historical single-threaded path.
  Values `>1` enable **userspace demux by source IP** (port ignored): one master
  thread receives UDP with recvmmsg and routes each datagram to
  `hash(src_ip) % N`. Replies are sent from workers on the shared bound socket.
  Demux copies into a **recycled buffer pool** (no `malloc` per packet in steady
  state); workers recycle DNS answer buffers and reuse sendmmsg scratch.

  Why not SO_REUSEPORT alone? Resolver/client source-port spray makes the kernel
  4-tuple hash split one logical client across sockets and would break QUIC.

  Good for ~5–10 concurrent clients where DNS/QUIC CPU saturates one core.
  Limits of v1: RX demux still runs on one core; a single client that multipaths
  through several recursive resolvers (different source IPs) may land on more
  than one worker. If a worker queue is full (8192), demux drops the packet
  (DNS is lossy) and logs a periodic warning.
- `SLIPSTREAM_UDP_SOCKET_BUFFER_BYTES` (default: 16 MiB)
  Requested SO_RCVBUF/SO_SNDBUF. Raise `net.core.rmem_max`/`wmem_max` at least as
  high (deploy sets 32 MiB) or the kernel will cap the effective size.

## picoquic build environment

These affect the build script in crates/slipstream-ffi:

- PICOQUIC_AUTO_BUILD
  Set to 0 to disable auto-building picoquic when headers/libs are missing.

- PICOQUIC_DIR
  picoquic source tree (default: vendor/picoquic).

- PICOQUIC_INCLUDE_DIR
  picoquic headers directory (default: vendor/picoquic/picoquic).

- PICOTLS_INCLUDE_DIR
  picotls headers directory (default: .picoquic-build/_deps/picotls-src/include on non-Windows, vendor/picotls/include for the Windows helper).

- PICOQUIC_BUILD_DIR
  picoquic build output (default: .picoquic-build; the Windows helper stages libs under .picoquic-build/windows/x64/Release and OpenSSL under .picoquic-build/windows/openssl by default).

- PICOQUIC_LIB_DIR
  Directory containing picoquic and picotls libraries.

## Script environment variables

Interop and benchmark scripts accept environment variables for ports, domains,
and paths. See docs/interop.md and docs/benchmarks.md for details.
