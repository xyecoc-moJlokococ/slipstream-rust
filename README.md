# Slipstream (Rust)

Slipstream is a high-performance DNS tunnel that carries QUIC packets over DNS queries and responses.
This repository hosts the Rust rewrite of the [original C implementation](https://github.com/EndPositive/slipstream).

## What is here

- slipstream-client and slipstream-server CLI binaries.
- A DNS codec crate (`slipstream-dns`) with vector-based tests, supporting eight different DNS
  answer record types as tunnel carriers (see below).
- picoquic FFI integration for multipath QUIC support, including several local picoquic patches
  (`vendor/picoquic`, tracked in `docs/picoquic-changes.md`).
- Fully async with tokio.
- An Android JNI embedding path (used by the companion `SlipstreamCLI` app) alongside the
  standalone CLI binaries.
- And more! For a more up-to-date list of extra upstream features, see the
  [merged PRs](https://github.com/Mygod/slipstream-rust/pulls?q=is%3Apr+is%3Amerged+label%3Aenhancement)
  on `Mygod/slipstream-rust`.

## Fork status and repository notes

This is `xyecoc-moJlokococ`'s personal fork of [Mygod/slipstream-rust](https://github.com/Mygod/slipstream-rust)
(`upstream` remote), pushed to `origin` at `github.com/xyecoc-moJlokococ/slipstream-rust`. It is a
personal/development fork, not a clean drop-in replacement for upstream — expect uncommitted
work-in-progress on branches from time to time.

## Differences from upstream (Mygod/slipstream-rust)

On top of upstream, this fork adds:

### DNS carrier diversity (anti-fingerprinting)

The original protocol carries the tunnel payload exclusively in TXT records. This fork's DNS codec
(`crates/slipstream-dns/src/codec.rs`) can carry it in **eight** different answer types instead,
selected per-connection via `--dns-query-type` (client) / accepted unconditionally by the server —
no server reconfiguration needed to switch client-side:

| Type | RR # | Capacity per response | Status |
|---|---|---|---|
| TXT | 16 | Whole payload in one record (255-byte chunked strings) | Default, fully reliable |
| HTTPS/SVCB | 65 | Whole payload in one record, carried in an opaque `ech` SvcParam (RFC 9460) | Reliable; looks like normal browser HTTPS-record traffic to DPI |
| NULL | 10 | Whole payload in one record, fully opaque RDATA (RFC 1035 §3.3.10) | Reliable; some resolvers strip/refuse this rarely-used type |
| A | 1 | 4 bytes/record, many records per response | **Implemented, wire-verified, not production-safe yet** |
| AAAA | 28 | 16 bytes/record, many records per response | **Implemented, wire-verified, not production-safe yet** |
| CNAME | 5 | ~150 bytes/record (base32) or ~187 (base64u), encoded as a name | **Implemented, wire-verified, not production-safe yet** |
| MX | 15 | Same as CNAME, plus a fixed 2-byte preference field | **Implemented, wire-verified, not production-safe yet** |
| SRV | 33 | Same as CNAME, plus fixed priority/weight/port fields | **Implemented, wire-verified, not production-safe yet** |

The "not production-safe yet" types (A/AAAA/CNAME/MX/SRV, collectively the "chunked" or
"name-carrier" types) round-trip correctly at the codec level (see the per-type tests in
`crates/slipstream-dns/src/codec.rs` and confirmed live via packet capture: the server correctly
answers with properly-chunked, properly-encoded multi-record responses) — but under real network
conditions the QUIC handshake frequently fails to complete before picoquic's internal handshake
timeout (`PICOQUIC_MICROSEC_HANDSHAKE_MAX`, hardcoded to 30s and never overridden by this client).
Root cause: these types have far worse per-byte RR-framing overhead than TXT/HTTPS/NULL (a 900-byte
QUIC packet needs ~225 records as A vs. 1 as TXT), so completing a multi-KB handshake needs
substantially more successful round trips, and real network jitter makes that unreliable within the
default timeout window. The Android client (`SlipstreamCLI`) currently only exposes
TXT/HTTPS/NULL in its query-type picker for this reason. Raising the handshake timeout (there is no
CLI flag for it today, but `picoquic_set_default_handshake_timeout` is available in
`slipstream-ffi/src/picoquic.rs` if you want to experiment) measurably helps but wasn't validated
enough to ship as a default; treat A/AAAA/CNAME/MX/SRV as an experimental fingerprint-diversity
option for now, not a supported carrier.

Two data-encoding knobs apply independently of the carrier type:

- **base32 vs base64u** (`--base64u-encoding`, client-only, no server config needed — the server
  detects the encoding per-query via a marker prefix). base64u is ~20% denser (6 bits/char vs. 5)
  but case-sensitive; only enable it once you've confirmed the resolver path preserves label case
  end to end, since a case-normalizing resolver/cache will silently corrupt the payload rather than
  fail cleanly.
- **EDNS-raw upstream encoding** (`--upstream-encoding edns-raw`, vs. the default `qname`). Carries
  the upload payload in a custom EDNS option instead of the QNAME. **Known not to work through real
  operator DNS resolvers** — testing found that resolvers commonly alter/re-pack custom EDNS option
  data in transit (an ~80-byte payload arrived as 73-74 bytes), corrupting it. Left in for
  authoritative/direct-to-server setups where no recursive resolver sits in the path, but don't rely
  on it through a real ISP resolver.

### DNS-over-TCP resolver transport

The client can speak to the resolver over TCP instead of UDP (`--resolver-transport tcp`), for
networks where UDP/53 is shaped, blocked, or otherwise unreliable. Includes upload/download pacing
tuned specifically for the TCP path (`--dns-tcp-packet-loop-burst`) and a dedicated stabilization
pass after early flapping was observed in the field.

### Runtime transport/qtype auto-selection

On connect (and on client network changes), the client can probe available transports/query types
and pick the fastest one automatically instead of requiring a fixed config per network — with a
throughput gate (not just "did the handshake complete") so a technically-reachable-but-throttled
transport doesn't get stuck as the pick.

### System CA certificate verification

Three TLS verification modes are available for the client, in increasing order of how "normal
HTTPS" they look:

- **No verification** (default if neither flag below is given). The client accepts any certificate
  the server presents. Simple, but offers no protection if DNS traffic is intercepted/redirected to
  an impersonating server.
- **Leaf pinning** (`--cert <path>`). Pins one exact certificate by DER comparison — no chain or
  hostname check. Strong protection, but brittle: the pinned cert has to be updated by hand every
  time the server's certificate changes.
- **System CA verification** (`--verify-system-ca`, new in this fork). Verifies the server's full
  certificate chain against the OS's default CA bundle plus hostname matching — the same thing a
  browser does for a normal HTTPS site. Locates the bundle the same way curl/git do (`SSL_CERT_FILE`
  well-known paths via the `openssl-probe` crate); needs a single bundle *file* on the host (a
  hashed cert-directory-only system isn't supported). Useful once the server has a real CA-issued
  certificate instead of a pinned self-signed one, since it survives cert rotation without any
  manual re-pinning. Mutually exclusive with `--cert` (enforced as a startup error if both are
  given). Not wired into the Android client: its statically-linked OpenSSL has no OS trust-store
  path it can reach, so the flag would just fail closed there.

### Anti-abuse / server hardening knobs

- **`--max-half-open-connections`** (default 4, was picoquic's stock default of 64). picoquic
  starts demanding a cheap Retry-token round trip once concurrent half-open (unvalidated)
  connections hit this threshold, instead of running a full crypto handshake for each — an
  adaptive DoS defense. The stock default of 64 never engaged in practice on this
  single-threaded server: a burst of only ~5 simultaneous handshakes was already enough to
  monopolize the runtime thread and start refusing connections (upstream issues #71/#37). 4 was
  chosen empirically to engage right at that failure point while still clearing ordinary
  legitimate concurrency (a couple of users reconnecting at once, or a client's multipath
  resolver-path probes).
- **`--idle-timeout-seconds`** (default 60) and **`--max-connections`** (default 256, was 8) —
  straightforward connection-lifecycle tuning.
- **`--response-ttl-jitter`** — vary the answer TTL by `id % (jitter+1)` instead of a constant
  value, to avoid a constant-TTL fingerprint.
- **`--max-poll-qps`** (client) — caps DNS poll queries/sec to soften the query-rate signature at
  the cost of throughput. All of the above default to the historical/permissive behavior; nothing
  changes unless you opt in.

### recvmmsg/sendmmsg batched UDP I/O (Linux server)

The server's UDP hot path can batch multiple datagrams per `recvmmsg`/`sendmmsg` syscall instead of
one syscall per datagram (`crates/slipstream-server/src/mmsg.rs`, Linux-only). Measured ~1.5x server
CPU reduction under real mixed upload+download load — meaningfully more headroom before hitting the
single-threaded server's CPU-bound collapse point, though less than the syscall-count reduction
alone would suggest, since a large share of the remaining cost is per-packet QUIC/crypto processing
that batching doesn't touch. An `SLIPSTREAM_RECVMMSG_BATCH` environment variable is available as an
ops escape hatch to shrink the batch size (down to `1` to effectively disable batching) without a
rebuild, in case it ever needs to be killed in the field.

### Direct SOCKS target with UDP-in-TCP relay

The server can terminate directly into a SOCKS proxy and relay UDP payloads over the TCP-based SOCKS
channel (`--direct-socks-target` / `--socks-proxy-target`), instead of only forwarding to a fixed
TCP target.

### Android integration

A JNI client bridge (`slipstream-client` exposes `extern "system" fn Java_...` entry points) so the
engine embeds directly into an Android VPN app (the companion `SlipstreamCLI` project) without a
subprocess, plus Android-specific hardening: best-effort `protect()`-based socket exemption from the
VPN tunnel, bounded/generation-guarded stop/restart so the native engine can't wedge the Android
service, and tuned carrier/pacing defaults for mobile radios.

### Stability fixes from real-world (mobile carrier) deployment

Fixed backpressure-driven lifecycle stalls, local TCP streams not closing on client EOF
(`crates/slipstream-client` half-close/reaper logic — see the `git log` for
`crates/slipstream-server/src/udp_fallback/forwarding.rs` and the client stream-close paths), a
significant UDP-carrier throughput/regression fix chain, orphaned native-thread reaping via
generation-guarded self-termination (a stuck packet-processing thread could previously get detached
and peg a CPU core indefinitely on stop/restart), and prompt shutdown-request handling during DNS
response processing. These came out of a long back-and-forth stabilizing the tunnel against a
specific ISP/mobile carrier rather than from synthetic testing.

### Misc protocol/perf work

Adaptive QNAME MTU override, compact QNAME upstream queries, a demand-driven poll-rate backoff and
CPU-throttle pair to stop the client pegging a core when a stream stalls with no progress, a
resolver-silence detector (flags a fully unresponsive resolver within seconds instead of relying on
slow app-level failure counting), and reduced idle client poll wakeups.

---

In short: upstream is the general-purpose engine; this fork layers on DNS-carrier fingerprint
diversity, a second (TCP) resolver transport, proper TLS verification options, server-side
anti-abuse and I/O-batching work, an Android embedding path, and a long round of stability hardening
driven by testing against a real, imperfect mobile network rather than a lab loopback.

## Quick start (local dev)

Prereqs:

- Rust toolchain (stable)
- cmake, pkg-config
- OpenSSL headers and libs
- python3 (for interop and benchmark scripts)

Initialize the picoquic submodule:

```
git submodule update --init --recursive
```

On non-Windows hosts, `cargo build` will auto-build picoquic via
`./scripts/build_picoquic.sh` when libs are missing (outputs to
`.picoquic-build/`). For Windows MSVC targets, dot-source the helper in the
same PowerShell session before building with Cargo. Use
`. ./scripts/build_picoquic_windows.ps1` for x86_64, or pass `-Platform ARM64`
for ARM64. See `docs/build.md` for details.

Build the Rust binaries:

```
cargo build -p slipstream-client -p slipstream-server
```

Generate a test TLS cert (optional example):

```
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=slipstream"
```

Run the server:

```
cargo run -p slipstream-server -- \
  --dns-listen-port 8853 \
  --target-address 127.0.0.1:5201 \
  --domain example.com \
  --cert ./cert.pem \
  --key ./key.pem \
  --reset-seed ./reset-seed
```

If the configured cert/key paths do not exist, the server auto-generates a
self-signed ECDSA P-256 certificate (1000-year validity). If `--reset-seed`
is omitted, the server will warn and stateless reset tokens will not persist
across restarts.

Run the client:

```
cargo run -p slipstream-client -- \
  --tcp-listen-port 7000 \
  --resolver 127.0.0.1:8853 \
  --domain example.com
```

Use DNS-over-TCP between the client and resolver when UDP is shaped or blocked:

```
cargo run -p slipstream-client -- \
  --tcp-listen-port 7000 \
  --resolver 1.1.1.1:53 \
  --resolver-transport tcp \
  --domain example.com
```

TCP resolver transport intentionally uses only the first resolver path.

Verify the server's certificate against the OS trust store instead of trusting it blindly (needs a
real CA-issued server certificate, not the auto-generated self-signed one above):

```
cargo run -p slipstream-client -- \
  --tcp-listen-port 7000 \
  --resolver 1.1.1.1:53 \
  --domain example.com \
  --verify-system-ca
```

### JSON config file

Instead of passing every setting as a flag, the client can load a JSON config
file. Fields are flat and map 1:1 onto the CLI (there is no xray-style
inbound/outbound/routing model — the client is a single fixed tunnel). Omitted
fields use the built-in defaults, and any CLI flag you also pass overrides the
corresponding file value (precedence: defaults < file < CLI):

```
cargo run -p slipstream-client -- --config client.json
```

See [docs/client.example.json](docs/client.example.json) for a full example.
`--config` is standalone from the SIP003 environment path.

Note: You can also run the client against a resolver that forwards to the server. For local testing, see the interop docs.

## Production note: conntrack for UDP/53

For a public `slipstream-server` on port 53, tune conntrack above many distro defaults.

Recommended baseline:

```conf
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_udp_timeout = 15
net.netfilter.nf_conntrack_udp_timeout_stream = 60
```

Sizing tiers:

- 1 GB RAM: `131072`
- 2-4 GB RAM: `262144`
- 8 GB+ RAM: `524288`

Keep steady-state `conntrack -C` below about 60% of `nf_conntrack_max`.

Also worth tuning on a busy box: `--max-half-open-connections` (see above) and, if serving heavy
UDP load on Linux, leaving recvmmsg batching at its default (or raising `SLIPSTREAM_RECVMMSG_BATCH`)
rather than disabling it.

## Benchmarks (local snapshot)

All results below are end-to-end completion times in seconds (lower is better),
averaged over 5 runs on local loopback. Payload: 10 MiB in each direction.
Variants are dnstt, C-C slipstream, Rust-Rust (non-auth), and Rust-Rust (auth
via `--authoritative <resolver>`).

See `scripts/bench` for scripts used for obtaining these results.

| Variant                              | Exfil avg (s) | Download avg (s) |
|--------------------------------------| ---: | ---: |
| dnstt                                | 16.207 | 2.492 |
| slipstream (C)                       | 5.332 | 1.096 |
| slipstream-rust                      | 3.249 | 0.978 |
| slipstream-rust (Authoritative mode) | 1.602 | 0.407 |

![Throughput bar chart](.github/throughput.png)

## Documentation

- docs/README.md for the doc index
- docs/build.md for build prerequisites and picoquic setup
- docs/usage.md for CLI usage
- docs/config.md for environment variables and tuning knobs
- docs/protocol.md for DNS encapsulation notes (**note:** predates the multi-qtype carrier work
  above — it still describes the original TXT-only wire format in detail; the codec source in
  `crates/slipstream-dns/src/codec.rs` is the current source of truth for the other seven types)
- docs/dns-codec.md for codec behavior and vectors
- docs/picoquic-changes.md for tracked local picoquic patches and why they're needed
- docs/interop.md for local harnesses and interop
- docs/benchmarks.md for benchmarking harnesses
- docs/benchmarks-results.md for benchmark results
- docs/profiling.md for profiling notes
- docs/design.md for architecture notes

## Repo layout

- crates/      Rust workspace crates
- docs/        Public docs and internal design notes
- fixtures/    Golden DNS vectors
- scripts/     Interop and benchmark harnesses
- tools/       Vector generator and helpers
- vendor/      picoquic submodule

## License

Apache-2.0. See LICENSE.
