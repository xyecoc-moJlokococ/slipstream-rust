# Slipstream (Rust)

Slipstream is a high-performance DNS tunnel that carries QUIC packets over DNS queries and responses.
This repository hosts the Rust rewrite of the [original C implementation](https://github.com/EndPositive/slipstream).

## What is here

- slipstream-client and slipstream-server CLI binaries.
- A DNS codec crate with vector-based tests.
- picoquic FFI integration for multipath QUIC support.
- Fully async with tokio.
- And more! For a more up-to-date list of extra features, see the [merged PRs](https://github.com/Mygod/slipstream-rust/pulls?q=is%3Apr+is%3Amerged+label%3Aenhancement).

## Differences from upstream (Mygod/slipstream-rust)

This is a personal fork tracking [Mygod/slipstream-rust](https://github.com/Mygod/slipstream-rust)
(itself a rewrite of the [original C implementation](https://github.com/EndPositive/slipstream)).
On top of upstream, this fork adds:

- **DNS-over-TCP resolver transport.** The client can speak to the resolver over
  TCP instead of UDP (`--resolver-transport tcp`), for networks where UDP/53 is
  shaped, blocked, or otherwise unreliable. Includes upload/download pacing tuned
  specifically for the TCP path and a dedicated stabilization pass after early
  flapping was observed in the field.
- **HTTPS/SVCB (type 65) DNS carrier**, alongside the original TXT carrier. The
  tunnel payload rides in an opaque `ech` SvcParam per RFC 9460 — a less
  suspicious-looking record type than TXT under DPI. The server still accepts
  legacy TXT queries at the same time, so this is a migration-safe, opt-in
  upgrade (`--dns-query-type` / `--accepted-query-type`), not a breaking change.
- **Configurable anti-fingerprinting knobs**: DNS label length for the encoded
  subdomain (`--dns-label-length`), answer TTL and TTL jitter
  (`--response-ttl` / `--response-ttl-jitter`), and a poll-rate cap
  (`--max-poll-qps`) to soften the query-rate signature at the cost of some
  throughput. All default to the historical behavior — nothing changes unless
  you opt in.
- **Runtime transport/qtype auto-selection.** On connect (and on client network
  changes), the client can probe available transports/query types and pick the
  fastest one automatically instead of requiring a fixed config per network.
- **Direct SOCKS target with UDP-in-TCP relay.** The server can terminate
  directly into a SOCKS proxy and relay UDP payloads over the TCP-based SOCKS
  channel, instead of only forwarding to a fixed TCP target.
- **Android integration**: a JNI client bridge (`slipstream-client` exposes
  `extern "system" fn Java_...` entry points) so the engine embeds directly
  into an Android VPN app without a subprocess, plus Android-specific
  hardening — best-effort `protect()`-based socket exemption from the VPN
  tunnel, bounded/generation-guarded stop/restart so the native engine can't
  wedge the Android service, and tuned carrier/pacing defaults for mobile
  radios.
- **Stability fixes from real-world (mobile carrier) deployment**: fixed
  backpressure-driven lifecycle stalls, local TCP streams not closing on
  client EOF, and a significant UDP-carrier regression fix chain — these came
  out of a long back-and-forth stabilizing the tunnel against a specific
  ISP/mobile carrier rather than from synthetic testing.
- **Misc protocol/perf work**: adaptive QNAME MTU override, compact QNAME
  upstream queries, raw EDNS upstream encoding, parallel probe clients, and
  reduced idle client poll wakeups.

In short: upstream is the general-purpose engine; this fork layers on a
second (TCP) resolver transport, DPI-resistance knobs, an Android embedding
path, and a round of stability hardening driven by testing against a real,
imperfect mobile network rather than a lab loopback.

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
- docs/protocol.md for DNS encapsulation notes
- docs/dns-codec.md for codec behavior and vectors
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
