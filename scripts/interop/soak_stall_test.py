#!/usr/bin/env python3
"""
Soak test: realistic parallel traffic through a real slipstream-client/slipstream-server pair,
with the resolver periodically going completely silent (via udp_capture_proxy.py's blackout
mode), for several minutes. Complements the fast in-process Rust regression test
(crates/slipstream-client/src/stall_shutdown_tests.rs), which proves the shutdown-check
mechanism is bounded under one synthetic backlog snapshot -- this instead exercises the whole
real stack (real QUIC handshake/reconnect, real DNS-tunnel pacing, real OS process teardown)
under sustained conditions closer to the vaydns-debug production incident (repeated resolver
stalls over a long-running session) than a single fast unit test can.

The bare slipstream-client CLI treats a silent resolver as fatal and exits rather than
reconnecting internally (that's deliberately the Android service's job in production -- see
resolver_silent_e2e.rs). This script plays that supervisor role: it restarts the client whenever
it exits, and measures how long each detect -> exit -> restart -> ready cycle takes, mirroring
the app's `recovery#N` cycle without needing a phone.

Usage (quick smoke run, ~70s):
    python3 scripts/interop/soak_stall_test.py --duration-s 70 --blackout-interval-s 30 \\
        --blackout-duration-s 10 --sessions 8

Usage (full 10-minute soak, ~40 blackout cycles like the "40 recoveries a day" report):
    python3 scripts/interop/soak_stall_test.py --duration-s 600 --blackout-interval-s 90 \\
        --blackout-duration-s 15 --sessions 20
"""

import argparse
import json
import os
import random
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--duration-s", type=float, default=600.0, help="Total soak duration (default: 10 minutes)")
    parser.add_argument("--blackout-interval-s", type=float, default=90.0, help="Seconds between blackout starts")
    parser.add_argument("--blackout-duration-s", type=float, default=15.0, help="Length of each blackout window")
    parser.add_argument("--sessions", type=int, default=20, help="Parallel traffic-generator workers")
    parser.add_argument("--payload-bytes", type=int, default=4096, help="Bytes per echoed request")
    parser.add_argument("--request-timeout-s", type=float, default=6.0, help="Per-request timeout")
    parser.add_argument("--min-pause-s", type=float, default=0.2, help="Min pause between a session's requests")
    parser.add_argument("--max-pause-s", type=float, default=1.5, help="Max pause between a session's requests")
    parser.add_argument("--delay-ms", type=float, default=25.0, help="Baseline resolver-path delay injected by the proxy")
    parser.add_argument("--jitter-ms", type=float, default=15.0, help="Resolver-path jitter injected by the proxy")
    parser.add_argument("--skip-build", action="store_true", help="Skip `cargo build`; assume binaries are current")
    parser.add_argument("--out-dir", default=None, help="Directory for logs (default: a fresh temp-ish dir under target/soak-logs)")
    parser.add_argument("--recovery-warn-s", type=float, default=None,
                         help="Warn if a blackout's recovery (first successful request after it ends) takes "
                         "longer than this. Default: blackout-duration-s * 2 + 20s.")
    return parser.parse_args()


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def pick_free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ProcGroup:
    """Tracks every subprocess we start so cleanup is a single, unmissable sweep."""

    def __init__(self) -> None:
        self.procs: List[subprocess.Popen] = []
        self._lock = threading.Lock()

    def add(self, proc: subprocess.Popen) -> subprocess.Popen:
        with self._lock:
            self.procs.append(proc)
        return proc

    def killall(self) -> None:
        with self._lock:
            procs = list(self.procs)
        for proc in procs:
            if proc.poll() is None:
                try:
                    proc.terminate()
                except OSError:
                    pass
        deadline = time.monotonic() + 5.0
        for proc in procs:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    pass


def cargo_build(root: Path) -> None:
    print("[soak] building slipstream-client + slipstream-server (release skipped, debug build)...", file=sys.stderr)
    status = subprocess.run(
        ["cargo", "build", "-p", "slipstream-client", "-p", "slipstream-server"],
        cwd=str(root),
        check=False,
    )
    if status.returncode != 0:
        raise SystemExit(f"cargo build failed with exit code {status.returncode}")


def bin_path(root: Path, name: str) -> Path:
    path = root / "target" / "debug" / name
    if os.name == "nt":
        path = path.with_suffix(".exe")
    return path


@dataclass
class RequestResult:
    ts: float
    ok: bool
    latency_s: Optional[float]


@dataclass
class Stats:
    lock: threading.Lock = field(default_factory=threading.Lock)
    results: List[RequestResult] = field(default_factory=list)

    def record(self, ts: float, ok: bool, latency_s: Optional[float]) -> None:
        with self.lock:
            self.results.append(RequestResult(ts, ok, latency_s))

    def snapshot(self) -> List[RequestResult]:
        with self.lock:
            return list(self.results)


def traffic_worker(
    session_id: int,
    tcp_port: int,
    payload_bytes: int,
    timeout_s: float,
    min_pause: float,
    max_pause: float,
    stats: Stats,
    stop_event: threading.Event,
) -> None:
    rng = random.Random(session_id * 7919 + 1)
    payload = bytes((session_id + i) % 256 for i in range(payload_bytes))
    while not stop_event.is_set():
        start = time.time()
        ok = False
        latency: Optional[float] = None
        try:
            with socket.create_connection(("127.0.0.1", tcp_port), timeout=timeout_s) as sock:
                sock.settimeout(timeout_s)
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                received = bytearray()
                while len(received) < len(payload):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
                ok = bytes(received) == payload
                latency = time.time() - start
        except OSError:
            ok = False
        stats.record(start, ok, latency)
        stop_event.wait(rng.uniform(min_pause, max_pause))


class ClientSupervisor:
    """Restarts slipstream-client whenever it exits -- the bare CLI treats a silent resolver as
    fatal and exits by design (see resolver_silent_e2e.rs), so something has to play the
    Android service's role of respawning it. Also logs each detect->exit->respawn->ready cycle,
    which is the process-level analog of the app's `recovery#N`."""

    def __init__(self, client_bin: Path, args: List[str], env: dict, log_path: Path, procs: ProcGroup) -> None:
        self.client_bin = client_bin
        self.args = args
        self.env = env
        self.log_path = log_path
        self.procs = procs
        self.stop_event = threading.Event()
        self.cycles: List[dict] = []
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="client-supervisor", daemon=True)
        self.ready_event = threading.Event()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self._thread.join(timeout=15.0)

    def _run(self) -> None:
        first = True
        with open(self.log_path, "a", encoding="utf-8") as log_fp:
            while not self.stop_event.is_set():
                cycle_start = time.monotonic()
                self.ready_event.clear()
                proc = subprocess.Popen(
                    [str(self.client_bin), *self.args],
                    stdout=log_fp,
                    stderr=subprocess.STDOUT,
                    env=self.env,
                )
                self.procs.add(proc)
                became_ready = self._wait_for_ready(timeout=10.0)
                ready_at = time.monotonic()
                if became_ready:
                    self.ready_event.set()
                if not first:
                    with self._lock:
                        self.cycles.append(
                            {
                                "restarted_at": cycle_start,
                                "became_ready": became_ready,
                                "ready_latency_s": (ready_at - cycle_start) if became_ready else None,
                            }
                        )
                first = False

                while proc.poll() is None and not self.stop_event.is_set():
                    time.sleep(0.1)
                if self.stop_event.is_set():
                    if proc.poll() is None:
                        try:
                            proc.terminate()
                            proc.wait(timeout=5.0)
                        except (OSError, subprocess.TimeoutExpired):
                            try:
                                proc.kill()
                            except OSError:
                                pass
                    return
                # Client exited on its own (fatal resolver_silent, or a crash) -- respawn.
                time.sleep(0.2)

    def _wait_for_ready(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
                if "Connection ready" in text:
                    return True
            except OSError:
                pass
            time.sleep(0.1)
        return False


def tail_contains(path: Path, needle: str) -> int:
    if not path.exists():
        return 0
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    return text.count(needle)


def main() -> int:
    args = parse_args()
    root = workspace_root()
    cert = root / "fixtures" / "certs" / "cert.pem"
    key = root / "fixtures" / "certs" / "key.pem"
    if not cert.exists() or not key.exists():
        print(f"missing fixtures at {cert} / {key}", file=sys.stderr)
        return 2

    if not args.skip_build:
        cargo_build(root)
    server_bin = bin_path(root, "slipstream-server")
    client_bin = bin_path(root, "slipstream-client")
    if not server_bin.exists() or not client_bin.exists():
        print("binaries missing after build -- pass --skip-build only if they already exist", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir) if args.out_dir else root / "target" / "soak-logs" / str(int(time.time()))
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[soak] logs under {out_dir}", file=sys.stderr)

    echo_port = pick_free_port()
    dns_upstream_port = pick_free_udp_port()
    dns_proxy_port = pick_free_udp_port()
    tcp_client_port = pick_free_port()
    domain = "test.example.com"

    procs = ProcGroup()
    try:
        echo_log = open(out_dir / "echo.log", "w", encoding="utf-8")
        echo_proc = procs.add(
            subprocess.Popen(
                [sys.executable, str(Path(__file__).parent / "tcp_echo.py"), "--listen", f"127.0.0.1:{echo_port}"],
                stdout=echo_log,
                stderr=subprocess.STDOUT,
            )
        )

        server_log = open(out_dir / "server.log", "w", encoding="utf-8")
        server_env = dict(os.environ, RUST_LOG="info")
        server_proc = procs.add(
            subprocess.Popen(
                [
                    str(server_bin),
                    "--dns-listen-host", "127.0.0.1",
                    "--dns-listen-port", str(dns_upstream_port),
                    "--target-address", f"127.0.0.1:{echo_port}",
                    "--domain", domain,
                    "--cert", str(cert),
                    "--key", str(key),
                ],
                stdout=server_log,
                stderr=subprocess.STDOUT,
                env=server_env,
            )
        )
        time.sleep(0.3)
        if server_proc.poll() is not None:
            print("slipstream-server exited immediately -- check server.log", file=sys.stderr)
            return 2

        proxy_log = out_dir / "proxy.jsonl"
        proxy_stderr = open(out_dir / "proxy.stderr.log", "w", encoding="utf-8")
        # Anchor for the blackout schedule: udp_capture_proxy.py times its own blackout windows
        # from ITS process start, which happens here -- not from soak_start below (captured only
        # once the client is already up and traffic is flowing). Using the wrong epoch silently
        # shifts every "recovery after blackout" calculation by however long startup took.
        proxy_start_monotonic = time.monotonic()
        proxy_start_wall = time.time()
        proxy_proc = procs.add(
            subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).parent / "udp_capture_proxy.py"),
                    "--listen", f"127.0.0.1:{dns_proxy_port}",
                    "--upstream", f"127.0.0.1:{dns_upstream_port}",
                    "--delay-ms", str(args.delay_ms),
                    "--jitter-ms", str(args.jitter_ms),
                    "--blackout-interval-s", str(args.blackout_interval_s),
                    "--blackout-duration-s", str(args.blackout_duration_s),
                    "--log", str(proxy_log),
                ],
                stdout=proxy_stderr,
                stderr=subprocess.STDOUT,
            )
        )
        time.sleep(0.3)
        if proxy_proc.poll() is not None:
            print("udp_capture_proxy exited immediately -- check proxy.stderr.log", file=sys.stderr)
            return 2

        client_env = dict(os.environ, RUST_LOG="info")
        client_args = [
            "--tcp-listen-port", str(tcp_client_port),
            "--resolver", f"127.0.0.1:{dns_proxy_port}",
            "--domain", domain,
            "--cert", str(cert),
        ]
        supervisor = ClientSupervisor(client_bin, client_args, client_env, out_dir / "client.log", procs)
        supervisor.start()
        if not supervisor._wait_for_ready(timeout=15.0):
            print("client never became ready -- check client.log", file=sys.stderr)
            return 2

        stats = Stats()
        stop_event = threading.Event()
        workers = [
            threading.Thread(
                target=traffic_worker,
                args=(i, tcp_client_port, args.payload_bytes, args.request_timeout_s,
                      args.min_pause_s, args.max_pause_s, stats, stop_event),
                daemon=True,
            )
            for i in range(args.sessions)
        ]
        for w in workers:
            w.start()

        soak_start = time.monotonic()
        print(f"[soak] running for {args.duration_s:.0f}s with blackouts every {args.blackout_interval_s:.0f}s "
              f"({args.blackout_duration_s:.0f}s each)...", file=sys.stderr)
        last_report = soak_start
        while time.monotonic() - soak_start < args.duration_s:
            time.sleep(1.0)
            now = time.monotonic()
            if now - last_report >= 30.0:
                snap = stats.snapshot()
                recent = [r for r in snap if r.ts >= time.time() - 30.0]
                ok_count = sum(1 for r in recent if r.ok)
                print(
                    f"[soak] t={now - soak_start:.0f}s requests(last30s)={len(recent)} "
                    f"ok={ok_count} restarts_so_far={len(supervisor.cycles)}",
                    file=sys.stderr,
                )
                last_report = now

        traffic_stop_wall = time.time()
        stop_event.set()
        for w in workers:
            w.join(timeout=args.request_timeout_s + 2.0)

        stop_started = time.monotonic()
        supervisor.stop()
        supervisor_stop_elapsed = time.monotonic() - stop_started

        # ---- Report ----
        results = sorted(stats.snapshot(), key=lambda r: r.ts)
        total = len(results)
        ok_total = sum(1 for r in results if r.ok)
        latencies = [r.latency_s for r in results if r.ok and r.latency_s is not None]

        recovery_warn_s = args.recovery_warn_s
        if recovery_warn_s is None:
            recovery_warn_s = args.blackout_duration_s * 2 + 20.0

        # Blackout offsets are relative to the PROXY's own start (it schedules blackouts from its
        # own process-start monotonic clock), which predates soak_start by however long server +
        # proxy + client-ready startup took -- not relative to soak_start. Only consider windows
        # that ended early enough to have had a full recovery_warn_s of traffic-generation time
        # left to observe a recovery in -- otherwise a blackout near the very end of the run gets
        # unfairly flagged "never recovered" just because we stopped watching, not because
        # anything was actually wrong.
        blackout_starts = []
        t = args.blackout_interval_s
        while args.blackout_interval_s > 0:
            window_end_wall = proxy_start_wall + t + args.blackout_duration_s
            if window_end_wall + recovery_warn_s > traffic_stop_wall:
                break
            blackout_starts.append(t)
            t += args.blackout_interval_s

        recovery_reports = []
        for offset in blackout_starts:
            window_end_wall = proxy_start_wall + offset + args.blackout_duration_s
            first_ok_after = next((r for r in results if r.ts >= window_end_wall and r.ok), None)
            recovery_s = (first_ok_after.ts - window_end_wall) if first_ok_after else None
            recovery_reports.append({"blackout_offset_s": offset, "recovery_s": recovery_s})

        resolver_silent_hits = tail_contains(out_dir / "client.log", "resolver_silent")
        panics = tail_contains(out_dir / "client.log", "panicked")

        print("\n=== soak_stall_test report ===", file=sys.stderr)
        print(f"requests: {total}, ok: {ok_total} ({(ok_total / total * 100.0) if total else 0.0:.1f}%)",
              file=sys.stderr)
        if latencies:
            print(
                f"latency ok(s): min={min(latencies):.3f} median={statistics.median(latencies):.3f} "
                f"p95={sorted(latencies)[int(len(latencies) * 0.95)]:.3f} max={max(latencies):.3f}",
                file=sys.stderr,
            )
        print(f"client restarts observed: {len(supervisor.cycles)}", file=sys.stderr)
        for cycle in supervisor.cycles:
            if not cycle["became_ready"]:
                print(f"  restart at t={cycle['restarted_at'] - soak_start:.1f}s NEVER became ready", file=sys.stderr)
        print(f"resolver_silent log hits: {resolver_silent_hits}", file=sys.stderr)
        print(f"panics in client log: {panics}", file=sys.stderr)
        print(f"final client stop (supervisor.stop) took {supervisor_stop_elapsed:.2f}s", file=sys.stderr)
        print("recovery after each blackout (time to first successful request once the window ends):",
              file=sys.stderr)
        failed_recoveries = 0
        slow_recoveries = 0
        for rep in recovery_reports:
            if rep["recovery_s"] is None:
                failed_recoveries += 1
                print(f"  blackout@{rep['blackout_offset_s']:.0f}s: NEVER recovered", file=sys.stderr)
            else:
                flag = ""
                if rep["recovery_s"] > recovery_warn_s:
                    slow_recoveries += 1
                    flag = f"  <-- exceeds warn threshold {recovery_warn_s:.0f}s"
                print(f"  blackout@{rep['blackout_offset_s']:.0f}s: recovered in {rep['recovery_s']:.1f}s{flag}",
                      file=sys.stderr)

        verdict_ok = (
            total > 0
            and panics == 0
            and failed_recoveries == 0
            and slow_recoveries == 0
            and supervisor_stop_elapsed < 12.0
        )
        print(f"\nVERDICT: {'PASS' if verdict_ok else 'FAIL'}", file=sys.stderr)
        (out_dir / "summary.json").write_text(
            json.dumps(
                {
                    "total_requests": total,
                    "ok_requests": ok_total,
                    "restarts": len(supervisor.cycles),
                    "resolver_silent_hits": resolver_silent_hits,
                    "panics": panics,
                    "final_stop_s": supervisor_stop_elapsed,
                    "recoveries": recovery_reports,
                    "verdict": "PASS" if verdict_ok else "FAIL",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return 0 if verdict_ok else 1
    finally:
        procs.killall()


if __name__ == "__main__":
    raise SystemExit(main())
