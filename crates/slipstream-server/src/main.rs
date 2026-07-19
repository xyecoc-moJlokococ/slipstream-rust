mod buf_pool;
mod config;
#[cfg(target_os = "linux")]
mod mmsg;
mod multi_worker;
mod server;
mod socks_target;
mod streams;
mod target;
mod udp_fallback;

use clap::{parser::ValueSource, CommandFactory, FromArgMatches, Parser};
use server::{run_server, ServerConfig};
use slipstream_core::{
    cli::{exit_with_error, exit_with_message, init_logging, unwrap_or_exit},
    normalize_domain, parse_host_port, parse_host_port_parts, sip003, AddressKind, HostPort,
};
use tokio::runtime::Builder;

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-server",
    about = "slipstream-server - A high-performance covert channel over DNS (server)"
)]
struct Args {
    #[arg(long = "dns-listen-host", default_value = "::")]
    dns_listen_host: String,
    #[arg(long = "dns-listen-port", short = 'l', default_value_t = 53)]
    dns_listen_port: u16,
    #[arg(
        long = "target-address",
        short = 'a',
        default_value = "127.0.0.1:5201",
        value_parser = parse_target_address
    )]
    target_address: HostPort,
    #[arg(long = "fallback", value_name = "HOST:PORT", value_parser = parse_fallback_address)]
    fallback: Option<HostPort>,
    #[arg(long = "cert", short = 'c', value_name = "PATH")]
    cert: Option<String>,
    #[arg(long = "key", short = 'k', value_name = "PATH")]
    key: Option<String>,
    #[arg(long = "reset-seed", value_name = "PATH")]
    reset_seed: Option<String>,
    #[arg(long = "domain", short = 'd', value_parser = parse_domain)]
    domains: Vec<String>,
    #[arg(long = "max-connections", default_value_t = 256, value_parser = parse_max_connections)]
    max_connections: u32,
    /// Concurrent half-open (unvalidated) connections tolerated before picoquic starts requiring a
    /// cheap Retry-token round-trip instead of a full crypto handshake for new connections (an
    /// adaptive, self-adjusting DoS defense). picoquic's built-in default is 64, which is far too
    /// high to help on this single-threaded server: a small burst of simultaneous handshakes can
    /// monopolize the one runtime thread and starve the TCP accept loop, dropping/refusing
    /// concurrent connection attempts (upstream issues #71/#37).
    ///
    /// picoquic starts demanding a Retry for a new initial once `current_number_half_open >=
    /// threshold` (vendor/picoquic packet.c), so to actually engage at the empirically reproduced
    /// ~5-concurrent failure point the default must be <= 5. 4 makes the defense kick in on the 5th
    /// simultaneous handshake (4 already half-open) while still clearing ordinary legitimate
    /// concurrency -- a couple of users reconnecting at once or a client's multipath resolver-path
    /// probes (~2-3 connections) -- so those don't pay an extra retry RTT. A default of 8 (or any
    /// value > 5) would leave the defense inert at exactly the load that triggered the bug. It is
    /// configurable (CLI --max-half-open-connections or the SIP003 `max-half-open-connections`
    /// plugin option) so ops can raise it if legitimate concurrency is higher, or lower it further,
    /// without a rebuild.
    #[arg(long = "max-half-open-connections", default_value_t = 4, value_parser = parse_max_half_open_connections)]
    max_half_open_connections: u32,
    #[arg(long = "idle-timeout-seconds", default_value_t = 60)]
    idle_timeout_seconds: u64,
    #[arg(long = "debug-streams")]
    debug_streams: bool,
    #[arg(long = "debug-commands")]
    debug_commands: bool,
    #[arg(long = "direct-socks-target")]
    direct_socks_target: bool,
    #[arg(long = "socks-proxy-target")]
    socks_proxy_target: bool,
    /// Base answer TTL (seconds) in DNS responses (default 60). Anti-fingerprinting knob.
    #[arg(long = "response-ttl", default_value_t = 60)]
    response_ttl: u32,
    /// If > 0, vary the answer TTL by id%(jitter+1) so it isn't constant (default 0).
    #[arg(long = "response-ttl-jitter", default_value_t = 0)]
    response_ttl_jitter: u32,
    /// Extra DNS query type to accept for tunnel queries, beyond the types already supported
    /// unconditionally (TXT/HTTPS/A/AAAA/CNAME/MX/SRV/NULL -- the client's --dns-query-type just
    /// needs to be one of those, no server config needed). Only useful for allowing some other,
    /// not-yet-implemented type without a code change.
    #[arg(long = "accepted-query-type", default_value_t = 16)]
    accepted_query_type: u16,
    /// Number of independent server worker threads (each with its own picoquic context).
    /// Default 1 preserves the historical single-threaded path. Values >1 enable userspace
    /// demux by source IP so DNS/QUIC CPU scales across cores for multi-client load. Do not use
    /// kernel SO_REUSEPORT alone for this — client/resolver source-port spray would split one
    /// QUIC connection across workers. SIP003 option: `workers`.
    #[arg(long = "workers", default_value_t = 1, value_parser = parse_workers)]
    workers: usize,
}

fn main() {
    init_logging();
    let matches = Args::command().get_matches();
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
    let sip003_env = unwrap_or_exit(sip003::read_sip003_env(), "SIP003 env error", 2);
    if sip003_env.is_present() {
        tracing::info!("SIP003 env detected; applying SS_* overrides with CLI precedence");
    }

    let dns_listen_host_provided = cli_provided(&matches, "dns_listen_host");
    let dns_listen_port_provided = cli_provided(&matches, "dns_listen_port");
    let (dns_listen_host, dns_listen_port) = unwrap_or_exit(
        sip003::select_host_port(
            &args.dns_listen_host,
            args.dns_listen_port,
            dns_listen_host_provided,
            dns_listen_port_provided,
            sip003_env.remote_host.as_deref(),
            sip003_env.remote_port.as_deref(),
            "SS_REMOTE",
        ),
        "SIP003 env error",
        2,
    );

    let sip003_local = if cli_provided(&matches, "target_address") {
        None
    } else {
        unwrap_or_exit(
            sip003::parse_endpoint(
                sip003_env.local_host.as_deref(),
                sip003_env.local_port.as_deref(),
                "SS_LOCAL",
            ),
            "SIP003 env error",
            2,
        )
    };
    let target_address = if let Some(endpoint) = &sip003_local {
        unwrap_or_exit(
            parse_host_port_parts(&endpoint.host, endpoint.port, AddressKind::Target),
            "SIP003 env error",
            2,
        )
    } else {
        args.target_address.clone()
    };
    let fallback_address = if cli_provided(&matches, "fallback") {
        args.fallback.clone()
    } else {
        sip003::last_option_value(&sip003_env.plugin_options, "fallback")
            .map(|value| unwrap_or_exit(parse_fallback_address(&value), "SIP003 env error", 2))
    };

    let domains = if !args.domains.is_empty() {
        args.domains.clone()
    } else {
        let option_domains = unwrap_or_exit(
            parse_domains_from_options(&sip003_env.plugin_options),
            "SIP003 env error",
            2,
        );
        if option_domains.is_empty() {
            exit_with_message("At least one domain is required", 2);
        }
        option_domains
    };

    let cert = if let Some(cert) = args.cert.clone() {
        cert
    } else if let Some(cert) = sip003::last_option_value(&sip003_env.plugin_options, "cert") {
        cert
    } else {
        exit_with_message("A certificate path is required", 2);
    };

    let key = if let Some(key) = args.key.clone() {
        key
    } else if let Some(key) = sip003::last_option_value(&sip003_env.plugin_options, "key") {
        key
    } else {
        exit_with_message("A key path is required", 2);
    };
    let reset_seed_path = if let Some(path) = args.reset_seed.clone() {
        Some(path)
    } else {
        sip003::last_option_value(&sip003_env.plugin_options, "reset-seed")
    };
    let max_connections = if cli_provided(&matches, "max_connections") {
        args.max_connections
    } else if let Some(value) =
        sip003::last_option_value(&sip003_env.plugin_options, "max-connections")
    {
        unwrap_or_exit(parse_max_connections(&value), "SIP003 env error", 2)
    } else {
        args.max_connections
    };
    // Threaded through the SIP003 plugin-options path just like max-connections above: under a
    // SIP003 plugin manager the operator has no CLI, so without this branch the half-open retry
    // threshold would be stuck at its default in exactly the deployment mode where production
    // tuning happens (see #71/#37 review).
    let max_half_open_connections = if cli_provided(&matches, "max_half_open_connections") {
        args.max_half_open_connections
    } else if let Some(value) =
        sip003::last_option_value(&sip003_env.plugin_options, "max-half-open-connections")
    {
        unwrap_or_exit(
            parse_max_half_open_connections(&value),
            "SIP003 env error",
            2,
        )
    } else {
        args.max_half_open_connections
    };

    let workers = if cli_provided(&matches, "workers") {
        args.workers
    } else if let Some(value) = sip003::last_option_value(&sip003_env.plugin_options, "workers") {
        unwrap_or_exit(parse_workers(&value), "SIP003 env error", 2)
    } else {
        args.workers
    };

    let config = ServerConfig {
        dns_listen_host,
        dns_listen_port,
        target_address,
        fallback_address,
        cert,
        key,
        reset_seed_path,
        domains,
        max_connections,
        max_half_open_connections,
        idle_timeout_seconds: args.idle_timeout_seconds,
        debug_streams: args.debug_streams,
        debug_commands: args.debug_commands,
        direct_socks_target: args.direct_socks_target,
        socks_proxy_target: args.socks_proxy_target,
        response_ttl: args.response_ttl,
        response_ttl_jitter: args.response_ttl_jitter,
        accepted_query_type: args.accepted_query_type,
        workers,
    };

    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed to build Tokio runtime");
    match runtime.block_on(run_server(&config)) {
        Ok(code) => std::process::exit(code),
        Err(err) => exit_with_error("Server error", err, 1),
    }
}

fn parse_domain(input: &str) -> Result<String, String> {
    normalize_domain(input).map_err(|err| err.to_string())
}

fn parse_target_address(input: &str) -> Result<HostPort, String> {
    parse_host_port(input, 5201, AddressKind::Target).map_err(|err| err.to_string())
}

fn parse_fallback_address(input: &str) -> Result<HostPort, String> {
    let parsed = parse_host_port(input, 0, AddressKind::Fallback).map_err(|err| err.to_string())?;
    if parsed.port == 0 {
        return Err("fallback address must include a port".to_string());
    }
    Ok(parsed)
}

fn parse_max_connections(input: &str) -> Result<u32, String> {
    let trimmed = input.trim();
    let value = trimmed
        .parse::<u32>()
        .map_err(|_| format!("Invalid max-connections value: {}", trimmed))?;
    if value == 0 {
        return Err("max-connections must be at least 1".to_string());
    }
    Ok(value)
}

fn parse_max_half_open_connections(input: &str) -> Result<u32, String> {
    let trimmed = input.trim();
    let value = trimmed
        .parse::<u32>()
        .map_err(|_| format!("Invalid max-half-open-connections value: {}", trimmed))?;
    // 0 would force a Retry-token round-trip on every single connection (adding an RTT even to the
    // common isolated-client case), which is what cookie_mode's force-retry bit is for; require at
    // least 1 so this knob only ever engages once concurrency actually appears.
    if value == 0 {
        return Err("max-half-open-connections must be at least 1".to_string());
    }
    Ok(value)
}

fn parse_workers(input: &str) -> Result<usize, String> {
    let trimmed = input.trim();
    let value = trimmed
        .parse::<usize>()
        .map_err(|_| format!("Invalid workers value: {}", trimmed))?;
    if value == 0 {
        return Err("workers must be at least 1".to_string());
    }
    // Soft cap: more than a few dozen picoquic contexts is almost never useful on a VPS and
    // multiplies memory (cert/TLS tables per context). Raise via code if a real need appears.
    if value > 64 {
        return Err("workers must be at most 64".to_string());
    }
    Ok(value)
}

fn cli_provided(matches: &clap::ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

fn parse_domains_from_options(options: &[sip003::Sip003Option]) -> Result<Vec<String>, String> {
    let mut domains = None;
    for option in options {
        if option.key == "domain" {
            if domains.is_some() {
                return Err("SIP003 domain option must not be repeated".to_string());
            }
            let entries = sip003::split_list(&option.value).map_err(|err| err.to_string())?;
            let mut parsed = Vec::new();
            for entry in entries {
                let normalized = normalize_domain(&entry).map_err(|err| err.to_string())?;
                parsed.push(normalized);
            }
            domains = Some(parsed);
        }
    }
    Ok(domains.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The production default for the half-open retry threshold. If this changes, revisit the
    /// rationale documented on the `--max-half-open-connections` flag in `Args`.
    const EXPECTED_DEFAULT_MAX_HALF_OPEN: u32 = 4;

    fn parse_args(extra: &[&str]) -> Result<Args, clap::Error> {
        let mut argv = vec!["slipstream-server"];
        argv.extend_from_slice(extra);
        Args::try_parse_from(argv)
    }

    #[test]
    fn max_half_open_connections_defaults_to_expected() {
        let args = parse_args(&[]).expect("defaults parse");
        assert_eq!(
            args.max_half_open_connections,
            EXPECTED_DEFAULT_MAX_HALF_OPEN
        );
    }

    #[test]
    fn max_half_open_connections_flag_overrides_default() {
        let args = parse_args(&["--max-half-open-connections", "2"]).expect("flag parses");
        assert_eq!(args.max_half_open_connections, 2);
    }

    #[test]
    fn max_half_open_connections_rejects_zero() {
        let err =
            parse_args(&["--max-half-open-connections", "0"]).expect_err("zero must be rejected");
        assert!(
            err.to_string().contains("at least 1"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn max_half_open_connections_rejects_non_numeric() {
        assert!(parse_args(&["--max-half-open-connections", "abc"]).is_err());
    }

    #[test]
    fn parse_max_half_open_connections_validates_bounds() {
        assert_eq!(parse_max_half_open_connections("1"), Ok(1));
        assert_eq!(parse_max_half_open_connections("  16 "), Ok(16));
        assert!(parse_max_half_open_connections("0").is_err());
        assert!(parse_max_half_open_connections("nope").is_err());
    }

    #[test]
    fn workers_defaults_to_one() {
        let args = parse_args(&[]).expect("defaults parse");
        assert_eq!(args.workers, 1);
    }

    #[test]
    fn workers_flag_overrides_default() {
        let args = parse_args(&["--workers", "4"]).expect("flag parses");
        assert_eq!(args.workers, 4);
    }

    #[test]
    fn workers_rejects_zero_and_too_large() {
        assert!(parse_args(&["--workers", "0"]).is_err());
        assert!(parse_args(&["--workers", "65"]).is_err());
        assert_eq!(parse_workers("8"), Ok(8));
    }
}
