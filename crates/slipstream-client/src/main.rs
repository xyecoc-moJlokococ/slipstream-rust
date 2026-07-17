mod dns;
mod error;
mod pacing;
mod pinning;
mod platform;
mod runtime;
mod streams;
mod system_ca;

use clap::{parser::ValueSource, ArgGroup, CommandFactory, FromArgMatches, Parser, ValueEnum};
use serde::Deserialize;
use slipstream_core::{
    cli::{exit_with_error, exit_with_message, init_logging, unwrap_or_exit},
    normalize_domain, parse_host_port, parse_host_port_parts, sip003, AddressKind, HostPort,
};
use slipstream_ffi::{
    ClientConfig, ResolverMode, ResolverSpec, ResolverTransport, UpstreamEncoding,
};
use tokio::runtime::Builder;

use pacing::DEFAULT_PACING_GAIN_PROBE;
use runtime::run_client_with_control;
use runtime::DEFAULT_DNS_TCP_PACKET_LOOP_BURST;

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-client",
    about = "slipstream-client - A high-performance covert channel over DNS (client)",
    group(
        ArgGroup::new("resolvers")
            .multiple(true)
            .args(["resolver", "authoritative"])
    )
)]
struct Args {
    /// Load settings from a JSON config file. Fields omitted from the file use the built-in
    /// defaults; any CLI flag explicitly passed overrides the file. Standalone from SIP003.
    #[arg(long = "config", value_name = "PATH")]
    config: Option<String>,
    #[arg(long = "tcp-listen-host", default_value = "::")]
    tcp_listen_host: String,
    #[arg(long = "tcp-listen-port", short = 'l', default_value_t = 5201)]
    tcp_listen_port: u16,
    #[arg(long = "resolver", short = 'r', value_parser = parse_resolver)]
    resolver: Vec<HostPort>,
    #[arg(
        long = "congestion-control",
        short = 'c',
        value_parser = ["bbr", "dcubic"]
    )]
    congestion_control: Option<String>,
    #[arg(long = "authoritative", value_parser = parse_resolver)]
    authoritative: Vec<HostPort>,
    #[arg(
        short = 'g',
        long = "gso",
        num_args = 0..=1,
        default_value_t = false,
        default_missing_value = "true"
    )]
    gso: bool,
    #[arg(long = "domain", short = 'd', value_parser = parse_domain)]
    domain: Option<String>,
    #[arg(long = "cert", value_name = "PATH")]
    cert: Option<String>,
    /// Verify the server's certificate against the OS's default CA bundle (full chain + hostname
    /// check), like a normal HTTPS client. Mutually exclusive with --cert (leaf pinning).
    #[arg(long = "verify-system-ca")]
    verify_system_ca: bool,
    #[arg(long = "keep-alive-interval", short = 't', default_value_t = 400)]
    keep_alive_interval: u16,
    #[arg(long = "debug-poll")]
    debug_poll: bool,
    #[arg(long = "debug-streams")]
    debug_streams: bool,
    #[arg(long = "resolver-transport", value_enum, default_value_t = ResolverTransportArg::Udp)]
    resolver_transport: ResolverTransportArg,
    #[arg(long = "pacing-gain-probe", default_value_t = DEFAULT_PACING_GAIN_PROBE)]
    pacing_gain_probe: f64,
    #[arg(long = "dns-tcp-packet-loop-burst", default_value_t = DEFAULT_DNS_TCP_PACKET_LOOP_BURST)]
    dns_tcp_packet_loop_burst: usize,
    #[arg(long = "upstream-encoding", value_enum, default_value_t = UpstreamEncodingArg::Qname)]
    upstream_encoding: UpstreamEncodingArg,
    #[arg(long = "qname-mtu", default_value_t = 0)]
    qname_mtu: u32,
    /// DNS query type to send (default 16 = TXT). Purely a client choice; the server accepts every
    /// type it knows how to answer unconditionally, no matching server config needed.
    #[arg(long = "dns-query-type", default_value_t = 16)]
    dns_query_type: u16,
    /// Label length (chars, 1..=63) for the encoded subdomain (default 57). Client-only fingerprint knob.
    #[arg(long = "dns-label-length", default_value_t = 57)]
    dns_label_length: usize,
    /// Cap on DNS poll queries per second (0 = unlimited). Lowers the query-rate fingerprint at the cost of throughput.
    #[arg(long = "max-poll-qps", default_value_t = 0)]
    max_poll_qps: u32,
    /// Encode the tunnel payload with base64u instead of base32 (default false). ~20% denser, but
    /// case-sensitive -- only enable once the resolver path is confirmed to preserve label case
    /// end to end. Purely a client choice, no server config needed.
    #[arg(long = "base64u-encoding")]
    base64u_encoding: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ResolverTransportArg {
    Udp,
    Tcp,
}

impl From<ResolverTransportArg> for ResolverTransport {
    fn from(value: ResolverTransportArg) -> Self {
        match value {
            ResolverTransportArg::Udp => ResolverTransport::Udp,
            ResolverTransportArg::Tcp => ResolverTransport::Tcp,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum UpstreamEncodingArg {
    Qname,
    EdnsRaw,
}

impl From<UpstreamEncodingArg> for UpstreamEncoding {
    fn from(value: UpstreamEncodingArg) -> Self {
        match value {
            UpstreamEncodingArg::Qname => UpstreamEncoding::Qname,
            UpstreamEncodingArg::EdnsRaw => UpstreamEncoding::EdnsRaw,
        }
    }
}

fn main() {
    init_logging();
    let matches = Args::command().get_matches();
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());

    if let Some(path) = args.config.clone() {
        run_from_config_file(&path, &args, &matches);
    }

    let sip003_env = unwrap_or_exit(sip003::read_sip003_env(), "SIP003 env error", 2);
    if sip003_env.is_present() {
        tracing::info!("SIP003 env detected; applying SS_* overrides with CLI precedence");
    }

    let tcp_listen_host_provided = cli_provided(&matches, "tcp_listen_host");
    let tcp_listen_port_provided = cli_provided(&matches, "tcp_listen_port");
    let (tcp_listen_host, tcp_listen_port) = unwrap_or_exit(
        sip003::select_host_port(
            &args.tcp_listen_host,
            args.tcp_listen_port,
            tcp_listen_host_provided,
            tcp_listen_port_provided,
            sip003_env.local_host.as_deref(),
            sip003_env.local_port.as_deref(),
            "SS_LOCAL",
        ),
        "SIP003 env error",
        2,
    );

    let domain = if let Some(domain) = args.domain.clone() {
        domain
    } else {
        let option_domain = unwrap_or_exit(
            parse_domain_option(&sip003_env.plugin_options),
            "SIP003 env error",
            2,
        );
        if let Some(domain) = option_domain {
            domain
        } else {
            exit_with_message("A domain is required", 2);
        }
    };

    let resolver_transport = if cli_provided(&matches, "resolver_transport") {
        ResolverTransport::from(args.resolver_transport)
    } else {
        unwrap_or_exit(
            parse_resolver_transport(&sip003_env.plugin_options),
            "SIP003 env error",
            2,
        )
        .unwrap_or_else(|| ResolverTransport::from(args.resolver_transport))
    };

    let cli_has_resolvers = has_cli_resolvers(&matches);
    let mut resolvers = if cli_has_resolvers {
        unwrap_or_exit(build_resolvers(&matches, true), "Resolver error", 2)
    } else {
        let resolver_options = unwrap_or_exit(
            parse_resolvers_from_options(&sip003_env.plugin_options),
            "SIP003 env error",
            2,
        );
        if !resolver_options.resolvers.is_empty() {
            resolver_options.resolvers
        } else {
            let sip003_remote = unwrap_or_exit(
                sip003::parse_endpoint(
                    sip003_env.remote_host.as_deref(),
                    sip003_env.remote_port.as_deref(),
                    "SS_REMOTE",
                ),
                "SIP003 env error",
                2,
            );
            if let Some(endpoint) = &sip003_remote {
                let mode = if resolver_options.authoritative_remote {
                    ResolverMode::Authoritative
                } else {
                    ResolverMode::Recursive
                };
                let resolver = unwrap_or_exit(
                    parse_host_port_parts(&endpoint.host, endpoint.port, AddressKind::Resolver),
                    "SIP003 env error",
                    2,
                );
                vec![ResolverSpec { resolver, mode }]
            } else {
                exit_with_message("At least one resolver is required", 2);
            }
        }
    };
    apply_resolver_transport(&mut resolvers, resolver_transport);

    let congestion_control = if args.congestion_control.is_some() {
        args.congestion_control.clone()
    } else {
        unwrap_or_exit(
            parse_congestion_control(&sip003_env.plugin_options),
            "SIP003 env error",
            2,
        )
    };

    let cert = if args.cert.is_some() {
        args.cert.clone()
    } else {
        sip003::last_option_value(&sip003_env.plugin_options, "cert")
    };
    if cert.is_some() && args.verify_system_ca {
        exit_with_message(
            "--cert (leaf pinning) and --verify-system-ca are mutually exclusive; pick one",
            2,
        );
    }
    if cert.is_none() && !args.verify_system_ca {
        tracing::warn!(
            "Server certificate pinning is disabled; this allows MITM. Provide --cert to pin the server leaf, --verify-system-ca to verify against the OS trust store, or dismiss this if your underlying tunnel provides authentication."
        );
    }

    let keep_alive_interval = if cli_provided(&matches, "keep_alive_interval") {
        args.keep_alive_interval
    } else {
        let keep_alive_override = unwrap_or_exit(
            parse_keep_alive_interval(&sip003_env.plugin_options),
            "SIP003 env error",
            2,
        );
        keep_alive_override.unwrap_or(args.keep_alive_interval)
    };

    let config = ClientConfig {
        tcp_listen_host: &tcp_listen_host,
        tcp_listen_port,
        resolvers: &resolvers,
        congestion_control: congestion_control.as_deref(),
        gso: args.gso,
        domain: &domain,
        cert: cert.as_deref(),
        verify_system_ca: args.verify_system_ca,
        keep_alive_interval: keep_alive_interval as usize,
        resolver_transport,
        upstream_encoding: UpstreamEncoding::from(args.upstream_encoding),
        qname_mtu: args.qname_mtu,
        pacing_gain_probe: args.pacing_gain_probe,
        dns_tcp_packet_loop_burst: args.dns_tcp_packet_loop_burst,
        dns_query_type: args.dns_query_type,
        dns_label_length: args.dns_label_length,
        max_poll_qps: args.max_poll_qps,
        debug_poll: args.debug_poll,
        debug_streams: args.debug_streams,
        base64u_encoding: args.base64u_encoding,
    };

    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed to build Tokio runtime");
    match runtime.block_on(run_client_with_control(&config, None, None)) {
        Ok(code) => std::process::exit(code),
        Err(err) => exit_with_error("Client error", err, 1),
    }
}

/// JSON config-file schema for slipstream-client. Deliberately flat and 1:1 with `ClientConfig` —
/// the client is a single fixed tunnel, so there is no xray-style inbound/outbound/routing model.
/// Every field is optional; omitted fields fall back to the CLI default.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ClientFileConfig {
    tcp_listen_host: Option<String>,
    tcp_listen_port: Option<u16>,
    resolvers: Vec<ResolverEntry>,
    congestion_control: Option<String>,
    gso: Option<bool>,
    domain: Option<String>,
    cert: Option<String>,
    verify_system_ca: Option<bool>,
    keep_alive_interval: Option<u16>,
    /// "udp" or "tcp".
    resolver_transport: Option<String>,
    /// "qname" or "edns-raw".
    upstream_encoding: Option<String>,
    qname_mtu: Option<u32>,
    pacing_gain_probe: Option<f64>,
    dns_tcp_packet_loop_burst: Option<usize>,
    dns_query_type: Option<u16>,
    dns_label_length: Option<usize>,
    max_poll_qps: Option<u32>,
    debug_poll: Option<bool>,
    debug_streams: Option<bool>,
    base64u_encoding: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolverEntry {
    addr: String,
    #[serde(default)]
    authoritative: bool,
}

/// Load a JSON config file, merge it with the CLI (explicit flags win, then file, then defaults),
/// and run the client. Runs the process to completion and never returns.
fn run_from_config_file(path: &str, args: &Args, matches: &clap::ArgMatches) -> ! {
    let text = unwrap_or_exit(
        std::fs::read_to_string(path).map_err(|err| format!("{}: {}", path, err)),
        "Failed to read config file",
        2,
    );
    let file: ClientFileConfig = unwrap_or_exit(
        serde_json::from_str(&text).map_err(|err| err.to_string()),
        "Invalid config file",
        2,
    );

    // Explicit CLI flag > file value > built-in default. `args.<field>` already holds the clap
    // default when the flag was not passed, so it doubles as the default source.
    let tcp_listen_host = if cli_provided(matches, "tcp_listen_host") {
        args.tcp_listen_host.clone()
    } else {
        file.tcp_listen_host
            .clone()
            .unwrap_or_else(|| args.tcp_listen_host.clone())
    };
    let tcp_listen_port = if cli_provided(matches, "tcp_listen_port") {
        args.tcp_listen_port
    } else {
        file.tcp_listen_port.unwrap_or(args.tcp_listen_port)
    };
    let keep_alive_interval = if cli_provided(matches, "keep_alive_interval") {
        args.keep_alive_interval
    } else {
        file.keep_alive_interval.unwrap_or(args.keep_alive_interval)
    };
    let gso = if cli_provided(matches, "gso") {
        args.gso
    } else {
        file.gso.unwrap_or(args.gso)
    };
    let qname_mtu = if cli_provided(matches, "qname_mtu") {
        args.qname_mtu
    } else {
        file.qname_mtu.unwrap_or(args.qname_mtu)
    };
    let pacing_gain_probe = if cli_provided(matches, "pacing_gain_probe") {
        args.pacing_gain_probe
    } else {
        file.pacing_gain_probe.unwrap_or(args.pacing_gain_probe)
    };
    let dns_tcp_packet_loop_burst = if cli_provided(matches, "dns_tcp_packet_loop_burst") {
        args.dns_tcp_packet_loop_burst
    } else {
        file.dns_tcp_packet_loop_burst
            .unwrap_or(args.dns_tcp_packet_loop_burst)
    };
    let dns_query_type = if cli_provided(matches, "dns_query_type") {
        args.dns_query_type
    } else {
        file.dns_query_type.unwrap_or(args.dns_query_type)
    };
    let dns_label_length = if cli_provided(matches, "dns_label_length") {
        args.dns_label_length
    } else {
        file.dns_label_length.unwrap_or(args.dns_label_length)
    };
    let max_poll_qps = if cli_provided(matches, "max_poll_qps") {
        args.max_poll_qps
    } else {
        file.max_poll_qps.unwrap_or(args.max_poll_qps)
    };
    let debug_poll = if cli_provided(matches, "debug_poll") {
        args.debug_poll
    } else {
        file.debug_poll.unwrap_or(args.debug_poll)
    };
    let debug_streams = if cli_provided(matches, "debug_streams") {
        args.debug_streams
    } else {
        file.debug_streams.unwrap_or(args.debug_streams)
    };
    let base64u_encoding = if cli_provided(matches, "base64u_encoding") {
        args.base64u_encoding
    } else {
        file.base64u_encoding.unwrap_or(args.base64u_encoding)
    };
    let verify_system_ca = if cli_provided(matches, "verify_system_ca") {
        args.verify_system_ca
    } else {
        file.verify_system_ca.unwrap_or(args.verify_system_ca)
    };

    let resolver_transport = if cli_provided(matches, "resolver_transport") {
        ResolverTransport::from(args.resolver_transport)
    } else if let Some(value) = file.resolver_transport.as_deref() {
        unwrap_or_exit(parse_transport_str(value), "Invalid config", 2)
    } else {
        ResolverTransport::from(args.resolver_transport)
    };
    let upstream_encoding = if cli_provided(matches, "upstream_encoding") {
        UpstreamEncoding::from(args.upstream_encoding)
    } else if let Some(value) = file.upstream_encoding.as_deref() {
        unwrap_or_exit(parse_encoding_str(value), "Invalid config", 2)
    } else {
        UpstreamEncoding::from(args.upstream_encoding)
    };

    let domain = if let Some(domain) = args.domain.clone() {
        domain
    } else if let Some(domain) = file.domain.as_deref() {
        unwrap_or_exit(
            normalize_domain(domain).map_err(|err| err.to_string()),
            "Invalid config domain",
            2,
        )
    } else {
        exit_with_message("A domain is required (config `domain` or --domain)", 2);
    };

    let congestion_control = if cli_provided(matches, "congestion_control") {
        args.congestion_control.clone()
    } else {
        file.congestion_control.clone()
    };
    if let Some(value) = congestion_control.as_deref() {
        if value != "bbr" && value != "dcubic" {
            exit_with_message(&format!("Invalid congestion_control value: {}", value), 2);
        }
    }
    let cert = if cli_provided(matches, "cert") {
        args.cert.clone()
    } else {
        file.cert.clone()
    };
    if cert.is_some() && verify_system_ca {
        exit_with_message(
            "cert (leaf pinning) and verify_system_ca are mutually exclusive; pick one",
            2,
        );
    }
    if cert.is_none() && !verify_system_ca {
        tracing::warn!(
            "Server certificate pinning is disabled; this allows MITM. Set `cert` (or --cert) to pin the server leaf, `verify_system_ca` (or --verify-system-ca) to verify against the OS trust store, or dismiss this if your underlying tunnel provides authentication."
        );
    }

    let mut resolvers = if has_cli_resolvers(matches) {
        unwrap_or_exit(build_resolvers(matches, true), "Resolver error", 2)
    } else {
        let specs = unwrap_or_exit(
            file_resolvers(&file.resolvers),
            "Invalid config resolver",
            2,
        );
        if specs.is_empty() {
            exit_with_message(
                "At least one resolver is required (config `resolvers` or --resolver)",
                2,
            );
        }
        specs
    };
    apply_resolver_transport(&mut resolvers, resolver_transport);

    let config = ClientConfig {
        tcp_listen_host: &tcp_listen_host,
        tcp_listen_port,
        resolvers: &resolvers,
        congestion_control: congestion_control.as_deref(),
        gso,
        domain: &domain,
        cert: cert.as_deref(),
        verify_system_ca,
        keep_alive_interval: keep_alive_interval as usize,
        resolver_transport,
        upstream_encoding,
        qname_mtu,
        pacing_gain_probe,
        dns_tcp_packet_loop_burst,
        dns_query_type,
        dns_label_length,
        max_poll_qps,
        debug_poll,
        debug_streams,
        base64u_encoding,
    };

    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed to build Tokio runtime");
    match runtime.block_on(run_client_with_control(&config, None, None)) {
        Ok(code) => std::process::exit(code),
        Err(err) => exit_with_error("Client error", err, 1),
    }
}

fn file_resolvers(entries: &[ResolverEntry]) -> Result<Vec<ResolverSpec>, String> {
    entries
        .iter()
        .map(|entry| {
            let resolver = parse_host_port(&entry.addr, 53, AddressKind::Resolver)
                .map_err(|err| err.to_string())?;
            let mode = if entry.authoritative {
                ResolverMode::Authoritative
            } else {
                ResolverMode::Recursive
            };
            Ok(ResolverSpec { resolver, mode })
        })
        .collect()
}

fn parse_transport_str(value: &str) -> Result<ResolverTransport, String> {
    match value {
        "udp" => Ok(ResolverTransport::Udp),
        "tcp" => Ok(ResolverTransport::Tcp),
        _ => Err(format!("Invalid resolver_transport value: {}", value)),
    }
}

fn parse_encoding_str(value: &str) -> Result<UpstreamEncoding, String> {
    match value {
        "qname" => Ok(UpstreamEncoding::Qname),
        "edns-raw" | "ednsraw" => Ok(UpstreamEncoding::EdnsRaw),
        _ => Err(format!("Invalid upstream_encoding value: {}", value)),
    }
}

fn parse_domain(input: &str) -> Result<String, String> {
    normalize_domain(input).map_err(|err| err.to_string())
}

fn parse_resolver(input: &str) -> Result<HostPort, String> {
    parse_host_port(input, 53, AddressKind::Resolver).map_err(|err| err.to_string())
}

fn build_resolvers(matches: &clap::ArgMatches, require: bool) -> Result<Vec<ResolverSpec>, String> {
    let mut ordered = Vec::new();
    collect_resolvers(matches, "resolver", ResolverMode::Recursive, &mut ordered)?;
    collect_resolvers(
        matches,
        "authoritative",
        ResolverMode::Authoritative,
        &mut ordered,
    )?;
    if ordered.is_empty() && require {
        return Err("At least one resolver is required".to_string());
    }
    ordered.sort_by_key(|(idx, _)| *idx);
    Ok(ordered.into_iter().map(|(_, spec)| spec).collect())
}

fn collect_resolvers(
    matches: &clap::ArgMatches,
    name: &str,
    mode: ResolverMode,
    ordered: &mut Vec<(usize, ResolverSpec)>,
) -> Result<(), String> {
    let indices: Vec<usize> = matches.indices_of(name).into_iter().flatten().collect();
    let values: Vec<HostPort> = matches
        .get_many::<HostPort>(name)
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    if indices.len() != values.len() {
        return Err(format!("Mismatched {} arguments", name));
    }
    for (idx, resolver) in indices.into_iter().zip(values) {
        ordered.push((idx, ResolverSpec { resolver, mode }));
    }
    Ok(())
}

fn cli_provided(matches: &clap::ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

fn has_cli_resolvers(matches: &clap::ArgMatches) -> bool {
    matches
        .get_many::<HostPort>("resolver")
        .map(|values| values.len() > 0)
        .unwrap_or(false)
        || matches
            .get_many::<HostPort>("authoritative")
            .map(|values| values.len() > 0)
            .unwrap_or(false)
}

fn parse_domain_option(options: &[sip003::Sip003Option]) -> Result<Option<String>, String> {
    let mut domain = None;
    let mut saw_domain = false;
    for option in options {
        if option.key == "domain" {
            if saw_domain {
                return Err("SIP003 domain option must not be repeated".to_string());
            }
            saw_domain = true;
            let mut entries = sip003::split_list(&option.value).map_err(|err| err.to_string())?;
            if entries.len() > 1 {
                return Err("SIP003 domain option must contain a single value".to_string());
            }
            let entry = entries
                .pop()
                .ok_or_else(|| "SIP003 domain option must contain a single value".to_string())?;
            let normalized = normalize_domain(&entry).map_err(|err| err.to_string())?;
            domain = Some(normalized);
        }
    }
    Ok(domain)
}

struct ResolverOptions {
    resolvers: Vec<ResolverSpec>,
    authoritative_remote: bool,
}

fn parse_resolvers_from_options(
    options: &[sip003::Sip003Option],
) -> Result<ResolverOptions, String> {
    let mut ordered = Vec::new();
    let mut authoritative_remote = false;
    for option in options {
        let mode = match option.key.as_str() {
            "resolver" => ResolverMode::Recursive,
            "authoritative" => ResolverMode::Authoritative,
            _ => continue,
        };
        let trimmed = option.value.trim();
        if trimmed.is_empty() {
            if mode == ResolverMode::Authoritative {
                authoritative_remote = true;
                continue;
            }
            return Err("Empty resolver value is not allowed".to_string());
        }
        let entries = sip003::split_list(&option.value).map_err(|err| err.to_string())?;
        for entry in entries {
            let resolver = parse_host_port(&entry, 53, AddressKind::Resolver)
                .map_err(|err| err.to_string())?;
            ordered.push(ResolverSpec { resolver, mode });
        }
    }
    Ok(ResolverOptions {
        resolvers: ordered,
        authoritative_remote,
    })
}

fn parse_congestion_control(options: &[sip003::Sip003Option]) -> Result<Option<String>, String> {
    let mut last = None;
    for option in options {
        if option.key == "congestion-control" {
            let value = option.value.trim();
            if value != "bbr" && value != "dcubic" {
                return Err(format!("Invalid congestion-control value: {}", value));
            }
            last = Some(value.to_string());
        }
    }
    Ok(last)
}

fn parse_keep_alive_interval(options: &[sip003::Sip003Option]) -> Result<Option<u16>, String> {
    let mut last = None;
    for option in options {
        if option.key == "keep-alive-interval" {
            let value = option.value.trim();
            let parsed = value
                .parse::<u16>()
                .map_err(|_| format!("Invalid keep-alive-interval value: {}", value))?;
            last = Some(parsed);
        }
    }
    Ok(last)
}

fn parse_resolver_transport(
    options: &[sip003::Sip003Option],
) -> Result<Option<ResolverTransport>, String> {
    let mut last = None;
    for option in options {
        if option.key == "resolver-transport" {
            let value = option.value.trim();
            last = Some(match value {
                "udp" => ResolverTransport::Udp,
                "tcp" => ResolverTransport::Tcp,
                _ => return Err(format!("Invalid resolver-transport value: {}", value)),
            });
        }
    }
    Ok(last)
}

fn apply_resolver_transport(resolvers: &mut Vec<ResolverSpec>, transport: ResolverTransport) {
    if transport == ResolverTransport::Tcp && resolvers.len() > 1 {
        tracing::warn!(
            "TCP resolver transport uses a single resolver; ignoring {} extra resolver(s)",
            resolvers.len() - 1
        );
        resolvers.truncate(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_ordered_resolvers() {
        let matches = Args::command()
            .try_get_matches_from([
                "slipstream-client",
                "--domain",
                "example.com",
                "--resolver",
                "1.1.1.1",
                "--authoritative",
                "2.2.2.2",
                "--resolver",
                "3.3.3.3:5353",
            ])
            .expect("matches should parse");
        let resolvers = build_resolvers(&matches, true).expect("resolvers should parse");
        assert_eq!(resolvers.len(), 3);
        assert_eq!(resolvers[0].resolver.host, "1.1.1.1");
        assert_eq!(resolvers[0].resolver.port, 53);
        assert_eq!(resolvers[0].mode, ResolverMode::Recursive);
        assert_eq!(resolvers[1].resolver.host, "2.2.2.2");
        assert_eq!(resolvers[1].mode, ResolverMode::Authoritative);
        assert_eq!(resolvers[2].resolver.host, "3.3.3.3");
        assert_eq!(resolvers[2].resolver.port, 5353);
    }

    #[test]
    fn maps_authoritative_first() {
        let matches = Args::command()
            .try_get_matches_from([
                "slipstream-client",
                "--domain",
                "example.com",
                "--authoritative",
                "8.8.8.8",
                "--resolver",
                "9.9.9.9",
            ])
            .expect("matches should parse");
        let resolvers = build_resolvers(&matches, true).expect("resolvers should parse");
        assert_eq!(resolvers.len(), 2);
        assert_eq!(resolvers[0].resolver.host, "8.8.8.8");
        assert_eq!(resolvers[0].mode, ResolverMode::Authoritative);
        assert_eq!(resolvers[1].resolver.host, "9.9.9.9");
        assert_eq!(resolvers[1].mode, ResolverMode::Recursive);
    }

    #[test]
    fn parses_plugin_resolvers_in_order() {
        let options = vec![
            sip003::Sip003Option {
                key: "resolver".to_string(),
                value: "1.1.1.1,2.2.2.2:5353".to_string(),
            },
            sip003::Sip003Option {
                key: "authoritative".to_string(),
                value: "3.3.3.3".to_string(),
            },
            sip003::Sip003Option {
                key: "resolver".to_string(),
                value: "4.4.4.4".to_string(),
            },
        ];
        let parsed = parse_resolvers_from_options(&options).expect("options should parse");
        assert_eq!(parsed.resolvers.len(), 4);
        assert_eq!(parsed.resolvers[0].resolver.host, "1.1.1.1");
        assert_eq!(parsed.resolvers[0].mode, ResolverMode::Recursive);
        assert_eq!(parsed.resolvers[1].resolver.host, "2.2.2.2");
        assert_eq!(parsed.resolvers[1].resolver.port, 5353);
        assert_eq!(parsed.resolvers[2].resolver.host, "3.3.3.3");
        assert_eq!(parsed.resolvers[2].mode, ResolverMode::Authoritative);
        assert_eq!(parsed.resolvers[3].resolver.host, "4.4.4.4");
        assert!(!parsed.authoritative_remote);
    }

    #[test]
    fn plugin_domain_single_entry() {
        let options = vec![sip003::Sip003Option {
            key: "domain".to_string(),
            value: "example.com".to_string(),
        }];
        let domain = parse_domain_option(&options)
            .expect("options should parse")
            .expect("domain should exist");
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn plugin_domain_rejects_repeated_option() {
        let options = vec![
            sip003::Sip003Option {
                key: "domain".to_string(),
                value: "example.com".to_string(),
            },
            sip003::Sip003Option {
                key: "domain".to_string(),
                value: "example.net".to_string(),
            },
        ];
        assert!(parse_domain_option(&options).is_err());
    }

    #[test]
    fn plugin_domain_rejects_multiple_entries() {
        let options = vec![sip003::Sip003Option {
            key: "domain".to_string(),
            value: "example.com,example.net".to_string(),
        }];
        assert!(parse_domain_option(&options).is_err());
    }

    #[test]
    fn authoritative_flag_applies_to_remote() {
        let options = vec![sip003::Sip003Option {
            key: "authoritative".to_string(),
            value: "".to_string(),
        }];
        let parsed = parse_resolvers_from_options(&options).expect("options should parse");
        assert!(parsed.resolvers.is_empty());
        assert!(parsed.authoritative_remote);
    }

    #[test]
    fn parses_plugin_resolver_transport() {
        let options = vec![sip003::Sip003Option {
            key: "resolver-transport".to_string(),
            value: "tcp".to_string(),
        }];
        assert_eq!(
            parse_resolver_transport(&options).expect("transport should parse"),
            Some(ResolverTransport::Tcp)
        );
    }

    #[test]
    fn tcp_transport_keeps_only_first_resolver() {
        let mut resolvers = vec![
            ResolverSpec {
                resolver: HostPort {
                    host: "1.1.1.1".to_string(),
                    port: 53,
                    family: slipstream_core::AddressFamily::V4,
                },
                mode: ResolverMode::Recursive,
            },
            ResolverSpec {
                resolver: HostPort {
                    host: "2.2.2.2".to_string(),
                    port: 53,
                    family: slipstream_core::AddressFamily::V4,
                },
                mode: ResolverMode::Recursive,
            },
        ];
        apply_resolver_transport(&mut resolvers, ResolverTransport::Tcp);
        assert_eq!(resolvers.len(), 1);
        assert_eq!(resolvers[0].resolver.host, "1.1.1.1");
    }
}
