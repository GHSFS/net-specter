// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! CLI Command Dispatcher and Modular Subcommand Handlers.

pub mod arp;
pub mod beacon;
pub mod cert;
pub mod dns;
pub mod filter;
pub mod hassh;
pub mod http;
pub mod icmp;
pub mod inspect;
pub mod os_fp;
pub mod quic;
pub mod synth;
pub mod tcp;
pub mod tls;

use crate::cli::Commands;
use crate::error::{Result, SpecterError};
use std::fs;
use std::path::Path;

/// Resolves a file path or hexadecimal string input into raw byte vector.
pub fn load_bytes_or_hex(input: &str) -> Result<Vec<u8>> {
    let path = Path::new(input);
    if path.exists() {
        return Ok(fs::read(path)?);
    }
    let clean_hex: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&clean_hex).map_err(|e| {
        SpecterError::InvalidArgument(format!(
            "Input '{input}' is neither an existing file nor valid hex: {e}"
        ))
    })
}

/// Dispatches a parsed CLI command to its modular handler.
pub fn execute(command: Commands) -> Result<()> {
    match command {
        Commands::InspectPcap { file, filter, json } => {
            inspect::handle_inspect_pcap(&file, filter.as_deref(), json)
        }
        Commands::Ja3 { file_or_hex, json } => tls::handle_ja3(&file_or_hex, json),
        Commands::Ja4 {
            file_or_hex,
            quic,
            json,
        } => tls::handle_ja4(&file_or_hex, quic, json),
        Commands::DnsAudit { file_or_hex, json } => dns::handle_dns_audit(&file_or_hex, json),
        Commands::TcpStream {
            file,
            dump_payload,
            json,
        } => tcp::handle_tcp_stream(&file, dump_payload, json),
        Commands::HttpAudit { file_or_hex, json } => http::handle_http_audit(&file_or_hex, json),
        Commands::CertAudit { file_or_hex, json } => cert::handle_cert_audit(&file_or_hex, json),
        Commands::QuicAudit { file_or_hex, json } => quic::handle_quic_audit(&file_or_hex, json),
        Commands::SynthPcap {
            output,
            pcapng,
            json,
        } => synth::handle_synth_pcap(&output, pcapng, json),
        Commands::BeaconAudit {
            file,
            min_events,
            threshold,
            json,
        } => beacon::handle_beacon_audit(&file, min_events, threshold, json),
        Commands::Filter { file, filter, json } => {
            self::filter::handle_filter(&file, &filter, json)
        }
        Commands::Hassh { file_or_hex, json } => hassh::handle_hassh(&file_or_hex, json),
        Commands::IcmpTunnel {
            file_or_hex,
            dump_payload,
            json,
        } => icmp::handle_icmp_tunnel(&file_or_hex, dump_payload, json),
        Commands::OsFp { file_or_hex, json } => os_fp::handle_os_fp(&file_or_hex, json),
        Commands::ArpAudit {
            file_or_hex,
            gateway,
            json,
        } => arp::handle_arp_audit(&file_or_hex, gateway.as_deref(), json),
    }
}
