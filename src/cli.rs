// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// NetSpecter (`nspecter`) — Zero-dependency network packet forensics, PCAP analyzer,
/// TLS JA3 fingerprinting engine, and DNS covert-channel detector.
#[derive(Debug, Parser)]
#[command(
    name = "nspecter",
    version,
    about = "Zero-dependency network packet forensics, PCAP analyzer, TLS JA3 fingerprinting engine, and DNS covert-channel detector"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Decode a PCAP capture file and summarize L3/L4 flows, TLS handshakes, and DNS queries
    InspectPcap {
        /// Path to the input .pcap file
        file: PathBuf,
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
    },
    /// Extract TLS ClientHello metadata and compute JA3 MD5/SHA-256 fingerprints from a .pcap or hex string
    Ja3 {
        /// Path to a .pcap file, raw binary file, or hex-encoded TLS ClientHello record
        file_or_hex: String,
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
    },
    /// Parse DNS wire packets from a .pcap or hex string and score covert-tunneling entropy anomalies
    DnsAudit {
        /// Path to a .pcap file, raw binary file, or hex-encoded DNS message
        file_or_hex: String,
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
    },
    /// Generate a deterministic multi-packet sample .pcap containing TLS 1.3 ClientHello and DNS packets
    SynthPcap {
        /// Output path for the generated .pcap file
        output: PathBuf,
        /// Emit structured JSON summary
        #[arg(long)]
        json: bool,
    },
}
