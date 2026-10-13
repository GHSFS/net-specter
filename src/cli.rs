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
        /// BPF-style packet filter expression (e.g. "tcp port 443", "src net 192.168.0.0/16")
        #[arg(long, short = 'f')]
        filter: Option<String>,
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
    /// Extract TLS and QUIC ClientHello/ServerHello metadata and compute JA4 / JA4S fingerprints
    Ja4 {
        /// Path to a .pcap/.pcapng file, raw binary file, or hex-encoded TLS/QUIC record
        file_or_hex: String,
        /// Force QUIC ('q') transport classification
        #[arg(long)]
        quic: bool,
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
    /// Reassemble bidirectional TCP byte streams from a PCAP/PCAPNG capture and inspect application payloads
    TcpStream {
        /// Path to the input .pcap or .pcapng file
        file: PathBuf,
        /// Dump reassembled client/server payloads in hexadecimal format
        #[arg(long)]
        dump_payload: bool,
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
    },
    /// Parse HTTP/1.1 requests/responses, HTTP/2 frames & SETTINGS, and compute JA4H client fingerprints
    HttpAudit {
        /// Path to a .pcap/.pcapng file, raw HTTP payload file, or hex-encoded message
        file_or_hex: String,
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
    },
    /// Parse TLS ServerHello (JA3S) and X.509 certificate chains, audit certificate anomalies
    CertAudit {
        /// Path to a .pcap/.pcapng file, raw DER certificate / handshake file, or hex-encoded message
        file_or_hex: String,
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
    },
    /// Decrypt QUIC Initial packets, strip RFC 9001 header protection, and extract TLS 1.3 ClientHello JA3/JA4 fingerprints
    QuicAudit {
        /// Path to a .pcap/.pcapng file, raw binary file, or hex-encoded QUIC Initial packet
        file_or_hex: String,
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
    },
    /// Generate a deterministic multi-packet sample .pcap or .pcapng containing TLS 1.3 ClientHello and DNS packets
    SynthPcap {
        /// Output path for the generated capture file (.pcap or .pcapng)
        output: PathBuf,
        /// Generate next-generation PCAPNG capture instead of classic PCAP
        #[arg(long)]
        pcapng: bool,
        /// Emit structured JSON summary
        #[arg(long)]
        json: bool,
    },
    /// Analyze flow inter-arrival times and detect periodic or jittered C2 beaconing
    BeaconAudit {
        /// Path to the input .pcap or .pcapng file
        file: PathBuf,
        /// Minimum packet events in a flow required for beacon audit
        #[arg(long, default_value_t = 4)]
        min_events: usize,
        /// Periodicity/regularity score threshold for classification
        #[arg(long, default_value_t = 0.70)]
        threshold: f64,
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
    },
    /// Filter packets in a PCAP/PCAPNG capture using BPF-style expressions
    Filter {
        /// Path to the input .pcap or .pcapng file
        file: PathBuf,
        /// BPF-style packet filter expression (e.g. "tcp port 443", "src net 10.0.0.0/8 and syn")
        filter: String,
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
    },
    /// Extract SSH-2.0 banners and SSH_MSG_KEXINIT metadata, compute Salesforce HASSH/HASSHServer fingerprints
    Hassh {
        /// Path to a .pcap/.pcapng file, raw binary SSH packet file, or hex-encoded message
        file_or_hex: String,
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
    },
    /// Audit ICMP Echo Request/Reply flows for covert data exfiltration, tunnels, and payload tampering
    IcmpTunnel {
        /// Path to a .pcap/.pcapng file, raw packet dump, or hex-encoded ICMP frame
        file_or_hex: String,
        /// Dump payload preview of suspicious or covert frames
        #[arg(long)]
        dump_payload: bool,
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
    },
}
