// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use clap::Parser;
use net_specter::cli::{Cli, Commands};
use net_specter::dns::parse_dns_packet;
use net_specter::error::{Result, SpecterError};
use net_specter::pcap::{build_synthetic_pcap, parse_pcap_bytes};
use net_specter::tls_ja3::parse_tls_client_hello;
use std::fs;
use std::path::Path;

fn load_bytes_or_hex(input: &str) -> Result<Vec<u8>> {
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

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::InspectPcap { file, json } => {
            let bytes = fs::read(&file)?;
            let report = parse_pcap_bytes(&bytes)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?
                );
            } else {
                println!(
                    "PCAP Capture v{}.{} | Linktype={} | Snaplen={} | Packets={} (TCP={}, UDP={})",
                    report.header.version_major,
                    report.header.version_minor,
                    report.header.linktype,
                    report.header.snaplen,
                    report.total_packets,
                    report.tcp_packets,
                    report.udp_packets
                );
                for f in &report.frames {
                    println!(
                        "  #[{}] {} {}:{} -> {}:{} ({} bytes payload)",
                        f.index,
                        f.protocol,
                        f.src_ip,
                        f.src_port,
                        f.dst_ip,
                        f.dst_port,
                        f.payload.len()
                    );
                }
                for tls in &report.tls_handshakes {
                    println!(
                        "  [TLS JA3] SNI={} | JA3={} | SHA256={}",
                        tls.sni.as_deref().unwrap_or("(none)"),
                        tls.ja3_md5,
                        tls.ja3_sha256
                    );
                }
                for dns in &report.dns_messages {
                    for q in &dns.questions {
                        println!(
                            "  [DNS] id=0x{:04x} {} {} | entropy={:.3} | risk={:?} ({})",
                            dns.transaction_id,
                            q.qtype_name,
                            q.qname,
                            q.subdomain_entropy,
                            q.risk_level,
                            q.risk_score
                        );
                    }
                }
            }
        }
        Commands::Ja3 { file_or_hex, json } => {
            let raw = load_bytes_or_hex(&file_or_hex)?;
            let reports = if let Ok(pcap_rep) = parse_pcap_bytes(&raw) {
                if pcap_rep.tls_handshakes.is_empty() {
                    return Err(SpecterError::MalformedTls(
                        "No TLS ClientHello handshakes found in PCAP capture".into(),
                    ));
                }
                pcap_rep.tls_handshakes
            } else {
                vec![parse_tls_client_hello(&raw)?]
            };

            if json {
                let out = if reports.len() == 1 {
                    serde_json::to_string_pretty(&reports[0])
                } else {
                    serde_json::to_string_pretty(&reports)
                }
                .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?;
                println!("{out}");
            } else {
                for rep in &reports {
                    println!("SNI        : {}", rep.sni.as_deref().unwrap_or("(none)"));
                    println!("ALPN       : {}", rep.alpn.join(", "));
                    println!("JA3 String : {}", rep.ja3_string);
                    println!("JA3 MD5    : {}", rep.ja3_md5);
                    println!("JA3 SHA256 : {}", rep.ja3_sha256);
                }
            }
        }
        Commands::DnsAudit { file_or_hex, json } => {
            let raw = load_bytes_or_hex(&file_or_hex)?;
            let reports = if let Ok(pcap_rep) = parse_pcap_bytes(&raw) {
                if pcap_rep.dns_messages.is_empty() {
                    return Err(SpecterError::MalformedDns(
                        "No DNS packets found in PCAP capture".into(),
                    ));
                }
                pcap_rep.dns_messages
            } else {
                vec![parse_dns_packet(&raw)?]
            };

            if json {
                let out = if reports.len() == 1 {
                    serde_json::to_string_pretty(&reports[0])
                } else {
                    serde_json::to_string_pretty(&reports)
                }
                .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?;
                println!("{out}");
            } else {
                for rep in &reports {
                    for q in &rep.questions {
                        println!(
                            "QNAME={} QTYPE={} Entropy={:.3} LongestLabel={} Risk={:?} ({}/100)",
                            q.qname,
                            q.qtype_name,
                            q.subdomain_entropy,
                            q.longest_label_len,
                            q.risk_level,
                            q.risk_score
                        );
                    }
                }
            }
        }
        Commands::SynthPcap { output, json } => {
            let bytes = build_synthetic_pcap();
            fs::write(&output, &bytes)?;
            let report = parse_pcap_bytes(&bytes)?;
            if json {
                let summary = serde_json::json!({
                    "output": output.display().to_string(),
                    "bytes_written": bytes.len(),
                    "packets": report.total_packets,
                    "tls_handshakes": report.tls_handshakes.len(),
                    "dns_messages": report.dns_messages.len(),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary)
                        .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?
                );
            } else {
                println!(
                    "Wrote synthetic PCAP ({} bytes, {} packets) to {}",
                    bytes.len(),
                    report.total_packets,
                    output.display()
                );
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}
