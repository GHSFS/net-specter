// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

#![forbid(unsafe_code)]

use clap::Parser;
use net_specter::beacon::{audit_beacon_bytes, BeaconAuditConfig};
use net_specter::cli::{Cli, Commands};
use net_specter::dns::parse_dns_packet;
use net_specter::error::{Result, SpecterError};
use net_specter::http_inspect::audit_http_bytes;
use net_specter::ja4::{extract_ja4_from_capture_bytes, Ja4Fingerprint};
use net_specter::pcap::{build_synthetic_pcap, parse_pcap_bytes};
use net_specter::pcapng::{build_synthetic_pcapng, is_pcapng, parse_pcapng_bytes};
use net_specter::tcp_stream::reassemble_capture_bytes;
use net_specter::tls_cert::audit_cert_bytes;
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
            if is_pcapng(&bytes) {
                let report = parse_pcapng_bytes(&bytes)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report)
                            .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?
                    );
                } else {
                    println!(
                        "PCAPNG Capture v{}.{} | SectionLen={} | Interfaces={} | Packets={} (TCP={}, UDP={})",
                        report.section.version_major,
                        report.section.version_minor,
                        report.section.section_length,
                        report.interfaces.len(),
                        report.total_packets,
                        report.tcp_packets,
                        report.udp_packets
                    );
                    for (idx, iface) in report.interfaces.iter().enumerate() {
                        println!(
                            "  [IFACE #{}] linktype={} snaplen={} resol=10^-{} name={}",
                            idx,
                            iface.linktype,
                            iface.snaplen,
                            iface.ts_resol,
                            iface.name.as_deref().unwrap_or("(unnamed)")
                        );
                    }
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
            } else {
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
        }
        Commands::Ja3 { file_or_hex, json } => {
            let raw = load_bytes_or_hex(&file_or_hex)?;
            let reports = if is_pcapng(&raw) {
                let pcapng_rep = parse_pcapng_bytes(&raw)?;
                if pcapng_rep.tls_handshakes.is_empty() {
                    return Err(SpecterError::MalformedTls(
                        "No TLS ClientHello handshakes found in PCAPNG capture".into(),
                    ));
                }
                pcapng_rep.tls_handshakes
            } else if let Ok(pcap_rep) = parse_pcap_bytes(&raw) {
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
        Commands::Ja4 {
            file_or_hex,
            quic,
            json,
        } => {
            let raw = load_bytes_or_hex(&file_or_hex)?;
            let fingerprints = extract_ja4_from_capture_bytes(&raw, quic)?;
            if fingerprints.is_empty() {
                return Err(SpecterError::MalformedTls(
                    "No TLS/QUIC ClientHello or ServerHello handshakes found".into(),
                ));
            }

            if json {
                let out = if fingerprints.len() == 1 {
                    serde_json::to_string_pretty(&fingerprints[0])
                } else {
                    serde_json::to_string_pretty(&fingerprints)
                }
                .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?;
                println!("{out}");
            } else {
                for fp in &fingerprints {
                    match fp {
                        Ja4Fingerprint::Client(c) => {
                            println!("[JA4 Client]");
                            println!("  Transport   : {:?}", c.transport);
                            println!("  JA4         : {}", c.ja4);
                            println!("  JA4_a       : {}", c.ja4_a);
                            println!("  JA4_b       : {}", c.ja4_b);
                            println!("  JA4_c       : {}", c.ja4_c);
                            println!("  SNI         : {}", c.sni.as_deref().unwrap_or("(none)"));
                            println!("  ALPN        : {}", c.alpn.join(", "));
                            println!("  Version     : {}", c.version);
                            println!("  Ciphers     : {}", c.cipher_suites.len());
                            println!("  Extensions  : {}", c.extensions.len());
                        }
                        Ja4Fingerprint::Server(s) => {
                            println!("[JA4S Server]");
                            println!("  Transport   : {:?}", s.transport);
                            println!("  JA4S        : {}", s.ja4s);
                            println!("  JA4S_a      : {}", s.ja4s_a);
                            println!("  JA4S_b      : {}", s.ja4s_b);
                            println!("  JA4S_c      : {}", s.ja4s_c);
                            println!("  Cipher      : 0x{:04x}", s.cipher_suite);
                            println!("  ALPN        : {}", s.alpn.as_deref().unwrap_or("(none)"));
                            println!("  Version     : {}", s.version);
                            println!("  Extensions  : {}", s.extensions.len());
                        }
                    }
                }
            }
        }
        Commands::DnsAudit { file_or_hex, json } => {
            let raw = load_bytes_or_hex(&file_or_hex)?;
            let reports = if is_pcapng(&raw) {
                let pcapng_rep = parse_pcapng_bytes(&raw)?;
                if pcapng_rep.dns_messages.is_empty() {
                    return Err(SpecterError::MalformedDns(
                        "No DNS packets found in PCAPNG capture".into(),
                    ));
                }
                pcapng_rep.dns_messages
            } else if let Ok(pcap_rep) = parse_pcap_bytes(&raw) {
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
        Commands::TcpStream {
            file,
            dump_payload,
            json,
        } => {
            let bytes = fs::read(&file)?;
            let reports = reassemble_capture_bytes(&bytes, dump_payload)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&reports)
                        .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?
                );
            } else {
                println!(
                    "TCP Stream Reassembly: {} stream(s) reassembled from {}",
                    reports.len(),
                    file.display()
                );
                for r in &reports {
                    println!(
                        "  [Stream #{}] {} <-> {} | dur={:.1}ms | c_pkts={} c_bytes={} | s_pkts={} s_bytes={}",
                        r.stream_id,
                        r.client,
                        r.server,
                        r.duration_ms,
                        r.client_packets,
                        r.client_payload_bytes,
                        r.server_packets,
                        r.server_payload_bytes
                    );
                    println!(
                        "    Status: syn={} fin={} rst={} handshake_complete={}",
                        r.syn_seen, r.fin_seen, r.rst_seen, r.handshake_complete
                    );
                    println!(
                        "    Retransmissions: client={} ({} B), server={} ({} B) | OutOfOrder: client={}, server={}",
                        r.client_retransmissions,
                        r.client_retransmitted_bytes,
                        r.server_retransmissions,
                        r.server_retransmitted_bytes,
                        r.client_out_of_order,
                        r.server_out_of_order
                    );
                    if !r.detected_protocols.is_empty() {
                        println!("    Protocols: {}", r.detected_protocols.join(", "));
                    }
                    if let Some(ja3) = &r.ja3 {
                        println!(
                            "    TLS JA3: SNI={} | JA3={} | SHA256={}",
                            ja3.sni.as_deref().unwrap_or("(none)"),
                            ja3.ja3_md5,
                            ja3.ja3_sha256
                        );
                    }
                    if let Some(ja4) = &r.ja4 {
                        println!("    TLS JA4: {}", ja4.ja4);
                    }
                    if let Some(client_hex) = &r.client_payload_hex {
                        let preview = if client_hex.len() > 64 {
                            format!("{}...", &client_hex[..64])
                        } else {
                            client_hex.clone()
                        };
                        println!(
                            "    Client Payload: {preview} ({} hex chars)",
                            client_hex.len()
                        );
                    }
                    if let Some(server_hex) = &r.server_payload_hex {
                        let preview = if server_hex.len() > 64 {
                            format!("{}...", &server_hex[..64])
                        } else {
                            server_hex.clone()
                        };
                        println!(
                            "    Server Payload: {preview} ({} hex chars)",
                            server_hex.len()
                        );
                    }
                }
            }
        }
        Commands::HttpAudit { file_or_hex, json } => {
            let bytes = load_bytes_or_hex(&file_or_hex)?;
            let report = audit_http_bytes(&bytes)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?
                );
            } else {
                println!(
                    "HTTP Audit Summary: {} message(s) | HTTP/1.1 Requests={} | Responses={} | HTTP/2 Connections={}",
                    report.total_messages,
                    report.http1_requests.len(),
                    report.http1_responses.len(),
                    report.http2_connections.len()
                );
                for req in &report.http1_requests {
                    println!(
                        "  [HTTP/1.1 REQ] {} {} {} | headers={} | JA4H={}",
                        req.method,
                        req.uri,
                        req.version,
                        req.headers.len(),
                        req.ja4h.ja4h
                    );
                }
                for resp in &report.http1_responses {
                    println!(
                        "  [HTTP/1.1 RESP] {} {} {} | headers={}",
                        resp.version,
                        resp.status_code,
                        resp.reason,
                        resp.headers.len()
                    );
                }
                for h2 in &report.http2_connections {
                    println!(
                        "  [HTTP/2] preface={} | frames={} | settings={}",
                        h2.preface_valid,
                        h2.frames.len(),
                        h2.settings.len()
                    );
                }
            }
        }
        Commands::CertAudit { file_or_hex, json } => {
            let bytes = load_bytes_or_hex(&file_or_hex)?;
            let report = audit_cert_bytes(&bytes)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?
                );
            } else {
                println!(
                    "TLS Forensic Audit: {} ServerHello(s), {} Certificate(s) ({} anomalies)",
                    report.server_hellos.len(),
                    report.certificates.len(),
                    report.total_anomalies
                );
                for sh in &report.server_hellos {
                    println!(
                        "  [ServerHello JA3S] Ver=0x{:04x} Cipher=0x{:04x} JA3S={} MD5={} SHA256={}",
                        sh.server_version, sh.cipher_suite, sh.ja3s_string, sh.ja3s_md5, sh.ja3s_sha256
                    );
                }
                for (i, c) in report.certificates.iter().enumerate() {
                    println!(
                        "  [Cert #{}] Subject=\"{}\" Issuer=\"{}\" Serial={} Algo={}",
                        i + 1,
                        c.subject,
                        c.issuer,
                        c.serial_number,
                        c.signature_algorithm
                    );
                    println!("    Validity: {} to {}", c.not_before, c.not_after);
                    if !c.sans_dns.is_empty() {
                        println!("    SANs DNS: {}", c.sans_dns.join(", "));
                    }
                    if !c.sans_ip.is_empty() {
                        println!("    SANs IP: {}", c.sans_ip.join(", "));
                    }
                    if c.is_self_signed {
                        println!("    Self-Signed: true");
                    }
                    if !c.anomalies.is_empty() {
                        println!("    Anomalies: {}", c.anomalies.join(", "));
                    }
                }
            }
        }
        Commands::QuicAudit { file_or_hex, json } => {
            let bytes = load_bytes_or_hex(&file_or_hex)?;
            let report = net_specter::quic::audit_quic_bytes(&bytes)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?
                );
            } else {
                println!(
                    "QUIC Initial Audit: {} packet(s) inspected, {} Initial(s), {} decrypted",
                    report.packets_inspected, report.quic_initial_count, report.decrypted_count
                );
                for r in &report.reports {
                    println!(
                        "  [{}] Version={} PN={} DCID={} SCID={}",
                        r.role, r.version, r.packet_number, r.dcid, r.scid
                    );
                    if let Some(ref hs) = r.handshake_type {
                        println!("    Handshake: {hs} ({} crypto bytes)", r.crypto_bytes_len);
                    }
                    if let Some(ref s) = r.sni {
                        println!("    SNI: {s}");
                    }
                    if !r.alpn.is_empty() {
                        println!("    ALPN: {}", r.alpn.join(", "));
                    }
                    if let Some(ref j) = r.ja3 {
                        println!("    JA3: {j}");
                    }
                    if let Some(ref d) = r.ja3_digest {
                        println!("    JA3 MD5: {d}");
                    }
                    if let Some(ref j) = r.ja4 {
                        println!("    JA4: {j}");
                    }
                    if let Some(ref j) = r.ja3s {
                        println!("    JA3S: {j}");
                    }
                    if let Some(ref j) = r.ja4s {
                        println!("    JA4S: {j}");
                    }
                }
            }
        }
        Commands::SynthPcap {
            output,
            pcapng,
            json,
        } => {
            if pcapng {
                let bytes = build_synthetic_pcapng();
                fs::write(&output, &bytes)?;
                let report = parse_pcapng_bytes(&bytes)?;
                if json {
                    let summary = serde_json::json!({
                        "output": output.display().to_string(),
                        "format": "pcapng",
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
                        "Wrote synthetic PCAPNG ({} bytes, {} packets) to {}",
                        bytes.len(),
                        report.total_packets,
                        output.display()
                    );
                }
            } else {
                let bytes = build_synthetic_pcap();
                fs::write(&output, &bytes)?;
                let report = parse_pcap_bytes(&bytes)?;
                if json {
                    let summary = serde_json::json!({
                        "output": output.display().to_string(),
                        "format": "pcap",
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
        Commands::BeaconAudit {
            file,
            min_events,
            threshold,
            json,
        } => {
            let bytes = fs::read(&file)?;
            let config = BeaconAuditConfig {
                min_events,
                threshold,
            };
            let report = audit_beacon_bytes(&bytes, config)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?
                );
            } else {
                println!(
                    "C2 Beacon Audit: {}/{} flow(s) analyzed from {}",
                    report.analyzed_flows,
                    report.total_flows,
                    file.display()
                );
                println!(
                    "  Verdicts: HighConfidence={}, Jittered={}, Suspect={}, Benign={}",
                    report.high_confidence_count,
                    report.jittered_count,
                    report.suspect_count,
                    report.benign_count
                );
                for f in &report.flows {
                    println!(
                        "  [{:?}] {} ({} events) | Regularity={:.2} Periodicity={:.2}",
                        f.verdict,
                        f.flow_key,
                        f.event_count,
                        f.regularity_score,
                        f.periodicity_score
                    );
                    println!(
                        "    Stats: mean={:.3}s median={:.3}s std_dev={:.3}s | Jitter={:.1}% (CV={:.3})",
                        f.mean, f.median, f.std_dev, f.jitter_percent, f.cv
                    );
                    println!(
                        "    Spectrogram: dom_period={:.3}s dom_freq={:.3}Hz peak_power_ratio={:.2} ({} bins)",
                        f.spectrogram.dominant_interval,
                        f.spectrogram.dominant_freq_hz,
                        f.spectrogram.peak_power_ratio,
                        f.spectrogram.bins.len()
                    );
                }
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
