// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{Result, SpecterError};
use crate::filter::FilterExpr;
use crate::pcap::parse_pcap_bytes;
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use std::fs;
use std::path::Path;

pub fn handle_inspect_pcap(file: &Path, filter: Option<&str>, json: bool) -> Result<()> {
    let bytes = fs::read(file)?;
    if is_pcapng(&bytes) {
        let mut report = parse_pcapng_bytes(&bytes)?;
        if let Some(filter_str) = filter {
            let parsed_filter = FilterExpr::parse(filter_str)?;
            report.frames.retain(|f| parsed_filter.matches(f));
            report.total_packets = report.frames.len();
            report.tcp_packets = report
                .frames
                .iter()
                .filter(|f| f.protocol.eq_ignore_ascii_case("TCP"))
                .count();
            report.udp_packets = report
                .frames
                .iter()
                .filter(|f| f.protocol.eq_ignore_ascii_case("UDP"))
                .count();
        }
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
        let mut report = parse_pcap_bytes(&bytes)?;
        if let Some(filter_str) = filter {
            let parsed_filter = FilterExpr::parse(filter_str)?;
            report.frames.retain(|f| parsed_filter.matches(f));
            report.total_packets = report.frames.len();
            report.tcp_packets = report
                .frames
                .iter()
                .filter(|f| f.protocol.eq_ignore_ascii_case("TCP"))
                .count();
            report.udp_packets = report
                .frames
                .iter()
                .filter(|f| f.protocol.eq_ignore_ascii_case("UDP"))
                .count();
        }
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
    Ok(())
}
