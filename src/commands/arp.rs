// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! CLI handler for ARP spoofing and Layer-2 MITM anomaly detection.

use crate::arp_audit::{audit_arp_bytes, ArpAuditConfig};
use crate::commands::load_bytes_or_hex;
use crate::error::{Result, SpecterError};

pub fn handle_arp_audit(file_or_hex: &str, gateway: Option<&str>, json: bool) -> Result<()> {
    let raw = load_bytes_or_hex(file_or_hex)?;
    let mut config = ArpAuditConfig::default();
    if let Some(gw) = gateway {
        config.gateway_ips.push(gw.to_string());
    }

    let report = audit_arp_bytes(&raw, file_or_hex, Some(config))?;

    if json {
        let out = serde_json::to_string_pretty(&report)
            .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?;
        println!("{out}");
    } else {
        println!(
            "ARP Spoofing & Layer-2 MITM Audit: {} frame(s), {} ARP ({} req, {} rep, {} garp) from {}",
            report.total_capture_frames,
            report.total_arp_frames,
            report.requests,
            report.replies,
            report.gratuitous_count,
            report.source
        );
        println!("  Overall Verdict : {:?}", report.overall_verdict);
        println!("  Discovered Hosts: {}", report.bindings.len());
        println!("  Anomalous Frames: {}", report.anomalous_frames.len());
        println!("  Threats Detected: {}", report.detected_threats.len());
        println!("  Summary         : {}", report.summary);
        println!();

        if !report.detected_threats.is_empty() {
            println!("  [!] Threat Indicators:");
            for t in &report.detected_threats {
                println!("    * {t}");
            }
            println!();
        }

        println!("  IP-to-MAC Active Bindings:");
        for (i, b) in report.bindings.iter().enumerate() {
            let gw_tag = if b.is_gateway { " [GATEWAY]" } else { "" };
            let flap_tag = if b.is_flapping { " [FLAPPING!]" } else { "" };
            println!(
                "    #{:<2} {:<15} -> {:<17} ({} transitions){}{}",
                i + 1,
                b.ip,
                b.current_mac,
                b.mac_transitions,
                gw_tag,
                flap_tag
            );
            if b.observed_macs.len() > 1 {
                println!("        Observed MACs: {}", b.observed_macs.join(", "));
            }
            for a in &b.anomalies {
                println!("        ! {a}");
            }
        }
        println!();

        if !report.anomalous_frames.is_empty() {
            println!(
                "  Anomalous Frames (showing up to {} of {}):",
                report.anomalous_frames.len().min(10),
                report.anomalous_frames.len()
            );
            for f in report.anomalous_frames.iter().take(10) {
                println!(
                    "    Frame #{:<4} [{:?}/{:?}] {} ({}) -> {} ({})",
                    f.frame_index,
                    f.opcode,
                    f.subtype,
                    f.sender_ip,
                    f.sender_mac,
                    f.target_ip,
                    f.target_mac
                );
                for a in &f.anomalies {
                    println!("      ! {a}");
                }
            }
        }
    }

    Ok(())
}
