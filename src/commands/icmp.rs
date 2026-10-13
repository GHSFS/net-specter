// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! CLI handler for ICMP Echo covert tunnel and anomaly auditing.

use crate::commands::load_bytes_or_hex;
use crate::error::{Result, SpecterError};
use crate::icmp_tunnel::{audit_icmp_bytes, IcmpTunnelVerdict};

pub fn handle_icmp_tunnel(file_or_hex: &str, dump_payload: bool, json: bool) -> Result<()> {
    let raw = load_bytes_or_hex(file_or_hex)?;
    let report = audit_icmp_bytes(&raw, file_or_hex)?;

    if json {
        let out = serde_json::to_string_pretty(&report)
            .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?;
        println!("{out}");
    } else {
        println!(
            "ICMP Covert Tunnel Audit: {} capture frame(s), {} ICMP frame(s) from {}",
            report.total_capture_frames, report.total_icmp_frames, report.source
        );
        println!(
            "  Requests: {} | Replies: {} | Conversations: {}",
            report.echo_requests,
            report.echo_replies,
            report.conversations.len()
        );
        println!("  Overall Verdict: {:?}", report.overall_verdict);
        println!("  Summary: {}", report.summary_narrative);
        println!();

        for (i, c) in report.conversations.iter().enumerate() {
            println!(
                "  Conversation #{}: {} <-> {} (ID 0x{:04x}, {:?})",
                i + 1,
                c.client_ip,
                c.server_ip,
                c.identifier,
                c.version
            );
            println!(
                "    Requests: {} | Replies: {} | Seq Gaps: {} | Mismatches: {}",
                c.request_count, c.reply_count, c.sequence_gaps, c.payload_mismatches
            );
            println!(
                "    Max Payload: {} bytes | Mean Entropy: {:.2} bits/byte | Verdict: {:?}",
                c.max_payload_len, c.mean_entropy, c.verdict
            );
            if !c.detected_threats.is_empty() {
                println!("    Threat Indicators:");
                for t in &c.detected_threats {
                    println!("      - {t}");
                }
            }
        }

        if (dump_payload || report.overall_verdict != IcmpTunnelVerdict::Clean)
            && !report.anomalous_frames.is_empty()
        {
            println!();
            println!(
                "  Anomalous Frames ({} detected):",
                report.anomalous_frames.len()
            );
            for f in report.anomalous_frames.iter().take(20) {
                println!(
                    "    Frame #{:<4} [{:?}] Seq {:<5} Len {:<4} Entropy {:.2} | {}",
                    f.frame_index,
                    f.echo_type,
                    f.sequence,
                    f.payload_len,
                    f.payload_entropy,
                    f.pattern_label
                );
                if dump_payload {
                    println!("      Preview: {}", f.payload_preview);
                }
                for a in &f.anomalies {
                    println!("      ! {a}");
                }
            }
        }
    }

    Ok(())
}
