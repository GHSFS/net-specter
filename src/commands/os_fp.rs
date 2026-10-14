// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! CLI handler for TCP SYN passive OS fingerprinting and JA4T audit.

use crate::commands::load_bytes_or_hex;
use crate::error::{Result, SpecterError};
use crate::p0f::audit_os_fingerprints;

pub fn handle_os_fp(file_or_hex: &str, json: bool) -> Result<()> {
    let raw = load_bytes_or_hex(file_or_hex)?;
    let report = audit_os_fingerprints(&raw, file_or_hex)?;

    if json {
        let out = serde_json::to_string_pretty(&report)
            .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?;
        println!("{out}");
    } else {
        println!(
            "TCP SYN Passive OS Fingerprint Audit: {} frame(s), {} TCP, {} SYN from {}",
            report.total_capture_frames,
            report.total_tcp_frames,
            report.total_syn_frames,
            report.source
        );
        println!("  Discovered Hosts: {}", report.hosts.len());
        println!("  Anomalous Frames: {}", report.anomalous_frames.len());
        println!("  Summary: {}", report.summary);
        println!();

        for (i, h) in report.hosts.iter().enumerate() {
            println!("  Host #{}: {} [{:?}]", i + 1, h.ip, h.role);
            println!(
                "    OS Match     : {} ({}) [{:.0}% confidence]",
                h.os_flavor,
                h.os_family,
                h.confidence * 100.0
            );
            println!("    JA4T (FoxIO) : {} (hash: {})", h.ja4t, h.ja4t_hash);
            println!("    p0f Signature: {}", h.p0f_sig);
            println!(
                "    TTL / Hops   : initial TTL {} -> distance {} hop(s) (seen: {})",
                h.initial_ttl,
                h.distance_hops,
                h.initial_ttl.saturating_sub(h.distance_hops)
            );
            println!("    Packets Seen : {}", h.total_syn_packets);
            if !h.anomalies.is_empty() {
                println!("    Anomalies Detected:");
                for a in &h.anomalies {
                    println!("      ! {a}");
                }
            }
            println!();
        }

        if !report.anomalous_frames.is_empty() {
            println!(
                "  Anomalous Packets Details ({} detected):",
                report.anomalous_frames.len()
            );
            for f in report.anomalous_frames.iter().take(10) {
                println!(
                    "    Frame #{:<4} [{:?}] {}:{} -> {}:{} | Win {:<5} | {}",
                    f.frame_index,
                    f.role,
                    f.src_ip,
                    f.src_port,
                    f.dst_ip,
                    f.dst_port,
                    f.window_size,
                    f.anomalies.join("; ")
                );
            }
        }
    }

    Ok(())
}
