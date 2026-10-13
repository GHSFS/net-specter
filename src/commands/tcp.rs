// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{Result, SpecterError};
use crate::tcp_stream::reassemble_capture_bytes;
use std::fs;
use std::path::Path;

pub fn handle_tcp_stream(file: &Path, dump_payload: bool, json: bool) -> Result<()> {
    let bytes = fs::read(file)?;
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
    Ok(())
}
