// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::commands::load_bytes_or_hex;
use crate::error::{Result, SpecterError};
use crate::quic::audit_quic_bytes;

pub fn handle_quic_audit(file_or_hex: &str, json: bool) -> Result<()> {
    let bytes = load_bytes_or_hex(file_or_hex)?;
    let report = audit_quic_bytes(&bytes)?;
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
    Ok(())
}
