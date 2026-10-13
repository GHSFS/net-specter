// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{Result, SpecterError};
use crate::pcap::{build_synthetic_pcap, parse_pcap_bytes};
use crate::pcapng::{build_synthetic_pcapng, parse_pcapng_bytes};
use std::fs;
use std::path::Path;

pub fn handle_synth_pcap(output: &Path, pcapng: bool, json: bool) -> Result<()> {
    if pcapng {
        let bytes = build_synthetic_pcapng();
        fs::write(output, &bytes)?;
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
        fs::write(output, &bytes)?;
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
    Ok(())
}
