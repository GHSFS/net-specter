// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::commands::load_bytes_or_hex;
use crate::error::{Result, SpecterError};
use crate::ssh_hassh::audit_ssh_bytes;

pub fn handle_hassh(file_or_hex: &str, json: bool) -> Result<()> {
    let raw = load_bytes_or_hex(file_or_hex)?;
    let report = audit_ssh_bytes(&raw, file_or_hex)?;

    if json {
        let out = serde_json::to_string_pretty(&report)
            .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?;
        println!("{out}");
    } else {
        println!(
            "SSH HASSH Audit: {} record(s) ({} client, {} server) from {}",
            report.total_records, report.client_records, report.server_records, report.source
        );
        for r in &report.records {
            println!(
                "  [{}] HASSH={} | SHA256={}",
                r.role, r.hassh, r.hassh_sha256
            );
            if let Some(ref b) = r.banner {
                println!("    Banner  : {}", b.raw);
                println!(
                    "    Software: {} (v{})",
                    b.software_version, b.proto_version
                );
                if let Some(ref c) = b.comments {
                    println!("    Comments: {}", c);
                }
            }
            if let (Some(ref src), Some(ref dst)) = (&r.src_endpoint, &r.dst_endpoint) {
                println!("    Endpoints: {src} -> {dst}");
            }
            println!("    Raw HASSH: {}", r.hassh_raw);
        }
    }
    Ok(())
}
