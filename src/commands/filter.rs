// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{Result, SpecterError};
use crate::filter::evaluate_filter_on_capture;
use std::fs;
use std::path::Path;

pub fn handle_filter(file: &Path, filter: &str, json: bool) -> Result<()> {
    let bytes = fs::read(file)?;
    let report = evaluate_filter_on_capture(&bytes, filter)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?
        );
    } else {
        println!(
            "BPF Filter: '{}' (canonical: {}) | Matched {}/{} frames (TCP={}, UDP={}, Other={})",
            report.filter_expression,
            report.canonical_expression,
            report.matched_packets,
            report.total_input_packets,
            report.tcp_matched,
            report.udp_matched,
            report.other_matched
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
    }
    Ok(())
}
