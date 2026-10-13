// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::commands::load_bytes_or_hex;
use crate::error::{Result, SpecterError};
use crate::http_inspect::audit_http_bytes;

pub fn handle_http_audit(file_or_hex: &str, json: bool) -> Result<()> {
    let bytes = load_bytes_or_hex(file_or_hex)?;
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
    Ok(())
}
