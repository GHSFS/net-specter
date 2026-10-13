// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! HTTP/1.1 request/response inspection, HTTP/2 frame and SETTINGS decoding,
//! FoxIO JA4H client fingerprint engine, and PCAP/PCAPNG capture auditing.

#![forbid(unsafe_code)]

use crate::error::{Result, SpecterError};
use crate::pcap::parse_pcap_bytes;
use crate::pcapng::is_pcapng;
use crate::tcp_stream::reassemble_capture_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const HTTP2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Zeroizing wrapper for transient sensitive payload data (cookies, auth tokens, bodies).
#[derive(Debug, Default, Clone)]
pub struct SensitiveBuffer(pub Vec<u8>);

impl Drop for SensitiveBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Decoded HTTP/2 SETTINGS frame parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http2SettingParameter {
    pub id: u16,
    pub name: String,
    pub value: u32,
}

/// Decoded HTTP/2 frame header and payload summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http2FrameReport {
    pub frame_type: u8,
    pub frame_type_name: String,
    pub flags: u8,
    pub stream_id: u32,
    pub length: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub settings: Vec<Http2SettingParameter>,
}

/// Decoded HTTP/2 connection overview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http2ConnectionReport {
    pub preface_valid: bool,
    pub frames: Vec<Http2FrameReport>,
    pub settings: Vec<Http2SettingParameter>,
}

/// FoxIO-compliant JA4H HTTP client fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja4hReport {
    pub ja4h: String,
    pub ja4h_a: String,
    pub ja4h_b: String,
    pub ja4h_c: String,
    pub ja4h_d: String,
    pub ja4h_r: String,
    pub method: String,
    pub version: String,
    pub has_cookie: bool,
    pub has_referer: bool,
    pub header_count: usize,
    pub language: String,
}

/// HTTP/1.1 parsed request report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http1RequestReport {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub referer: Option<String>,
    pub body_peek: Option<String>,
    pub ja4h: Ja4hReport,
}

/// HTTP/1.1 parsed response report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http1ResponseReport {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<String>,
    pub body_peek: Option<String>,
}

/// Comprehensive audit report across HTTP/1.1, HTTP/2, and JA4H fingerprints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpAuditReport {
    pub http1_requests: Vec<Http1RequestReport>,
    pub http1_responses: Vec<Http1ResponseReport>,
    pub http2_connections: Vec<Http2ConnectionReport>,
    pub ja4h_fingerprints: Vec<Ja4hReport>,
    pub total_messages: usize,
}

#[inline]
pub fn compute_sha256_12(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(&hasher.finalize()[..6])
}

fn normalize_language(raw: &str) -> String {
    let cleaned = raw.replace('-', "").replace(';', ",").to_ascii_lowercase();
    let first = cleaned.split(',').next().unwrap_or("").trim();
    let truncated = if first.len() >= 4 { &first[..4] } else { first };
    format!("{truncated:0<4}")
}

fn normalize_method(method: &str) -> String {
    let m = method.to_ascii_lowercase();
    if m.len() >= 2 {
        m[..2].to_string()
    } else {
        format!("{m:0<2}")
    }
}

fn normalize_version(version: &str) -> String {
    let v = version.to_ascii_uppercase();
    if v.contains("1.0") {
        "10".into()
    } else if v.contains("1.1") {
        "11".into()
    } else if v.contains("2.0") || v.contains("/2") || v == "2" {
        "20".into()
    } else if v.contains("3.0") || v.contains("/3") || v == "3" {
        "30".into()
    } else {
        "11".into()
    }
}

/// Computes FoxIO JA4H HTTP client fingerprint.
pub fn compute_ja4h(method: &str, version: &str, headers: &[(String, String)]) -> Ja4hReport {
    let method_2 = normalize_method(method);
    let version_2 = normalize_version(version);
    let (mut has_cookie, mut has_referer) = (false, false);
    let (mut accept_language, mut filtered_headers, mut cookie_pairs) =
        (None, Vec::new(), Vec::new());

    for (name, val) in headers {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with(':') {
            continue;
        }
        if lower.starts_with("cookie") {
            has_cookie = true;
            for part in val.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                if let Some((k, v)) = part.split_once('=') {
                    cookie_pairs.push((k.trim().to_string(), v.trim().to_string()));
                } else {
                    cookie_pairs.push((part.to_string(), String::new()));
                }
            }
            continue;
        }
        if lower == "referer" {
            has_referer = true;
            continue;
        }
        if lower == "accept-language" && accept_language.is_none() {
            accept_language = Some(val.as_str());
        }
        filtered_headers.push(name.clone());
    }

    let cookie_flag = if has_cookie { 'c' } else { 'n' };
    let referer_flag = if has_referer { 'r' } else { 'n' };
    let header_count = filtered_headers.len().min(99);
    let lang_4 = accept_language.map_or_else(|| "0000".into(), normalize_language);
    let ja4h_a =
        format!("{method_2}{version_2}{cookie_flag}{referer_flag}{header_count:02}{lang_4}");
    let headers_sha12 = compute_sha256_12(&filtered_headers.join(","));

    cookie_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let (cookie_names_sha12, cookie_values_sha12, raw_names, raw_values) =
        if cookie_pairs.is_empty() {
            (
                "000000000000".to_string(),
                "000000000000".to_string(),
                String::new(),
                String::new(),
            )
        } else {
            let names: Vec<&str> = cookie_pairs.iter().map(|(k, _)| k.as_str()).collect();
            let values: Vec<&str> = cookie_pairs.iter().map(|(_, v)| v.as_str()).collect();
            let (n, v) = (names.join(","), values.join(","));
            (compute_sha256_12(&n), compute_sha256_12(&v), n, v)
        };

    let ja4h = format!("{ja4h_a}_{headers_sha12}_{cookie_names_sha12}_{cookie_values_sha12}");
    let ja4h_r = format!(
        "{ja4h_a}_{}_{raw_names}_{raw_values}",
        filtered_headers.join(",")
    );

    Ja4hReport {
        ja4h,
        ja4h_a,
        ja4h_b: headers_sha12,
        ja4h_c: cookie_names_sha12,
        ja4h_d: cookie_values_sha12,
        ja4h_r,
        method: method.to_string(),
        version: version.to_string(),
        has_cookie,
        has_referer,
        header_count,
        language: lang_4,
    }
}

/// Parses an HTTP/1.1 request wire payload.
pub fn parse_http1_request(bytes: &[u8]) -> Result<Http1RequestReport> {
    let mut _sensitive = SensitiveBuffer(bytes.to_vec());
    let (header_bytes, body_bytes) = split_http_headers_body(bytes)?;
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| SpecterError::MalformedHttp(format!("Non-UTF8 headers: {e}")))?;
    let mut lines = header_str.split('\n').map(|l| l.trim_end_matches('\r'));
    let req_line = lines
        .next()
        .ok_or_else(|| SpecterError::MalformedHttp("Missing request line".into()))?;

    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 3 || !parts[2].starts_with("HTTP/") {
        return Err(SpecterError::MalformedHttp(format!(
            "Invalid request line: '{req_line}'"
        )));
    }
    let (method, uri, version) = (parts[0], parts[1], parts[2]);
    let (mut headers, mut cookies, mut referer) = (Vec::new(), Vec::new(), None);

    for line in lines.map(str::trim).filter(|l| !l.is_empty()) {
        if let Some((name, val)) = line.split_once(':') {
            let (n, v) = (name.trim().to_string(), val.trim().to_string());
            if n.eq_ignore_ascii_case("cookie") {
                for pair in v.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                    if let Some((k, val)) = pair.split_once('=') {
                        cookies.push((k.trim().to_string(), val.trim().to_string()));
                    } else {
                        cookies.push((pair.to_string(), String::new()));
                    }
                }
            } else if n.eq_ignore_ascii_case("referer") && referer.is_none() {
                referer = Some(v.clone());
            }
            headers.push((n, v));
        }
    }

    let body_peek = (!body_bytes.is_empty())
        .then(|| String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(64)]).to_string());
    let ja4h = compute_ja4h(method, version, &headers);
    Ok(Http1RequestReport {
        method: method.into(),
        uri: uri.into(),
        version: version.into(),
        headers,
        cookies,
        referer,
        body_peek,
        ja4h,
    })
}

/// Parses an HTTP/1.1 response wire payload.
pub fn parse_http1_response(bytes: &[u8]) -> Result<Http1ResponseReport> {
    let mut _sensitive = SensitiveBuffer(bytes.to_vec());
    let (header_bytes, body_bytes) = split_http_headers_body(bytes)?;
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| SpecterError::MalformedHttp(format!("Non-UTF8 headers: {e}")))?;
    let mut lines = header_str.split('\n').map(|l| l.trim_end_matches('\r'));
    let status_line = lines
        .next()
        .ok_or_else(|| SpecterError::MalformedHttp("Missing status line".into()))?;

    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 || !parts[0].starts_with("HTTP/") {
        return Err(SpecterError::MalformedHttp(format!(
            "Invalid status line: '{status_line}'"
        )));
    }
    let version = parts[0].to_string();
    let status_code: u16 = parts[1].parse().map_err(|e| {
        SpecterError::MalformedHttp(format!("Invalid status code '{}': {e}", parts[1]))
    })?;
    let reason = if parts.len() >= 3 {
        parts[2..].join(" ")
    } else {
        String::new()
    };

    let (mut headers, mut cookies) = (Vec::new(), Vec::new());
    for line in lines.map(str::trim).filter(|l| !l.is_empty()) {
        if let Some((name, val)) = line.split_once(':') {
            let (n, v) = (name.trim().to_string(), val.trim().to_string());
            if n.eq_ignore_ascii_case("set-cookie") {
                cookies.push(v.clone());
            }
            headers.push((n, v));
        }
    }

    let body_peek = (!body_bytes.is_empty())
        .then(|| String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(64)]).to_string());
    Ok(Http1ResponseReport {
        version,
        status_code,
        reason,
        headers,
        cookies,
        body_peek,
    })
}

fn split_http_headers_body(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    if bytes.is_empty() {
        return Err(SpecterError::MalformedHttp("Empty HTTP payload".into()));
    }
    let end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| (p, p + 4))
        .or_else(|| {
            bytes
                .windows(2)
                .position(|w| w == b"\n\n")
                .map(|p| (p, p + 2))
        });
    match end {
        Some((h_end, b_start)) => Ok((&bytes[..h_end], &bytes[b_start..])),
        None => Ok((bytes, &[][..])),
    }
}

pub fn decode_setting_name(id: u16) -> &'static str {
    match id {
        0x0001 => "HEADER_TABLE_SIZE",
        0x0002 => "ENABLE_PUSH",
        0x0003 => "MAX_CONCURRENT_STREAMS",
        0x0004 => "INITIAL_WINDOW_SIZE",
        0x0005 => "MAX_FRAME_SIZE",
        0x0006 => "MAX_HEADER_LIST_SIZE",
        0x0008 => "ENABLE_CONNECT_PROTOCOL",
        _ => "UNKNOWN",
    }
}

pub fn decode_frame_type_name(t: u8) -> &'static str {
    match t {
        0x00 => "DATA",
        0x01 => "HEADERS",
        0x02 => "PRIORITY",
        0x03 => "RST_STREAM",
        0x04 => "SETTINGS",
        0x05 => "PUSH_PROMISE",
        0x06 => "PING",
        0x07 => "GOAWAY",
        0x08 => "WINDOW_UPDATE",
        0x09 => "CONTINUATION",
        _ => "UNKNOWN",
    }
}

/// Parses an HTTP/2 connection preface and frame stream.
pub fn parse_http2_frames(bytes: &[u8]) -> Result<Http2ConnectionReport> {
    if bytes.len() < 9 && !bytes.starts_with(HTTP2_PREFACE) {
        return Err(SpecterError::MalformedHttp(
            "Buffer too short for HTTP/2 frames".into(),
        ));
    }
    let (preface_valid, mut offset) = if bytes.starts_with(HTTP2_PREFACE) {
        (true, 24)
    } else {
        (false, 0)
    };
    let (mut frames, mut all_settings) = (Vec::new(), Vec::new());

    while offset + 9 <= bytes.len() {
        let length = ((bytes[offset] as usize) << 16)
            | ((bytes[offset + 1] as usize) << 8)
            | (bytes[offset + 2] as usize);
        let frame_type = bytes[offset + 3];
        let flags = bytes[offset + 4];
        let stream_id = u32::from_be_bytes([
            bytes[offset + 5] & 0x7F,
            bytes[offset + 6],
            bytes[offset + 7],
            bytes[offset + 8],
        ]);
        if !preface_valid && frame_type > 0x09 {
            return Err(SpecterError::MalformedHttp(format!(
                "Unrecognized HTTP/2 frame type 0x{frame_type:02x} without connection preface"
            )));
        }
        let frame_type_name = decode_frame_type_name(frame_type).to_string();

        if offset + 9 + length > bytes.len() {
            return Err(SpecterError::MalformedHttp(format!(
                "Truncated HTTP/2 frame type 0x{frame_type:02x}: required {} bytes, remaining {}",
                9 + length,
                bytes.len() - offset
            )));
        }

        let payload = &bytes[offset + 9..offset + 9 + length];
        let mut frame_settings = Vec::new();
        match frame_type {
            0x04 => {
                if stream_id != 0 {
                    return Err(SpecterError::MalformedHttp(
                        "SETTINGS frame stream_id must be 0".into(),
                    ));
                }
                if (flags & 0x01) != 0 {
                    if length != 0 {
                        return Err(SpecterError::MalformedHttp(
                            "SETTINGS ACK frame length must be 0".into(),
                        ));
                    }
                } else {
                    if length % 6 != 0 {
                        return Err(SpecterError::MalformedHttp(format!(
                            "Invalid SETTINGS frame length {length}: must be multiple of 6"
                        )));
                    }
                    for chunk in payload.chunks_exact(6) {
                        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                        let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                        let param = Http2SettingParameter {
                            id,
                            name: decode_setting_name(id).to_string(),
                            value: val,
                        };
                        frame_settings.push(param.clone());
                        all_settings.push(param);
                    }
                }
            }
            0x06 if stream_id != 0 || length != 8 => {
                return Err(SpecterError::MalformedHttp(
                    "Invalid PING frame stream_id or length".into(),
                ));
            }
            0x08 if length != 4 => {
                return Err(SpecterError::MalformedHttp(
                    "WINDOW_UPDATE frame length must be 4".into(),
                ));
            }
            _ => {}
        }

        frames.push(Http2FrameReport {
            frame_type,
            frame_type_name,
            flags,
            stream_id,
            length,
            settings: frame_settings,
        });
        offset += 9 + length;
    }

    if offset < bytes.len() {
        return Err(SpecterError::MalformedHttp(format!(
            "Truncated HTTP/2 frame header: {} trailing bytes",
            bytes.len() - offset
        )));
    }
    if frames.is_empty() && !preface_valid {
        return Err(SpecterError::MalformedHttp(
            "No valid HTTP/2 frames found".into(),
        ));
    }
    Ok(Http2ConnectionReport {
        preface_valid,
        frames,
        settings: all_settings,
    })
}

fn is_likely_http_request(bytes: &[u8]) -> bool {
    const PREFIXES: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    PREFIXES.iter().any(|p| bytes.starts_with(p))
}

fn is_likely_http_response(bytes: &[u8]) -> bool {
    bytes.starts_with(b"HTTP/1.") || bytes.starts_with(b"HTTP/2.")
}

fn audit_single_payload(bytes: &[u8], report: &mut HttpAuditReport) {
    if bytes.is_empty() {
        return;
    }
    if bytes.starts_with(HTTP2_PREFACE) {
        if let Ok(h2_rep) = parse_http2_frames(bytes) {
            report.total_messages += 1;
            report.http2_connections.push(h2_rep);
            return;
        }
    }
    if is_likely_http_request(bytes) {
        if let Ok(req) = parse_http1_request(bytes) {
            report.ja4h_fingerprints.push(req.ja4h.clone());
            report.http1_requests.push(req);
            report.total_messages += 1;
            return;
        }
    }
    if is_likely_http_response(bytes) {
        if let Ok(resp) = parse_http1_response(bytes) {
            report.http1_responses.push(resp);
            report.total_messages += 1;
            return;
        }
    }
    if bytes.len() >= 9 {
        if let Ok(h2_rep) = parse_http2_frames(bytes) {
            if !h2_rep.frames.is_empty() {
                report.total_messages += 1;
                report.http2_connections.push(h2_rep);
            }
        }
    }
}

/// Inspects network traffic for HTTP/1.1 and HTTP/2 payloads from PCAP/PCAPNG captures or raw bytes.
pub fn audit_http_bytes(bytes: &[u8]) -> Result<HttpAuditReport> {
    if bytes.is_empty() {
        return Err(SpecterError::InvalidArgument(
            "Empty input bytes for HTTP audit".into(),
        ));
    }
    if is_pcapng(bytes) || parse_pcap_bytes(bytes).is_ok() {
        let streams = reassemble_capture_bytes(bytes, true)?;
        let mut report = HttpAuditReport::default();
        for s in streams {
            if let Some(c_hex) = s.client_payload_hex {
                if let Ok(c_bytes) = hex::decode(&c_hex) {
                    audit_single_payload(&c_bytes, &mut report);
                }
            }
            if let Some(s_hex) = s.server_payload_hex {
                if let Ok(s_bytes) = hex::decode(&s_hex) {
                    audit_single_payload(&s_bytes, &mut report);
                }
            }
        }
        if report.total_messages == 0 {
            return Err(SpecterError::MalformedHttp(
                "No HTTP/1.1 or HTTP/2 payloads identified in capture".into(),
            ));
        }
        return Ok(report);
    }

    let mut report = HttpAuditReport::default();
    audit_single_payload(bytes, &mut report);
    if report.total_messages == 0 {
        return Err(SpecterError::MalformedHttp(
            "Input is neither a valid capture nor recognizable HTTP/1.1 or HTTP/2 payload".into(),
        ));
    }
    Ok(report)
}
