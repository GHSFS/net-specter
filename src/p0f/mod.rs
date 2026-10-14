// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! TCP SYN Passive OS Fingerprinting & FoxIO JA4T / JA4TS Engine (`p0f`).
//!
//! Decodes TCP SYN and SYN-ACK header options, initial TTL, window size, MSS,
//! window scale factor, and TCP options layout to identify operating system
//! families (Windows, Linux, macOS/iOS, BSD, Cisco/Solaris) and port scanners
//! (Nmap, Masscan, ZMap), generating FoxIO JA4T and p0f v3 signatures.

pub mod classify;
pub mod synth;

pub use classify::{classify_os, OsClassification};
pub use synth::build_synthetic_syn_pcap;

use crate::error::{Result, SpecterError};
use crate::pcap::{decode_frame, parse_pcap_bytes, DecodedFrame};
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const TCP_OPT_EOL: u8 = 0;
pub const TCP_OPT_NOP: u8 = 1;
pub const TCP_OPT_MSS: u8 = 2;
pub const TCP_OPT_WSCALE: u8 = 3;
pub const TCP_OPT_SACK_PERMITTED: u8 = 4;
pub const TCP_OPT_SACK: u8 = 5;
pub const TCP_OPT_TIMESTAMP: u8 = 8;

/// Single parsed TCP option descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedTcpOption {
    pub kind: u8,
    pub length: u8,
    pub name: String,
}

/// TCP conversation role derived from SYN/ACK flag combinations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TcpRole {
    Client,
    Server,
}

/// Aggregated operating system fingerprint summary for an individual host endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostOsSummary {
    pub ip: String,
    pub role: TcpRole,
    pub os_family: String,
    pub os_flavor: String,
    pub confidence: f64,
    pub ja4t: String,
    pub ja4t_hash: String,
    pub p0f_sig: String,
    pub initial_ttl: u8,
    pub distance_hops: u8,
    pub total_syn_packets: usize,
    pub anomalies: Vec<String>,
}

/// Individual packet-level OS fingerprint analysis record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsFpRecord {
    pub frame_index: usize,
    pub timestamp_ns: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub role: TcpRole,
    pub os_family: String,
    pub os_flavor: String,
    pub confidence: f64,
    pub ja4t: String,
    pub ja4t_hash: String,
    pub p0f_sig: String,
    pub ttl: u8,
    pub initial_ttl: u8,
    pub distance_hops: u8,
    pub window_size: u16,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub options_layout: String,
    pub anomalies: Vec<String>,
}

/// Comprehensive passive OS fingerprint audit report across a capture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsFpAuditReport {
    pub source: String,
    pub total_capture_frames: usize,
    pub total_tcp_frames: usize,
    pub total_syn_frames: usize,
    pub hosts: Vec<HostOsSummary>,
    pub records: Vec<OsFpRecord>,
    pub anomalous_frames: Vec<OsFpRecord>,
    pub summary: String,
}

/// Parses raw TCP options slice, extracting ordered option kinds, MSS, WSCALE, and quirks.
pub fn parse_tcp_options(
    options_raw: &[u8],
) -> (
    Vec<ParsedTcpOption>,
    Option<u16>,
    Option<u8>,
    bool,
    bool,
    Vec<String>,
) {
    let mut options = Vec::new();
    let mut mss = None;
    let mut wscale = None;
    let mut sack_permitted = false;
    let mut has_timestamps = false;
    let mut quirks = Vec::new();

    let mut pos = 0usize;
    while pos < options_raw.len() {
        let kind = options_raw[pos];
        if kind == TCP_OPT_EOL {
            options.push(ParsedTcpOption {
                kind: 0,
                length: 1,
                name: "eol".into(),
            });
            let trailing = &options_raw[pos + 1..];
            if !trailing.is_empty() && trailing.iter().any(|&b| b != 0) {
                quirks.push("trailing_non_zero_past_eol".into());
            }
            break;
        }
        if kind == TCP_OPT_NOP {
            options.push(ParsedTcpOption {
                kind: 1,
                length: 1,
                name: "nop".into(),
            });
            pos += 1;
            continue;
        }
        if pos + 1 >= options_raw.len() {
            quirks.push("truncated_option_header".into());
            break;
        }
        let len = options_raw[pos + 1];
        if len < 2 || pos + (len as usize) > options_raw.len() {
            quirks.push(format!("malformed_option_length_kind_{kind}_len_{len}"));
            break;
        }
        let opt_data = &options_raw[pos + 2..pos + (len as usize)];
        match kind {
            TCP_OPT_MSS => {
                if opt_data.len() == 2 {
                    let val = u16::from_be_bytes([opt_data[0], opt_data[1]]);
                    mss = Some(val);
                } else {
                    quirks.push("invalid_mss_length".into());
                }
                options.push(ParsedTcpOption {
                    kind,
                    length: len,
                    name: "mss".into(),
                });
            }
            TCP_OPT_WSCALE => {
                if !opt_data.is_empty() {
                    let ws = opt_data[0];
                    if ws > 14 {
                        quirks.push(format!("excessive_wscale_{ws}"));
                    }
                    wscale = Some(ws);
                } else {
                    quirks.push("invalid_wscale_length".into());
                }
                options.push(ParsedTcpOption {
                    kind,
                    length: len,
                    name: "ws".into(),
                });
            }
            TCP_OPT_SACK_PERMITTED => {
                sack_permitted = true;
                options.push(ParsedTcpOption {
                    kind,
                    length: len,
                    name: "sok".into(),
                });
            }
            TCP_OPT_TIMESTAMP => {
                has_timestamps = true;
                options.push(ParsedTcpOption {
                    kind,
                    length: len,
                    name: "ts".into(),
                });
            }
            TCP_OPT_SACK => {
                options.push(ParsedTcpOption {
                    kind,
                    length: len,
                    name: "sack".into(),
                });
            }
            other => {
                options.push(ParsedTcpOption {
                    kind,
                    length: len,
                    name: format!("opt_{other}"),
                });
            }
        }
        pos += len as usize;
    }

    (options, mss, wscale, sack_permitted, has_timestamps, quirks)
}

/// Estimates original initial TTL (32, 64, 128, 255) and network hop distance.
pub fn estimate_initial_ttl(observed_ttl: u8) -> (u8, u8) {
    let ittl: u8 = if observed_ttl <= 32 {
        32
    } else if observed_ttl <= 64 {
        64
    } else if observed_ttl <= 128 {
        128
    } else {
        255
    };
    let distance = ittl.saturating_sub(observed_ttl);
    (ittl, distance)
}

/// Computes FoxIO JA4T/JA4TS fingerprint `{window_size}_{options}_{wscale}_{mss}` and 12-char SHA-256 hash.
pub fn compute_ja4t(
    window_size: u16,
    options_kinds: &[u8],
    wscale: Option<u8>,
    mss: Option<u16>,
) -> (String, String) {
    let opt_str = if options_kinds.is_empty() {
        "0".to_string()
    } else {
        options_kinds
            .iter()
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    let ws_str = wscale.unwrap_or(0).to_string();
    let mss_str = mss.unwrap_or(0).to_string();
    let raw = format!("{window_size}_{opt_str}_{ws_str}_{mss_str}");

    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let full_hash = hex::encode(hasher.finalize());
    let hash_12 = full_hash[..12].to_string();

    (raw, hash_12)
}

/// Formats a p0f v3 style signature string.
#[allow(clippy::too_many_arguments)]
pub fn compute_p0f_signature(
    ip_version: u8,
    ittl: u8,
    distance: u8,
    options_len: usize,
    mss: Option<u16>,
    window_size: u16,
    wscale: Option<u8>,
    options: &[ParsedTcpOption],
    quirks: &[String],
    payload_len: usize,
) -> String {
    let mss_str = mss.map(|m| m.to_string()).unwrap_or_else(|| "*".into());
    let scale_str = wscale
        .map(|w| w.to_string())
        .unwrap_or_else(|| "none".into());
    let layout_str = if options.is_empty() {
        "none".into()
    } else {
        options
            .iter()
            .map(|o| o.name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    let quirks_str = if quirks.is_empty() {
        "none".into()
    } else {
        quirks.join(",")
    };
    format!("{ip_version}:{ittl}:{distance}:{options_len}:{mss_str}:{window_size},{scale_str}:{layout_str}:{quirks_str}:{payload_len}")
}

/// Audits capture data (PCAP, PCAPNG, or raw packet) and performs passive OS fingerprinting on all SYN packets.
pub fn audit_os_fingerprints(data: &[u8], source_name: &str) -> Result<OsFpAuditReport> {
    let mut frames: Vec<DecodedFrame> = Vec::new();

    if is_pcapng(data) {
        let rep = parse_pcapng_bytes(data)?;
        frames = rep.frames;
    } else if data.len() >= 24
        && (data.starts_with(&[0xd4, 0xc3, 0xb2, 0xa1])
            || data.starts_with(&[0xa1, 0xb2, 0xc3, 0xd4])
            || data.starts_with(&[0x4d, 0x3c, 0xb2, 0xa1])
            || data.starts_with(&[0xa1, 0xb2, 0x3c, 0x4d]))
    {
        let rep = parse_pcap_bytes(data)?;
        frames = rep.frames;
    } else if let Ok(df) = decode_frame(1, 0, 0, data.len() as u32, 1, data) {
        frames.push(df);
    } else {
        return Err(SpecterError::MalformedFp(
            "Provided buffer is not a valid PCAP, PCAPNG, or raw Ethernet frame".into(),
        ));
    }

    let total_capture_frames = frames.len();
    let mut total_tcp_frames = 0usize;
    let mut total_syn_frames = 0usize;
    let mut records = Vec::new();
    let mut anomalous_frames = Vec::new();
    let mut host_map: HashMap<(String, TcpRole), HostOsSummary> = HashMap::new();

    for f in &frames {
        if f.protocol != "TCP" {
            continue;
        }
        total_tcp_frames += 1;

        let flags = match f.tcp_flags {
            Some(fl) => fl,
            None => continue,
        };

        if !flags.syn {
            continue;
        }
        total_syn_frames += 1;

        let role = if flags.ack {
            TcpRole::Server
        } else {
            TcpRole::Client
        };

        let raw_options = f.tcp_options.as_deref().unwrap_or(&[]);
        let (options, mss, wscale, _sack_ok, has_ts, mut quirks) = parse_tcp_options(raw_options);
        let options_kinds: Vec<u8> = options.iter().map(|o| o.kind).collect();
        let options_layout = if options.is_empty() {
            "none".into()
        } else {
            options
                .iter()
                .map(|o| o.name.as_str())
                .collect::<Vec<_>>()
                .join(",")
        };

        let win = f.tcp_window.unwrap_or(0);
        let df = f.ip_df.unwrap_or(false);
        let (ittl, distance) = estimate_initial_ttl(f.ttl);

        let mut anomalies = Vec::new();
        if flags.fin {
            anomalies.push("SYN+FIN flag anomaly (evasive port scan)".into());
        }
        if flags.rst {
            anomalies.push("SYN+RST flag anomaly (evasive port scan)".into());
        }
        if win == 0 {
            anomalies.push("Zero TCP window size on SYN (potential DoS/scanner probe)".into());
        }
        if mss.is_none() && role == TcpRole::Client {
            anomalies.push("Missing MSS option on SYN packet".into());
        }
        if let Some(m) = mss {
            if !(536..=65531).contains(&m) {
                anomalies.push(format!("Anomalous MSS value ({m} bytes)"));
            }
        }
        if let Some(w) = wscale {
            if w > 14 {
                anomalies.push(format!("Illegal WSCALE factor ({w} > 14)"));
            }
        }
        anomalies.append(&mut quirks);

        let (ja4t, ja4t_hash) = compute_ja4t(win, &options_kinds, wscale, mss);
        let p0f_sig = compute_p0f_signature(
            f.ip_version,
            ittl,
            distance,
            raw_options.len(),
            mss,
            win,
            wscale,
            &options,
            &anomalies,
            f.payload.len(),
        );

        let os_class = classify_os(ittl, &options_kinds, wscale, mss, win, has_ts, df);

        let ts_ns = (f.ts_sec as u64) * 1_000_000_000 + (f.ts_subsec as u64);
        let record = OsFpRecord {
            frame_index: f.index,
            timestamp_ns: ts_ns,
            src_ip: f.src_ip.clone(),
            dst_ip: f.dst_ip.clone(),
            src_port: f.src_port,
            dst_port: f.dst_port,
            role,
            os_family: os_class.family.clone(),
            os_flavor: os_class.flavor.clone(),
            confidence: os_class.confidence,
            ja4t: ja4t.clone(),
            ja4t_hash: ja4t_hash.clone(),
            p0f_sig: p0f_sig.clone(),
            ttl: f.ttl,
            initial_ttl: ittl,
            distance_hops: distance,
            window_size: win,
            mss,
            wscale,
            options_layout,
            anomalies: anomalies.clone(),
        };

        if !anomalies.is_empty() {
            anomalous_frames.push(record.clone());
        }

        let host_entry =
            host_map
                .entry((f.src_ip.clone(), role))
                .or_insert_with(|| HostOsSummary {
                    ip: f.src_ip.clone(),
                    role,
                    os_family: os_class.family.clone(),
                    os_flavor: os_class.flavor.clone(),
                    confidence: os_class.confidence,
                    ja4t: ja4t.clone(),
                    ja4t_hash: ja4t_hash.clone(),
                    p0f_sig: p0f_sig.clone(),
                    initial_ttl: ittl,
                    distance_hops: distance,
                    total_syn_packets: 0,
                    anomalies: Vec::new(),
                });

        host_entry.total_syn_packets += 1;
        for a in anomalies {
            if !host_entry.anomalies.contains(&a) {
                host_entry.anomalies.push(a);
            }
        }

        records.push(record);
    }

    let mut hosts: Vec<HostOsSummary> = host_map.into_values().collect();
    hosts.sort_by(|a, b| a.ip.cmp(&b.ip));

    let summary = format!(
        "Audited {} frame(s): {} TCP packets, {} SYN/SYN-ACK frames analyzed across {} unique host(s). {} anomalous frame(s) detected.",
        total_capture_frames,
        total_tcp_frames,
        total_syn_frames,
        hosts.len(),
        anomalous_frames.len()
    );

    Ok(OsFpAuditReport {
        source: source_name.to_string(),
        total_capture_frames,
        total_tcp_frames,
        total_syn_frames,
        hosts,
        records,
        anomalous_frames,
        summary,
    })
}
