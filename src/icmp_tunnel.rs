// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! ICMP Echo Payload & Timing Covert Tunnel Detector.
//!
//! Decodes ICMPv4 (RFC 792) and ICMPv6 (RFC 4443) Echo Request and Reply frames,
//! tracking conversation state, sequence continuity, Shannon entropy, standard OS
//! ping payload signatures (Windows, Linux, macOS), and detecting covert tunneling,
//! payload tampering, and data exfiltration.

use crate::error::{Result, SpecterError};
use crate::pcap::{decode_frame, parse_pcap_bytes, DecodedFrame};
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

pub const ICMPV4_TYPE_ECHO_REPLY: u8 = 0;
pub const ICMPV4_TYPE_ECHO_REQUEST: u8 = 8;
pub const ICMPV6_TYPE_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_TYPE_ECHO_REPLY: u8 = 129;

pub const WINDOWS_PING_PAYLOAD: &[u8] = b"abcdefghijklmnopqrstuvwabcdefghi";

/// ICMP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcmpVersion {
    V4,
    V6,
}

/// ICMP Echo message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcmpEchoType {
    EchoRequest,
    EchoReply,
    Other(u8),
}

/// Forensic classification of ICMP traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcmpTunnelVerdict {
    Clean,
    Suspicious,
    TunnelDetected,
}

/// Parsed ICMP Echo frame with security inspection telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpEchoFrame {
    pub frame_index: usize,
    pub timestamp_ns: u64,
    pub version: IcmpVersion,
    pub echo_type: IcmpEchoType,
    pub src_ip: String,
    pub dst_ip: String,
    pub identifier: u16,
    pub sequence: u16,
    pub payload_len: usize,
    pub payload_entropy: f64,
    pub is_standard_pattern: bool,
    pub pattern_label: String,
    pub payload_preview: String,
    pub anomalies: Vec<String>,
}

/// Aggregated metrics for an ICMP Echo conversation between two hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpConversationSummary {
    pub client_ip: String,
    pub server_ip: String,
    pub identifier: u16,
    pub version: IcmpVersion,
    pub request_count: usize,
    pub reply_count: usize,
    pub sequence_gaps: usize,
    pub duplicate_sequences: usize,
    pub payload_mismatches: usize,
    pub max_payload_len: usize,
    pub mean_entropy: f64,
    pub high_entropy_count: usize,
    pub verdict: IcmpTunnelVerdict,
    pub detected_threats: Vec<String>,
}

/// Comprehensive ICMP tunnel audit report for a capture file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpAuditReport {
    pub source: String,
    pub total_capture_frames: usize,
    pub total_icmp_frames: usize,
    pub echo_requests: usize,
    pub echo_replies: usize,
    pub conversations: Vec<IcmpConversationSummary>,
    pub anomalous_frames: Vec<IcmpEchoFrame>,
    pub overall_verdict: IcmpTunnelVerdict,
    pub summary_narrative: String,
}

/// Calculates Shannon entropy ($H = -\sum p \log_2 p$) in bits per byte [0.0, 8.0].
pub fn compute_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Inspects payload bytes against known standard OS ping patterns.
pub fn detect_payload_pattern(payload: &[u8]) -> (&'static str, bool) {
    if payload.is_empty() {
        return ("Empty Payload", true);
    }

    // Windows standard 32-byte ping pattern: 'a'..'w' repeated
    if payload.len() == 32 && payload == WINDOWS_PING_PAYLOAD {
        return ("Windows Standard Ping (32-byte alphabet)", true);
    }
    if payload.len() >= 16 && payload.starts_with(b"abcdefgh") {
        return ("Windows-Variant Ping (ASCII alphabet)", true);
    }

    // Linux standard ping: 56 bytes, first 8-16 bytes timeval, followed by 0x10..0x37 or ASCII seq
    if payload.len() == 56 {
        let tail = &payload[16..];
        let is_linux_hex = tail
            .iter()
            .enumerate()
            .all(|(i, &b)| b == ((0x10 + i) as u8));
        let is_linux_ascii = tail
            .iter()
            .enumerate()
            .all(|(i, &b)| b == ((b'!' + (i as u8)) & 0x7f));
        if is_linux_hex || is_linux_ascii {
            return ("Linux Standard Ping (56-byte timeval + sequence)", true);
        }
    }

    // All zero or constant fill
    if payload.iter().all(|&b| b == 0) {
        return ("Zero-Filled Payload", true);
    }
    let first = payload[0];
    if payload.iter().all(|&b| b == first) {
        return ("Constant-Byte Repeating Fill", true);
    }

    ("Non-Standard Payload", false)
}

/// Inspects payload bytes for plain-text command strings and exfiltration signatures.
fn scan_exfiltration_signatures(payload: &[u8]) -> Vec<String> {
    let mut signs = Vec::new();
    let lower = payload.to_ascii_lowercase();

    let signatures: &[(&[u8], &str)] = &[
        (b"cmd.exe", "Windows Command Shell (cmd.exe)"),
        (b"powershell", "PowerShell invocation"),
        (b"/bin/sh", "Unix Shell (/bin/sh)"),
        (b"/bin/bash", "Bourne Again Shell (/bin/bash)"),
        (b"whoami", "Identity reconnaissance (whoami)"),
        (b"cat /etc", "System configuration exfiltration"),
        (b"http/", "Tunneled HTTP traffic"),
        (b"get ", "HTTP GET Request"),
        (b"post ", "HTTP POST Request"),
        (b"ssh-", "Tunneled SSH Protocol"),
        (b"begin rsa", "Cryptographic key exfiltration"),
        (b"ptun", "ptunnel / PingTunnel signature"),
    ];

    for &(needle, desc) in signatures {
        if lower.windows(needle.len()).any(|w| w == needle) {
            signs.push(desc.to_string());
        }
    }
    signs
}

/// Generates a sanitized ASCII/hex preview of a payload.
fn format_payload_preview(payload: &[u8], max_len: usize) -> String {
    let display_len = payload.len().min(max_len);
    let mut preview = String::new();
    for &b in &payload[..display_len] {
        if b.is_ascii_graphic() || b == b' ' {
            preview.push(b as char);
        } else {
            preview.push('.');
        }
    }
    if payload.len() > max_len {
        preview.push_str("...");
    }
    preview
}

/// Parses raw ICMP bytes from an IP packet payload slice.
pub fn parse_icmp_echo(
    raw: &[u8],
    frame_index: usize,
    timestamp_ns: u64,
    src_ip: &str,
    dst_ip: &str,
    version: IcmpVersion,
) -> Option<IcmpEchoFrame> {
    if raw.len() < 8 {
        return None;
    }

    let icmp_type = raw[0];
    let _icmp_code = raw[1];
    let identifier = u16::from_be_bytes([raw[4], raw[5]]);
    let sequence = u16::from_be_bytes([raw[6], raw[7]]);
    let payload = &raw[8..];

    let echo_type = match version {
        IcmpVersion::V4 => match icmp_type {
            ICMPV4_TYPE_ECHO_REQUEST => IcmpEchoType::EchoRequest,
            ICMPV4_TYPE_ECHO_REPLY => IcmpEchoType::EchoReply,
            other => IcmpEchoType::Other(other),
        },
        IcmpVersion::V6 => match icmp_type {
            ICMPV6_TYPE_ECHO_REQUEST => IcmpEchoType::EchoRequest,
            ICMPV6_TYPE_ECHO_REPLY => IcmpEchoType::EchoReply,
            other => IcmpEchoType::Other(other),
        },
    };

    let entropy = compute_shannon_entropy(payload);
    let (pattern_label, is_standard) = detect_payload_pattern(payload);
    let mut anomalies = Vec::new();

    // Check abnormal payload size
    if payload.len() > 128 {
        anomalies.push(format!(
            "Abnormally large payload size ({} bytes > 128 bytes)",
            payload.len()
        ));
    }

    // Check entropy threshold for encrypted/compressed covert tunnels
    if payload.len() >= 32 && entropy >= 5.5 {
        anomalies.push(format!(
            "High Shannon entropy ({entropy:.2} bits/byte) indicative of encrypted/compressed tunneling"
        ));
    }

    // Check signatures
    let sigs = scan_exfiltration_signatures(payload);
    for sig in sigs {
        anomalies.push(format!("Signature detected: {sig}"));
    }

    Some(IcmpEchoFrame {
        frame_index,
        timestamp_ns,
        version,
        echo_type,
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        identifier,
        sequence,
        payload_len: payload.len(),
        payload_entropy: entropy,
        is_standard_pattern: is_standard,
        pattern_label: pattern_label.to_string(),
        payload_preview: format_payload_preview(payload, 32),
        anomalies,
    })
}

#[derive(Default)]
struct ConversationTracker {
    version: Option<IcmpVersion>,
    requests: usize,
    replies: usize,
    sequences: Vec<u16>,
    payload_mismatches: usize,
    max_payload_len: usize,
    total_entropy: f64,
    high_entropy_count: usize,
    request_payloads: HashMap<u16, Vec<u8>>,
    threats: Vec<String>,
}

/// Audits arbitrary capture data (PCAP, PCAPNG, or raw packet bytes) for ICMP covert tunnels.
pub fn audit_icmp_bytes(data: &[u8], source_name: &str) -> Result<IcmpAuditReport> {
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
    } else {
        // Attempt raw packet decode
        if let Ok(df) = decode_frame(1, 0, 0, data.len() as u32, 1, data) {
            frames.push(df);
        } else {
            return Err(SpecterError::MalformedIcmp(
                "Provided buffer is not a valid PCAP, PCAPNG, or raw Ethernet frame".into(),
            ));
        }
    }

    let total_capture_frames = frames.len();
    let mut total_icmp_frames = 0;
    let mut total_requests = 0;
    let mut total_replies = 0;
    let mut parsed_frames: Vec<IcmpEchoFrame> = Vec::new();
    let mut conversations: HashMap<(String, String, u16), ConversationTracker> = HashMap::new();

    for f in &frames {
        let is_v4 = f.protocol == "ICMP" || f.protocol == "IP_1";
        let is_v6 = f.protocol == "ICMPv6" || f.protocol == "IP_58";

        if !is_v4 && !is_v6 {
            continue;
        }

        total_icmp_frames += 1;
        let version = if is_v6 {
            IcmpVersion::V6
        } else {
            IcmpVersion::V4
        };
        let ts_ns = (f.ts_sec as u64) * 1_000_000_000 + (f.ts_subsec as u64);

        if let Some(parsed) =
            parse_icmp_echo(&f.payload, f.index, ts_ns, &f.src_ip, &f.dst_ip, version)
        {
            let raw_echo_payload = if f.payload.len() >= 8 {
                f.payload[8..].to_vec()
            } else {
                Vec::new()
            };

            let conv_key = if parsed.echo_type == IcmpEchoType::EchoRequest {
                total_requests += 1;
                (
                    parsed.src_ip.clone(),
                    parsed.dst_ip.clone(),
                    parsed.identifier,
                )
            } else if parsed.echo_type == IcmpEchoType::EchoReply {
                total_replies += 1;
                (
                    parsed.dst_ip.clone(),
                    parsed.src_ip.clone(),
                    parsed.identifier,
                )
            } else {
                continue;
            };

            let entry = conversations.entry(conv_key).or_default();
            entry.version = Some(version);
            entry.max_payload_len = entry.max_payload_len.max(parsed.payload_len);
            entry.total_entropy += parsed.payload_entropy;
            if parsed.payload_entropy >= 5.5 {
                entry.high_entropy_count += 1;
            }

            match parsed.echo_type {
                IcmpEchoType::EchoRequest => {
                    entry.requests += 1;
                    entry.sequences.push(parsed.sequence);
                    entry
                        .request_payloads
                        .insert(parsed.sequence, raw_echo_payload);
                }
                IcmpEchoType::EchoReply => {
                    entry.replies += 1;
                    // Check payload symmetry with request
                    if let Some(req_payload) = entry.request_payloads.get(&parsed.sequence) {
                        if req_payload != &raw_echo_payload {
                            entry.payload_mismatches += 1;
                            entry.threats.push(format!(
                                "Payload mismatch on seq {}: Request len {} != Reply len {} (RFC 792 violation / covert tunnel)",
                                parsed.sequence,
                                req_payload.len(),
                                raw_echo_payload.len()
                            ));
                        }
                    } else {
                        entry.threats.push(format!(
                            "Orphaned Echo Reply on seq {}: no preceding Echo Request recorded",
                            parsed.sequence
                        ));
                    }
                }
                _ => {}
            }

            for a in &parsed.anomalies {
                if !entry.threats.contains(a) {
                    entry.threats.push(a.clone());
                }
            }

            parsed_frames.push(parsed);
        }
    }

    let mut conv_summaries = Vec::new();
    let mut overall_verdict = IcmpTunnelVerdict::Clean;
    let mut anomalous_frames = Vec::new();

    for ((client, server, id), mut tracker) in conversations {
        let total_packets = tracker.requests + tracker.replies;
        let mean_entropy = if total_packets > 0 {
            tracker.total_entropy / (total_packets as f64)
        } else {
            0.0
        };

        // Sequence gap and duplicate checks
        let mut sequence_gaps = 0;
        let mut duplicate_sequences = 0;
        if tracker.sequences.len() > 1 {
            for w in tracker.sequences.windows(2) {
                if w[1] > w[0] + 1 {
                    sequence_gaps += (w[1] - w[0] - 1) as usize;
                } else if w[1] == w[0] {
                    duplicate_sequences += 1;
                }
            }
        }

        if sequence_gaps > 0 {
            tracker
                .threats
                .push(format!("Detected {sequence_gaps} sequence number gap(s)"));
        }
        if duplicate_sequences > 0 {
            tracker.threats.push(format!(
                "Detected {duplicate_sequences} duplicate sequence number(s)"
            ));
        }

        let verdict = if tracker.payload_mismatches > 0
            || tracker.high_entropy_count > 0
            || tracker
                .threats
                .iter()
                .any(|t| t.contains("Signature detected") || t.contains("large payload"))
        {
            IcmpTunnelVerdict::TunnelDetected
        } else if sequence_gaps > 0 || !tracker.threats.is_empty() {
            IcmpTunnelVerdict::Suspicious
        } else {
            IcmpTunnelVerdict::Clean
        };

        if verdict == IcmpTunnelVerdict::TunnelDetected {
            overall_verdict = IcmpTunnelVerdict::TunnelDetected;
        } else if verdict == IcmpTunnelVerdict::Suspicious
            && overall_verdict != IcmpTunnelVerdict::TunnelDetected
        {
            overall_verdict = IcmpTunnelVerdict::Suspicious;
        }

        // Zeroize memory of buffered request payloads for safety
        for mut p in tracker.request_payloads.into_values() {
            p.zeroize();
        }

        conv_summaries.push(IcmpConversationSummary {
            client_ip: client,
            server_ip: server,
            identifier: id,
            version: tracker.version.unwrap_or(IcmpVersion::V4),
            request_count: tracker.requests,
            reply_count: tracker.replies,
            sequence_gaps,
            duplicate_sequences,
            payload_mismatches: tracker.payload_mismatches,
            max_payload_len: tracker.max_payload_len,
            mean_entropy,
            high_entropy_count: tracker.high_entropy_count,
            verdict,
            detected_threats: tracker.threats,
        });
    }

    for frame in parsed_frames {
        if !frame.anomalies.is_empty() || !frame.is_standard_pattern {
            anomalous_frames.push(frame);
        }
    }

    let summary_narrative = match overall_verdict {
        IcmpTunnelVerdict::Clean => {
            format!("Audit clean: {total_icmp_frames} ICMP frames inspected across {} conversation(s). All conform to standard OS ping profiles.", conv_summaries.len())
        }
        IcmpTunnelVerdict::Suspicious => {
            format!("Suspicious anomalies flagged: {total_icmp_frames} ICMP frames inspected. Sequence gaps, non-standard patterns, or orphaned replies observed.")
        }
        IcmpTunnelVerdict::TunnelDetected => {
            format!("CRITICAL: ICMP covert tunnel or data exfiltration detected across {} conversation(s). Request/Reply payload divergence, high entropy, or command strings identified.", conv_summaries.len())
        }
    };

    Ok(IcmpAuditReport {
        source: source_name.to_string(),
        total_capture_frames,
        total_icmp_frames,
        echo_requests: total_requests,
        echo_replies: total_replies,
        conversations: conv_summaries,
        anomalous_frames,
        overall_verdict,
        summary_narrative,
    })
}

/// Builds a deterministic synthetic PCAP capture file containing ICMP test flows:
/// 1. Standard Windows Ping (Clean, 32-byte matching payload)
/// 2. Standard Linux Ping (Clean, 56-byte matching payload)
/// 3. Covert Tunnel Flow (TunnelDetected, payload mismatch, high entropy, sequence gap)
/// 4. Plaintext Exfiltration Flow (Command string signatures)
pub fn build_synthetic_icmp_pcap() -> Vec<u8> {
    let mut packets: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    let mut ts_sec = 1700000000u32;

    // Helper: craft IPv4 + ICMP Ethernet frame
    let make_icmp_frame =
        |src: [u8; 4], dst: [u8; 4], icmp_type: u8, id: u16, seq: u16, payload: &[u8]| -> Vec<u8> {
            let mut icmp = Vec::with_capacity(8 + payload.len());
            icmp.push(icmp_type);
            icmp.push(0); // code
            icmp.extend_from_slice(&[0, 0]); // checksum placeholder
            icmp.extend_from_slice(&id.to_be_bytes());
            icmp.extend_from_slice(&seq.to_be_bytes());
            icmp.extend_from_slice(payload);

            // Compute ICMP checksum
            let mut sum = 0u32;
            let mut i = 0;
            while i < icmp.len() {
                let word = if i + 1 < icmp.len() {
                    u16::from_be_bytes([icmp[i], icmp[i + 1]]) as u32
                } else {
                    (icmp[i] as u32) << 8
                };
                sum = sum.wrapping_add(word);
                i += 2;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let checksum = !(sum as u16);
            icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

            // IPv4 Header
            let ip_len = (20 + icmp.len()) as u16;
            let mut ip = Vec::with_capacity(20 + icmp.len());
            ip.push(0x45);
            ip.push(0x00);
            ip.extend_from_slice(&ip_len.to_be_bytes());
            ip.extend_from_slice(&[0x12, 0x34]); // id
            ip.extend_from_slice(&[0x40, 0x00]); // flags/frag
            ip.push(64); // ttl
            ip.push(1); // proto ICMP
            ip.extend_from_slice(&[0, 0]); // ip checksum
            ip.extend_from_slice(&src);
            ip.extend_from_slice(&dst);
            ip.extend_from_slice(&icmp);

            // Ethernet Frame
            let mut eth = Vec::with_capacity(14 + ip.len());
            eth.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
            eth.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src mac
            eth.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
            eth.extend_from_slice(&ip);
            eth
        };

    // 1. Clean Windows Ping: 2 requests + 2 replies (matching 32-byte payload)
    let win_client = [192, 168, 1, 50];
    let win_server = [8, 8, 8, 8];
    for seq in 1..=2 {
        let req = make_icmp_frame(
            win_client,
            win_server,
            ICMPV4_TYPE_ECHO_REQUEST,
            0x0100,
            seq,
            WINDOWS_PING_PAYLOAD,
        );
        packets.push((ts_sec, 0, req));
        ts_sec += 1;
        let rep = make_icmp_frame(
            win_server,
            win_client,
            ICMPV4_TYPE_ECHO_REPLY,
            0x0100,
            seq,
            WINDOWS_PING_PAYLOAD,
        );
        packets.push((ts_sec, 50_000, rep));
        ts_sec += 1;
    }

    // 2. Clean Linux Ping: 1 request + 1 reply (matching 56-byte payload)
    let linux_client = [10, 0, 0, 15];
    let linux_server = [1, 1, 1, 1];
    let mut linux_payload = vec![0u8; 56];
    // Fill first 16 bytes with dummy timestamp and rest with 0x10..0x37
    linux_payload[0..8].copy_from_slice(&1700000000u64.to_le_bytes());
    linux_payload[8..16].copy_from_slice(&123456u64.to_le_bytes());
    for (idx, b) in linux_payload[16..].iter_mut().enumerate() {
        *b = (0x10 + idx) as u8;
    }
    let req2 = make_icmp_frame(
        linux_client,
        linux_server,
        ICMPV4_TYPE_ECHO_REQUEST,
        0x0200,
        1,
        &linux_payload,
    );
    packets.push((ts_sec, 0, req2));
    ts_sec += 1;
    let rep2 = make_icmp_frame(
        linux_server,
        linux_client,
        ICMPV4_TYPE_ECHO_REPLY,
        0x0200,
        1,
        &linux_payload,
    );
    packets.push((ts_sec, 20_000, rep2));
    ts_sec += 1;

    // 3. Covert Tunnel Flow: high entropy, request != reply (exfiltration/tunneling), seq gap
    let tunnel_client = [172, 16, 0, 99];
    let tunnel_server = [198, 51, 100, 7];
    // High-entropy 128-byte payload
    let mut high_entropy_req = vec![0u8; 128];
    for (i, b) in high_entropy_req.iter_mut().enumerate() {
        *b = ((i * 101 + 37) % 256) as u8;
    }
    let mut high_entropy_rep = vec![0u8; 128];
    for (i, b) in high_entropy_rep.iter_mut().enumerate() {
        *b = ((i * 173 + 89) % 256) as u8;
    }
    let req3 = make_icmp_frame(
        tunnel_client,
        tunnel_server,
        ICMPV4_TYPE_ECHO_REQUEST,
        0x9999,
        10,
        &high_entropy_req,
    );
    packets.push((ts_sec, 0, req3));
    ts_sec += 1;
    let rep3 = make_icmp_frame(
        tunnel_server,
        tunnel_client,
        ICMPV4_TYPE_ECHO_REPLY,
        0x9999,
        10,
        &high_entropy_rep,
    );
    packets.push((ts_sec, 10_000, rep3));
    ts_sec += 1;

    // Sequence gap (jump to 15) with plaintext command exfiltration
    let cmd_payload = b"GET /admin/secrets HTTP/1.1\r\nHost: c2.internal\r\ncmd.exe /c whoami";
    let req4 = make_icmp_frame(
        tunnel_client,
        tunnel_server,
        ICMPV4_TYPE_ECHO_REQUEST,
        0x9999,
        15,
        cmd_payload,
    );
    packets.push((ts_sec, 0, req4));

    // Construct classic PCAP header
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic usec LE
    pcap.extend_from_slice(&2u16.to_le_bytes()); // major
    pcap.extend_from_slice(&4u16.to_le_bytes()); // minor
    pcap.extend_from_slice(&0u32.to_le_bytes()); // thiszone
    pcap.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    pcap.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    pcap.extend_from_slice(&1u32.to_le_bytes()); // linktype Ethernet

    for (sec, subsec, pkt) in packets {
        pcap.extend_from_slice(&sec.to_le_bytes());
        pcap.extend_from_slice(&subsec.to_le_bytes());
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // caplen
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // origlen
        pcap.extend_from_slice(&pkt);
    }

    pcap
}
