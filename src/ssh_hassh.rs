// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! SSH-2.0 Protocol Identification Banner & Salesforce HASSH/HASSHServer
//! Key-Exchange Fingerprinting Engine (RFC 4253 & Salesforce HASSH Standard).

use crate::error::{Result, SpecterError};
use crate::pcap::parse_pcap_bytes;
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use crate::tcp_stream::reassemble_capture_bytes;
use md5::Digest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// SSH protocol role in key-exchange negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshRole {
    Client,
    Server,
}

impl std::fmt::Display for SshRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client => write!(f, "client"),
            Self::Server => write!(f, "server"),
        }
    }
}

/// Parsed SSH-2.0 Identification Banner (RFC 4253 Section 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshBanner {
    pub raw: String,
    pub proto_version: String,
    pub software_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

/// Parsed SSH_MSG_KEXINIT (Message Type 20 / 0x14, RFC 4253 Section 7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKexInit {
    pub packet_length: u32,
    pub padding_length: u8,
    pub cookie_hex: String,
    pub kex_algorithms: String,
    pub server_host_key_algorithms: String,
    pub encryption_algorithms_client_to_server: String,
    pub encryption_algorithms_server_to_client: String,
    pub mac_algorithms_client_to_server: String,
    pub mac_algorithms_server_to_client: String,
    pub compression_algorithms_client_to_server: String,
    pub compression_algorithms_server_to_client: String,
    pub languages_client_to_server: String,
    pub languages_server_to_client: String,
    pub first_kex_packet_follows: bool,
}

/// Computed Salesforce HASSH or HASSHServer report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshHasshReport {
    pub role: SshRole,
    pub raw: String,
    pub md5: String,
    pub sha256: String,
}

/// Forensic record pairing an SSH endpoint with its banner, KEXINIT, and HASSH fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshHasshRecord {
    pub role: SshRole,
    pub hassh: String,
    pub hassh_sha256: String,
    pub hassh_raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<SshBanner>,
    pub kex: SshKexInit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_endpoint: Option<String>,
}

/// Complete capture or payload audit report for SSH traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshAuditReport {
    pub source: String,
    pub total_records: usize,
    pub client_records: usize,
    pub server_records: usize,
    pub records: Vec<SshHasshRecord>,
}

/// Parses an SSH-2.0 identification banner from a payload according to RFC 4253 Section 4.2.
/// Returns the parsed banner and the total number of bytes consumed up to and including
/// the trailing newline delimiter.
pub fn parse_ssh_banner(payload: &[u8]) -> Option<(SshBanner, usize)> {
    let mut cursor = 0;
    while cursor < payload.len() {
        let rest = &payload[cursor..];
        let line_end = rest.iter().position(|&b| b == b'\n')?;
        let full_end = cursor + line_end + 1;
        let mut line_bytes = &rest[..line_end];
        if line_bytes.ends_with(b"\r") {
            line_bytes = &line_bytes[..line_bytes.len() - 1];
        }

        if line_bytes.starts_with(b"SSH-") {
            let line_str = std::str::from_utf8(line_bytes).ok()?;
            let parts: Vec<&str> = line_str.splitn(3, '-').collect();
            if parts.len() >= 3 {
                let proto_version = parts[1].to_string();
                let software_and_comments = parts[2];
                let (software_version, comments) = match software_and_comments.find(' ') {
                    Some(space_idx) => {
                        let sw = &software_and_comments[..space_idx];
                        let cm = &software_and_comments[space_idx + 1..];
                        (
                            sw.to_string(),
                            if cm.is_empty() {
                                None
                            } else {
                                Some(cm.to_string())
                            },
                        )
                    }
                    None => (software_and_comments.to_string(), None),
                };

                let banner = SshBanner {
                    raw: line_str.to_string(),
                    proto_version,
                    software_version,
                    comments,
                };
                return Some((banner, full_end));
            }
        }
        cursor = full_end;
    }
    None
}

#[inline]
fn read_namelist(buf: &[u8], offset: &mut usize) -> Result<String> {
    if buf.len().saturating_sub(*offset) < 4 {
        return Err(SpecterError::MalformedSsh(
            "Truncated name-list length field".into(),
        ));
    }
    let len = u32::from_be_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ]) as usize;
    *offset += 4;
    if buf.len().saturating_sub(*offset) < len {
        return Err(SpecterError::MalformedSsh(format!(
            "Truncated name-list string: requested {len} bytes, only {} available",
            buf.len().saturating_sub(*offset)
        )));
    }
    let end = match offset.checked_add(len) {
        Some(e) if e <= buf.len() => e,
        _ => {
            return Err(SpecterError::MalformedSsh(
                "Name-list length overflow".into(),
            ))
        }
    };
    let s = std::str::from_utf8(&buf[*offset..end])
        .map_err(|e| SpecterError::MalformedSsh(format!("Invalid UTF-8 in name-list: {e}")))?;
    *offset = end;
    Ok(s.to_string())
}

fn parse_kexinit_body(packet_length: u32, padding_length: u8, body: &[u8]) -> Result<SshKexInit> {
    if body.is_empty() {
        return Err(SpecterError::MalformedSsh(
            "Empty SSH message payload".into(),
        ));
    }
    let msg_type = body[0];
    if msg_type != 20 {
        return Err(SpecterError::MalformedSsh(format!(
            "Expected SSH_MSG_KEXINIT (type 20 / 0x14), found type {msg_type}"
        )));
    }
    if body.len() < 17 {
        return Err(SpecterError::MalformedSsh(
            "Truncated SSH_MSG_KEXINIT cookie field".into(),
        ));
    }
    let cookie_hex = hex::encode(&body[1..17]);
    let mut offset = 17;

    let kex_algorithms = read_namelist(body, &mut offset)?;
    let server_host_key_algorithms = read_namelist(body, &mut offset)?;
    let encryption_algorithms_client_to_server = read_namelist(body, &mut offset)?;
    let encryption_algorithms_server_to_client = read_namelist(body, &mut offset)?;
    let mac_algorithms_client_to_server = read_namelist(body, &mut offset)?;
    let mac_algorithms_server_to_client = read_namelist(body, &mut offset)?;
    let compression_algorithms_client_to_server = read_namelist(body, &mut offset)?;
    let compression_algorithms_server_to_client = read_namelist(body, &mut offset)?;
    let languages_client_to_server = read_namelist(body, &mut offset)?;
    let languages_server_to_client = read_namelist(body, &mut offset)?;

    let first_kex_packet_follows = offset < body.len() && body[offset] != 0;

    Ok(SshKexInit {
        packet_length,
        padding_length,
        cookie_hex,
        kex_algorithms,
        server_host_key_algorithms,
        encryption_algorithms_client_to_server,
        encryption_algorithms_server_to_client,
        mac_algorithms_client_to_server,
        mac_algorithms_server_to_client,
        compression_algorithms_client_to_server,
        compression_algorithms_server_to_client,
        languages_client_to_server,
        languages_server_to_client,
        first_kex_packet_follows,
    })
}

/// Parses an SSH_MSG_KEXINIT packet from binary packet bytes or raw message payload.
pub fn parse_ssh_kexinit(payload: &[u8]) -> Result<SshKexInit> {
    if payload.is_empty() {
        return Err(SpecterError::MalformedSsh("Empty SSH payload".into()));
    }

    // Skip preceding banner if embedded in stream
    let actual_payload = if let Some((_, banner_end)) = parse_ssh_banner(payload) {
        &payload[banner_end..]
    } else {
        payload
    };

    if actual_payload.is_empty() {
        return Err(SpecterError::MalformedSsh(
            "Payload contained banner but no subsequent KEXINIT packet".into(),
        ));
    }

    // Case 1: RFC 4253 binary packet header: packet_length (4 bytes) + padding_length (1 byte)
    if actual_payload.len() >= 5 {
        let pkt_len = u32::from_be_bytes([
            actual_payload[0],
            actual_payload[1],
            actual_payload[2],
            actual_payload[3],
        ]) as usize;
        let pad_len = actual_payload[4] as usize;
        let min_len = pad_len.saturating_add(18);

        if pkt_len >= min_len {
            if let Some(total_len) = 4usize.checked_add(pkt_len) {
                if total_len <= actual_payload.len()
                    && actual_payload.len() > 5
                    && actual_payload[5] == 20
                {
                    let payload_len = pkt_len.saturating_sub(1).saturating_sub(pad_len);
                    if let Some(body_end) = 5usize.checked_add(payload_len) {
                        if body_end <= actual_payload.len() {
                            let body = &actual_payload[5..body_end];
                            if let Ok(kex) = parse_kexinit_body(pkt_len as u32, pad_len as u8, body)
                            {
                                return Ok(kex);
                            }
                        }
                    }
                }
            }
        }
    }

    // Case 2: Raw message payload starting with type 20
    if actual_payload[0] == 20 {
        if let Ok(kex) = parse_kexinit_body(actual_payload.len() as u32, 0, actual_payload) {
            return Ok(kex);
        }
    }

    // Case 3: Scan for binary packet boundary containing type 20
    for i in 0..actual_payload.len().saturating_sub(6) {
        if actual_payload[i + 5] == 20 {
            let pkt_len = u32::from_be_bytes([
                actual_payload[i],
                actual_payload[i + 1],
                actual_payload[i + 2],
                actual_payload[i + 3],
            ]) as usize;
            let pad_len = actual_payload[i + 4] as usize;
            let min_len = pad_len.saturating_add(18);
            if pkt_len >= min_len {
                if let Some(needed_end) = (i + 4).checked_add(pkt_len) {
                    if needed_end <= actual_payload.len() {
                        let payload_len = pkt_len.saturating_sub(1).saturating_sub(pad_len);
                        let body_start = i + 5;
                        if let Some(body_end) = body_start.checked_add(payload_len) {
                            if body_end <= actual_payload.len() {
                                let body = &actual_payload[body_start..body_end];
                                if let Ok(kex) =
                                    parse_kexinit_body(pkt_len as u32, pad_len as u8, body)
                                {
                                    return Ok(kex);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err(SpecterError::MalformedSsh(
        "No valid SSH_MSG_KEXINIT packet found in payload".into(),
    ))
}

/// Computes Salesforce HASSH (client) or HASSHServer fingerprints from a parsed KEXINIT.
/// Returns `(raw_string, md5_hex, sha256_hex)`.
pub fn compute_hassh(kex: &SshKexInit, role: SshRole) -> (String, String, String) {
    let raw = match role {
        SshRole::Client => format!(
            "{};{};{};{}",
            kex.kex_algorithms,
            kex.encryption_algorithms_client_to_server,
            kex.mac_algorithms_client_to_server,
            kex.compression_algorithms_client_to_server
        ),
        SshRole::Server => format!(
            "{};{};{};{}",
            kex.kex_algorithms,
            kex.encryption_algorithms_server_to_client,
            kex.mac_algorithms_server_to_client,
            kex.compression_algorithms_server_to_client
        ),
    };

    let mut md5 = md5::Md5::new();
    md5.update(raw.as_bytes());
    let md5_hex = hex::encode(md5.finalize());

    let mut sha256 = sha2::Sha256::new();
    sha256.update(raw.as_bytes());
    let sha256_hex = hex::encode(sha256.finalize());

    (raw, md5_hex, sha256_hex)
}

/// Computes a structured `SshHasshReport`.
pub fn compute_hassh_report(kex: &SshKexInit, role: SshRole) -> SshHasshReport {
    let (raw, md5, sha256) = compute_hassh(kex, role);
    SshHasshReport {
        role,
        raw,
        md5,
        sha256,
    }
}

fn append_namelist(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Builds a deterministic, RFC 4253-compliant synthetic `SSH_MSG_KEXINIT` binary packet.
pub fn build_synthetic_ssh_kexinit(role: SshRole) -> Vec<u8> {
    let cookie = [
        0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ];

    let (kex, host_key, enc_c2s, enc_s2c, mac_c2s, mac_s2c, comp_c2s, comp_s2c) = match role {
        SshRole::Client => (
            "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
            "ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
            "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr",
            "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr",
            "umac-64-etm@openssh.com,hmac-sha2-256",
            "umac-64-etm@openssh.com,hmac-sha2-256",
            "none,zlib@openssh.com",
            "none,zlib@openssh.com",
        ),
        SshRole::Server => (
            "curve25519-sha256,diffie-hellman-group14-sha256",
            "ssh-ed25519,rsa-sha2-512",
            "aes256-ctr,aes128-ctr",
            "aes256-ctr,aes128-ctr",
            "hmac-sha2-256,umac-64-etm@openssh.com",
            "hmac-sha2-256,umac-64-etm@openssh.com",
            "none",
            "none",
        ),
    };

    let mut body = Vec::with_capacity(256);
    body.push(20); // SSH_MSG_KEXINIT
    body.extend_from_slice(&cookie);
    append_namelist(&mut body, kex);
    append_namelist(&mut body, host_key);
    append_namelist(&mut body, enc_c2s);
    append_namelist(&mut body, enc_s2c);
    append_namelist(&mut body, mac_c2s);
    append_namelist(&mut body, mac_s2c);
    append_namelist(&mut body, comp_c2s);
    append_namelist(&mut body, comp_s2c);
    append_namelist(&mut body, ""); // languages_client_to_server
    append_namelist(&mut body, ""); // languages_server_to_client
    body.push(0); // first_kex_packet_follows = false
    body.extend_from_slice(&0u32.to_be_bytes()); // reserved = 0

    // Compute RFC 4253 padding (multiple of 8, minimum 4 bytes)
    let unpadded = 4 + 1 + body.len();
    let rem = unpadded % 8;
    let mut pad_len = if rem == 0 { 8 } else { 8 - rem };
    if pad_len < 4 {
        pad_len += 8;
    }

    let pkt_len = (1 + body.len() + pad_len) as u32;
    let mut packet = Vec::with_capacity(4 + 1 + body.len() + pad_len);
    packet.extend_from_slice(&pkt_len.to_be_bytes());
    packet.push(pad_len as u8);
    packet.extend_from_slice(&body);
    packet.resize(packet.len() + pad_len, 0);

    packet
}

fn build_ipv4_tcp_frame(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(54 + payload.len());
    // Ethernet II (14 bytes)
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    // IPv4 header (20 bytes)
    frame.push(0x45);
    frame.push(0x00);
    let total_len = (20 + 20 + payload.len()) as u16;
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&0xbeefu16.to_be_bytes());
    frame.extend_from_slice(&0x4000u16.to_be_bytes());
    frame.push(64); // TTL
    frame.push(6); // TCP
    frame.extend_from_slice(&0u16.to_be_bytes()); // checksum
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);

    // TCP header (20 bytes)
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&1000u32.to_be_bytes()); // seq
    frame.extend_from_slice(&2000u32.to_be_bytes()); // ack
    frame.push(0x50); // data offset 5
    frame.push(0x18); // ACK + PSH
    frame.extend_from_slice(&8192u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());

    // Payload
    frame.extend_from_slice(payload);
    frame
}

/// Builds a deterministic synthetic PCAP capture containing an SSH exchange
/// with Client & Server banners and Client & Server KEXINIT packets.
pub fn build_synthetic_ssh_pcap() -> Vec<u8> {
    let mut pcap = Vec::new();
    // PCAP Global Header
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    pcap.extend_from_slice(&2u16.to_le_bytes()); // major
    pcap.extend_from_slice(&4u16.to_le_bytes()); // minor
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    pcap.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET

    let client_ip = [192, 168, 1, 100];
    let server_ip = [10, 0, 0, 1];
    let client_port = 54321;
    let server_port = 22;

    let client_banner_bytes = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
    let server_banner_bytes = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n";
    let client_kex = build_synthetic_ssh_kexinit(SshRole::Client);
    let server_kex = build_synthetic_ssh_kexinit(SshRole::Server);

    let packets = [
        (
            build_ipv4_tcp_frame(
                client_ip,
                server_ip,
                client_port,
                server_port,
                client_banner_bytes,
            ),
            1700000000u32,
            100000u32,
        ),
        (
            build_ipv4_tcp_frame(
                server_ip,
                client_ip,
                server_port,
                client_port,
                server_banner_bytes,
            ),
            1700000000u32,
            120000u32,
        ),
        (
            build_ipv4_tcp_frame(client_ip, server_ip, client_port, server_port, &client_kex),
            1700000000u32,
            150000u32,
        ),
        (
            build_ipv4_tcp_frame(server_ip, client_ip, server_port, client_port, &server_kex),
            1700000000u32,
            180000u32,
        ),
    ];

    for (pkt, ts_sec, ts_usec) in &packets {
        let len = pkt.len() as u32;
        pcap.extend_from_slice(&ts_sec.to_le_bytes());
        pcap.extend_from_slice(&ts_usec.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(pkt);
    }

    pcap
}

/// Forensically audits raw bytes, packet streams, or PCAP/PCAPNG captures for
/// SSH-2.0 identification banners, KEXINIT negotiations, and Salesforce HASSH fingerprints.
pub fn audit_ssh_bytes(bytes: &[u8], source_label: &str) -> Result<SshAuditReport> {
    if bytes.is_empty() {
        return Err(SpecterError::InvalidArgument(
            "Empty bytes for SSH audit".into(),
        ));
    }

    let mut records = Vec::new();

    // Check if input is a PCAP or PCAPNG capture
    if is_pcapng(bytes) || parse_pcap_bytes(bytes).is_ok() {
        let mut banner_map: HashMap<(String, String), SshBanner> = HashMap::new();

        // Pass 1: Try TCP stream reassembly for complete flow reconstruction
        if let Ok(streams) = reassemble_capture_bytes(bytes, true) {
            for s in streams {
                let client_ep = s.client.clone();
                let server_ep = s.server.clone();

                // Inspect client direction
                if let Some(c_hex) = s.client_payload_hex.as_deref() {
                    if let Ok(c_bytes) = hex::decode(c_hex) {
                        let mut banner = None;
                        let mut kex_bytes = &c_bytes[..];
                        if let Some((b, end)) = parse_ssh_banner(&c_bytes) {
                            banner = Some(b);
                            kex_bytes = &c_bytes[end..];
                        }
                        if let Ok(kex) = parse_ssh_kexinit(kex_bytes) {
                            let (raw, md5, sha256) = compute_hassh(&kex, SshRole::Client);
                            records.push(SshHasshRecord {
                                role: SshRole::Client,
                                hassh: md5,
                                hassh_sha256: sha256,
                                hassh_raw: raw,
                                banner,
                                kex,
                                src_endpoint: Some(client_ep.clone()),
                                dst_endpoint: Some(server_ep.clone()),
                            });
                        }
                    }
                }

                // Inspect server direction
                if let Some(s_hex) = s.server_payload_hex.as_deref() {
                    if let Ok(s_bytes) = hex::decode(s_hex) {
                        let mut banner = None;
                        let mut kex_bytes = &s_bytes[..];
                        if let Some((b, end)) = parse_ssh_banner(&s_bytes) {
                            banner = Some(b);
                            kex_bytes = &s_bytes[end..];
                        }
                        if let Ok(kex) = parse_ssh_kexinit(kex_bytes) {
                            let (raw, md5, sha256) = compute_hassh(&kex, SshRole::Server);
                            records.push(SshHasshRecord {
                                role: SshRole::Server,
                                hassh: md5,
                                hassh_sha256: sha256,
                                hassh_raw: raw,
                                banner,
                                kex,
                                src_endpoint: Some(server_ep.clone()),
                                dst_endpoint: Some(client_ep.clone()),
                            });
                        }
                    }
                }
            }
        }

        // Pass 2: If reassembly produced no records, inspect individual packet frames
        if records.is_empty() {
            let frames = if is_pcapng(bytes) {
                parse_pcapng_bytes(bytes)?.frames
            } else {
                parse_pcap_bytes(bytes)?.frames
            };

            for f in &frames {
                let src_ep = format!("{}:{}", f.src_ip, f.src_port);
                let dst_ep = format!("{}:{}", f.dst_ip, f.dst_port);
                let key = (src_ep.clone(), dst_ep.clone());

                if let Some((b, _)) = parse_ssh_banner(&f.payload) {
                    banner_map.insert(key.clone(), b);
                }

                if let Ok(kex) = parse_ssh_kexinit(&f.payload) {
                    let role = if f.dst_port == 22 {
                        SshRole::Client
                    } else if f.src_port == 22
                        || kex.encryption_algorithms_client_to_server.is_empty()
                    {
                        SshRole::Server
                    } else {
                        SshRole::Client
                    };
                    let (raw, md5, sha256) = compute_hassh(&kex, role);
                    let banner = banner_map.get(&key).cloned();
                    records.push(SshHasshRecord {
                        role,
                        hassh: md5,
                        hassh_sha256: sha256,
                        hassh_raw: raw,
                        banner,
                        kex,
                        src_endpoint: Some(src_ep),
                        dst_endpoint: Some(dst_ep),
                    });
                }
            }
        }
    } else {
        // Raw SSH byte stream or standalone packet
        let mut banner = None;
        let mut kex_bytes = bytes;
        if let Some((b, end)) = parse_ssh_banner(bytes) {
            banner = Some(b);
            kex_bytes = &bytes[end..];
        }

        let kex = parse_ssh_kexinit(kex_bytes)?;
        let role = SshRole::Client;
        let (raw, md5, sha256) = compute_hassh(&kex, role);
        records.push(SshHasshRecord {
            role,
            hassh: md5,
            hassh_sha256: sha256,
            hassh_raw: raw,
            banner,
            kex,
            src_endpoint: None,
            dst_endpoint: None,
        });
    }

    if records.is_empty() {
        return Err(SpecterError::MalformedSsh(
            "No SSH banner or KEXINIT messages found".into(),
        ));
    }

    let client_records = records.iter().filter(|r| r.role == SshRole::Client).count();
    let server_records = records.iter().filter(|r| r.role == SshRole::Server).count();

    Ok(SshAuditReport {
        source: source_label.to_string(),
        total_records: records.len(),
        client_records,
        server_records,
        records,
    })
}
