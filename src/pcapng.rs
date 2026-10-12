// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::dns::{parse_dns_packet, DnsPacketReport};
use crate::error::{Result, SpecterError};
use crate::pcap::{decode_frame, DecodedFrame, LINKTYPE_ETHERNET};
use crate::tls_ja3::{parse_tls_client_hello, TlsClientHelloReport};
use serde::{Deserialize, Serialize};

pub const BLOCK_TYPE_SHB: u32 = 0x0A0D_0D0A;
pub const BLOCK_TYPE_IDB: u32 = 0x0000_0001;
pub const BLOCK_TYPE_SPB: u32 = 0x0000_0003;
pub const BLOCK_TYPE_NRB: u32 = 0x0000_0004;
pub const BLOCK_TYPE_ISB: u32 = 0x0000_0005;
pub const BLOCK_TYPE_EPB: u32 = 0x0000_0006;

pub const BOM_BIG_ENDIAN: [u8; 4] = [0x1A, 0x2E, 0x3B, 0x4C];
pub const BOM_LITTLE_ENDIAN: [u8; 4] = [0x4C, 0x3B, 0x2E, 0x1A];

pub const OPT_ENDOFOPT: u16 = 0;
pub const OPT_COMMENT: u16 = 1;

pub const SHB_HARDWARE: u16 = 2;
pub const SHB_OS: u16 = 3;
pub const SHB_USER_APP: u16 = 4;

pub const IF_NAME: u16 = 2;
pub const IF_DESCRIPTION: u16 = 3;
pub const IF_TSRESOL: u16 = 9;

/// Metadata parsed from a PCAPNG Section Header Block (SHB).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcapngSectionHeader {
    pub version_major: u16,
    pub version_minor: u16,
    pub section_length: i64,
    pub big_endian: bool,
    pub hardware: Option<String>,
    pub os: Option<String>,
    pub user_app: Option<String>,
    pub comment: Option<String>,
}

/// Interface metadata parsed from an Interface Description Block (IDB).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcapngInterface {
    pub linktype: u32,
    pub snaplen: u32,
    pub name: Option<String>,
    pub description: Option<String>,
    pub ts_resol: u8,
    pub comment: Option<String>,
}

/// Comprehensive inspection report of a PCAPNG capture file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapngInspectReport {
    pub section: PcapngSectionHeader,
    pub interfaces: Vec<PcapngInterface>,
    pub total_packets: usize,
    pub tcp_packets: usize,
    pub udp_packets: usize,
    pub frames: Vec<DecodedFrame>,
    pub tls_handshakes: Vec<TlsClientHelloReport>,
    pub dns_messages: Vec<DnsPacketReport>,
}

#[inline]
fn read_u16(bytes: &[u8], big_endian: bool) -> u16 {
    if big_endian {
        u16::from_be_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_le_bytes([bytes[0], bytes[1]])
    }
}

#[inline]
fn read_u32(bytes: &[u8], big_endian: bool) -> u32 {
    if big_endian {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }
}

#[inline]
fn read_i64(bytes: &[u8], big_endian: bool) -> i64 {
    if big_endian {
        i64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    } else {
        i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }
}

/// Reconstructs a full 64-bit nanosecond timestamp from PCAPNG timestamp parts
/// and the interface's `tsresol` option.
#[inline]
pub fn reconstruct_nanos(ts_high: u32, ts_low: u32, ts_resol: u8) -> u64 {
    let raw = ((ts_high as u64) << 32) | (ts_low as u64);
    match ts_resol {
        9 => raw,
        6 => raw.saturating_mul(1_000),
        3 => raw.saturating_mul(1_000_000),
        0 => raw.saturating_mul(1_000_000_000),
        r if (r & 0x80) == 0 => {
            if r < 9 {
                let factor = 10u64.checked_pow((9 - r) as u32).unwrap_or(u64::MAX);
                raw.saturating_mul(factor)
            } else if let Some(div) = 10u64.checked_pow((r - 9) as u32) {
                raw.checked_div(div).unwrap_or(0)
            } else {
                0
            }
        }
        _ => raw.saturating_mul(1_000),
    }
}

/// Fast magic test to determine whether a byte slice is a PCAPNG capture.
#[inline]
pub fn is_pcapng(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == [0x0A, 0x0D, 0x0D, 0x0A]
}

fn parse_options(bytes: &[u8], big_endian: bool) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut opts = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        if opts.len() >= 1024 {
            return Err(SpecterError::InvalidPcapng(
                "Excessive options count in block (DoS protection)".into(),
            ));
        }
        let code = read_u16(&bytes[offset..offset + 2], big_endian);
        let len = read_u16(&bytes[offset + 2..offset + 4], big_endian) as usize;
        offset += 4;
        if code == OPT_ENDOFOPT {
            break;
        }
        if offset + len > bytes.len() {
            return Err(SpecterError::InvalidPcapng(format!(
                "Option 0x{code:04x} length {len} exceeds block options slice boundary"
            )));
        }
        let val = bytes[offset..offset + len].to_vec();
        opts.push((code, val));
        let pad = (4 - (len % 4)) % 4;
        offset = (offset + len + pad).min(bytes.len());
    }
    Ok(opts)
}

/// Parses raw PCAPNG bytes into a comprehensive forensics inspection report.
pub fn parse_pcapng_bytes(data: &[u8]) -> Result<PcapngInspectReport> {
    if !is_pcapng(data) {
        return Err(SpecterError::InvalidPcapng(
            "Missing PCAPNG Section Header Block magic (0x0A0D0D0A)".into(),
        ));
    }
    if data.len() < 28 {
        return Err(SpecterError::InvalidPcapng(
            "Buffer shorter than minimal 28-byte Section Header Block".into(),
        ));
    }

    let mut pos = 0usize;
    let mut big_endian = false;
    let mut current_section: Option<PcapngSectionHeader> = None;
    let mut interfaces: Vec<PcapngInterface> = Vec::new();
    let mut frames = Vec::new();
    let mut tls_handshakes = Vec::new();
    let mut dns_messages = Vec::new();
    let mut tcp_packets = 0usize;
    let mut udp_packets = 0usize;
    let mut frame_index = 0usize;

    while pos < data.len() {
        if pos + 12 > data.len() {
            return Err(SpecterError::InvalidPcapng(format!(
                "Truncated block header at offset {pos}"
            )));
        }

        if data[pos..pos + 4] == [0x0A, 0x0D, 0x0D, 0x0A] {
            if pos + 28 > data.len() {
                return Err(SpecterError::InvalidPcapng(format!(
                    "Truncated Section Header Block at offset {pos}"
                )));
            }
            let bom = &data[pos + 8..pos + 12];
            big_endian = if bom == BOM_BIG_ENDIAN {
                true
            } else if bom == BOM_LITTLE_ENDIAN {
                false
            } else {
                return Err(SpecterError::InvalidPcapng(format!(
                    "Invalid byte order magic 0x{:02x}{:02x}{:02x}{:02x} at offset {}",
                    bom[0],
                    bom[1],
                    bom[2],
                    bom[3],
                    pos + 8
                )));
            };

            let block_len = read_u32(&data[pos + 4..pos + 8], big_endian) as usize;
            if block_len < 28 || block_len % 4 != 0 {
                return Err(SpecterError::InvalidPcapng(format!(
                    "Invalid Section Header Block length {block_len} at offset {pos}"
                )));
            }
            if pos + block_len > data.len() {
                return Err(SpecterError::InvalidPcapng(format!(
                    "Section Header Block length {block_len} exceeds data bounds at offset {pos}"
                )));
            }
            let trailing_len =
                read_u32(&data[pos + block_len - 4..pos + block_len], big_endian) as usize;
            if trailing_len != block_len {
                return Err(SpecterError::InvalidPcapng(format!(
                    "SHB trailing length mismatch ({trailing_len} != {block_len}) at offset {pos}"
                )));
            }

            let version_major = read_u16(&data[pos + 12..pos + 14], big_endian);
            let version_minor = read_u16(&data[pos + 14..pos + 16], big_endian);
            let section_length = read_i64(&data[pos + 16..pos + 24], big_endian);

            let mut hardware = None;
            let mut os = None;
            let mut user_app = None;
            let mut comment = None;

            if block_len > 28 {
                let options_slice = &data[pos + 24..pos + block_len - 4];
                let opts = parse_options(options_slice, big_endian)?;
                for (code, val) in opts {
                    match code {
                        OPT_COMMENT => comment = Some(String::from_utf8_lossy(&val).to_string()),
                        SHB_HARDWARE => hardware = Some(String::from_utf8_lossy(&val).to_string()),
                        SHB_OS => os = Some(String::from_utf8_lossy(&val).to_string()),
                        SHB_USER_APP => user_app = Some(String::from_utf8_lossy(&val).to_string()),
                        _ => {}
                    }
                }
            }

            current_section = Some(PcapngSectionHeader {
                version_major,
                version_minor,
                section_length,
                big_endian,
                hardware,
                os,
                user_app,
                comment,
            });

            pos += block_len;
            continue;
        }

        let block_type = read_u32(&data[pos..pos + 4], big_endian);
        let block_len = read_u32(&data[pos + 4..pos + 8], big_endian) as usize;
        if block_len < 12 || block_len % 4 != 0 {
            return Err(SpecterError::InvalidPcapng(format!(
                "Invalid block length {block_len} for block 0x{block_type:08x} at offset {pos}"
            )));
        }
        if pos + block_len > data.len() {
            return Err(SpecterError::InvalidPcapng(format!(
                "Block 0x{block_type:08x} length {block_len} exceeds data bounds at offset {pos}"
            )));
        }
        let trailing_len =
            read_u32(&data[pos + block_len - 4..pos + block_len], big_endian) as usize;
        if trailing_len != block_len {
            return Err(SpecterError::InvalidPcapng(format!(
                "Block 0x{block_type:08x} trailing length mismatch ({trailing_len} != {block_len}) at offset {pos}"
            )));
        }

        match block_type {
            BLOCK_TYPE_IDB => {
                if block_len < 20 {
                    return Err(SpecterError::InvalidPcapng(format!(
                        "Interface Description Block shorter than 20 bytes at offset {pos}"
                    )));
                }
                let linktype = read_u16(&data[pos + 8..pos + 10], big_endian) as u32;
                let snaplen = read_u32(&data[pos + 12..pos + 16], big_endian);
                let mut name = None;
                let mut description = None;
                let mut ts_resol = 6u8;
                let mut comment = None;

                if block_len > 20 {
                    let options_slice = &data[pos + 16..pos + block_len - 4];
                    let opts = parse_options(options_slice, big_endian)?;
                    for (code, val) in opts {
                        match code {
                            OPT_COMMENT => {
                                comment = Some(String::from_utf8_lossy(&val).to_string())
                            }
                            IF_NAME => name = Some(String::from_utf8_lossy(&val).to_string()),
                            IF_DESCRIPTION => {
                                description = Some(String::from_utf8_lossy(&val).to_string())
                            }
                            IF_TSRESOL => {
                                if let Some(&r) = val.first() {
                                    ts_resol = r;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                interfaces.push(PcapngInterface {
                    linktype,
                    snaplen,
                    name,
                    description,
                    ts_resol,
                    comment,
                });
            }
            BLOCK_TYPE_EPB => {
                if block_len < 32 {
                    return Err(SpecterError::InvalidPcapng(format!(
                        "Enhanced Packet Block shorter than 32 bytes at offset {pos}"
                    )));
                }
                let iface_id = read_u32(&data[pos + 8..pos + 12], big_endian);
                let ts_high = read_u32(&data[pos + 12..pos + 16], big_endian);
                let ts_low = read_u32(&data[pos + 16..pos + 20], big_endian);
                let caplen = read_u32(&data[pos + 20..pos + 24], big_endian) as usize;
                let wirelen = read_u32(&data[pos + 24..pos + 28], big_endian);

                if caplen > block_len - 32 {
                    return Err(SpecterError::InvalidPcapng(format!(
                        "EPB caplen {caplen} exceeds available block payload ({}) at offset {pos}",
                        block_len - 32
                    )));
                }
                let padded_len = (caplen + 3) & !3;
                if padded_len > block_len - 32 {
                    return Err(SpecterError::InvalidPcapng(format!(
                        "EPB caplen {caplen} with padding ({padded_len}) exceeds block boundary at offset {pos}"
                    )));
                }

                let iface = interfaces.get(iface_id as usize);
                let linktype = iface.map(|i| i.linktype).unwrap_or(LINKTYPE_ETHERNET);
                let ts_resol = iface.map(|i| i.ts_resol).unwrap_or(6);

                let raw_ts = ((ts_high as u64) << 32) | (ts_low as u64);
                let (ts_sec, ts_subsec) = if ts_resol == 9 {
                    (
                        (raw_ts / 1_000_000_000) as u32,
                        (raw_ts % 1_000_000_000) as u32,
                    )
                } else if ts_resol == 6 {
                    ((raw_ts / 1_000_000) as u32, (raw_ts % 1_000_000) as u32)
                } else {
                    let nanos = reconstruct_nanos(ts_high, ts_low, ts_resol);
                    (
                        (nanos / 1_000_000_000) as u32,
                        (nanos % 1_000_000_000) as u32,
                    )
                };

                let raw_pkt = &data[pos + 28..pos + 28 + caplen];
                let decoded =
                    decode_frame(frame_index, ts_sec, ts_subsec, wirelen, linktype, raw_pkt)?;
                frame_index += 1;

                match decoded.protocol.as_str() {
                    "TCP" => {
                        tcp_packets += 1;
                        if decoded.payload.first() == Some(&0x16) {
                            if let Ok(ja3) = parse_tls_client_hello(&decoded.payload) {
                                tls_handshakes.push(ja3);
                            }
                        }
                    }
                    "UDP" => {
                        udp_packets += 1;
                        if (decoded.src_port == 53
                            || decoded.dst_port == 53
                            || decoded.src_port == 5353
                            || decoded.dst_port == 5353)
                            && decoded.payload.len() >= 12
                        {
                            if let Ok(dns_rep) = parse_dns_packet(&decoded.payload) {
                                dns_messages.push(dns_rep);
                            }
                        }
                    }
                    _ => {}
                }

                frames.push(decoded);
            }
            BLOCK_TYPE_SPB => {
                if block_len < 16 {
                    return Err(SpecterError::InvalidPcapng(format!(
                        "Simple Packet Block shorter than 16 bytes at offset {pos}"
                    )));
                }
                let wirelen = read_u32(&data[pos + 8..pos + 12], big_endian);
                let max_cap = block_len - 16;
                let caplen = (wirelen as usize).min(max_cap);
                let raw_pkt = &data[pos + 12..pos + 12 + caplen];
                let linktype = interfaces
                    .first()
                    .map(|i| i.linktype)
                    .unwrap_or(LINKTYPE_ETHERNET);

                let decoded = decode_frame(frame_index, 0, 0, wirelen, linktype, raw_pkt)?;
                frame_index += 1;

                match decoded.protocol.as_str() {
                    "TCP" => {
                        tcp_packets += 1;
                        if decoded.payload.first() == Some(&0x16) {
                            if let Ok(ja3) = parse_tls_client_hello(&decoded.payload) {
                                tls_handshakes.push(ja3);
                            }
                        }
                    }
                    "UDP" => {
                        udp_packets += 1;
                        if (decoded.src_port == 53
                            || decoded.dst_port == 53
                            || decoded.src_port == 5353
                            || decoded.dst_port == 5353)
                            && decoded.payload.len() >= 12
                        {
                            if let Ok(dns_rep) = parse_dns_packet(&decoded.payload) {
                                dns_messages.push(dns_rep);
                            }
                        }
                    }
                    _ => {}
                }

                frames.push(decoded);
            }
            _ => {
                // Gracefully skip ISB, NRB, Custom Blocks, etc.
            }
        }

        pos += block_len;
    }

    let section = current_section.ok_or_else(|| {
        SpecterError::InvalidPcapng("No Section Header Block found in capture".into())
    })?;

    Ok(PcapngInspectReport {
        section,
        interfaces,
        total_packets: frame_index,
        tcp_packets,
        udp_packets,
        frames,
        tls_handshakes,
        dns_messages,
    })
}

fn push_opt(buf: &mut Vec<u8>, code: u16, val: &[u8]) {
    buf.extend_from_slice(&code.to_le_bytes());
    buf.extend_from_slice(&(val.len() as u16).to_le_bytes());
    buf.extend_from_slice(val);
    let pad = (4 - (val.len() % 4)) % 4;
    buf.resize(buf.len() + pad, 0);
}

fn push_opt_end(buf: &mut Vec<u8>) {
    buf.extend_from_slice(&OPT_ENDOFOPT.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
}

fn wrap_block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let total_len = (12 + body.len()) as u32;
    let mut block = Vec::with_capacity(total_len as usize);
    block.extend_from_slice(&block_type.to_le_bytes());
    block.extend_from_slice(&total_len.to_le_bytes());
    block.extend_from_slice(body);
    block.extend_from_slice(&total_len.to_le_bytes());
    block
}

/// Generates a deterministic multi-packet PCAPNG capture with nanosecond precision.
pub fn build_synthetic_pcapng() -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);

    // 1. Section Header Block (SHB)
    let mut shb_body = Vec::new();
    shb_body.extend_from_slice(&BOM_LITTLE_ENDIAN);
    shb_body.extend_from_slice(&1u16.to_le_bytes()); // Major
    shb_body.extend_from_slice(&0u16.to_le_bytes()); // Minor
    shb_body.extend_from_slice(&(-1i64).to_le_bytes()); // Unspecified section length

    push_opt(&mut shb_body, SHB_HARDWARE, b"x86_64");
    push_opt(&mut shb_body, SHB_OS, b"Rust Forensics Engine");
    push_opt(&mut shb_body, SHB_USER_APP, b"net-specter 0.2.0");
    push_opt(
        &mut shb_body,
        OPT_COMMENT,
        b"Synthetic PCAPNG capture with nanosecond precision",
    );
    push_opt_end(&mut shb_body);
    out.extend_from_slice(&wrap_block(BLOCK_TYPE_SHB, &shb_body));

    // 2. Interface Description Block (IDB)
    let mut idb_body = Vec::new();
    idb_body.extend_from_slice(&1u16.to_le_bytes()); // LinkType Ethernet (1)
    idb_body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    idb_body.extend_from_slice(&65535u32.to_le_bytes()); // SnapLen

    push_opt(&mut idb_body, IF_NAME, b"eth0");
    push_opt(
        &mut idb_body,
        IF_DESCRIPTION,
        b"Synthetic Gigabit Forensics Interface",
    );
    push_opt(&mut idb_body, IF_TSRESOL, &[9u8]); // 10^-9 (nanoseconds)
    push_opt(
        &mut idb_body,
        OPT_COMMENT,
        b"Default nanosecond Ethernet interface",
    );
    push_opt_end(&mut idb_body);
    out.extend_from_slice(&wrap_block(BLOCK_TYPE_IDB, &idb_body));

    // 3. Enhanced Packet Blocks (EPBs)
    let packets = crate::pcap::synthetic_test_packets();
    for (idx, frame) in packets.iter().enumerate() {
        let mut epb_body = Vec::new();
        epb_body.extend_from_slice(&0u32.to_le_bytes()); // Interface ID 0

        let ts_sec = 1_700_000_000u64 + (idx as u64);
        let ts_nsec = (idx as u64) * 125_000_000u64;
        let total_nanos = ts_sec * 1_000_000_000 + ts_nsec;
        let ts_high = (total_nanos >> 32) as u32;
        let ts_low = (total_nanos & 0xFFFF_FFFF) as u32;

        epb_body.extend_from_slice(&ts_high.to_le_bytes());
        epb_body.extend_from_slice(&ts_low.to_le_bytes());
        epb_body.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // CapLen
        epb_body.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // WireLen
        epb_body.extend_from_slice(frame);
        let pad = (4 - (frame.len() % 4)) % 4;
        epb_body.resize(epb_body.len() + pad, 0);

        if idx == 0 {
            push_opt(&mut epb_body, OPT_COMMENT, b"TLS 1.3 ClientHello Frame");
            push_opt_end(&mut epb_body);
        }

        out.extend_from_slice(&wrap_block(BLOCK_TYPE_EPB, &epb_body));
    }

    out
}
