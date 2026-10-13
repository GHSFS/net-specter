// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! QUIC Initial Packet & RFC 9001 Header Protection Decryptor.
//!
//! Provides zero-dependency parsing, header protection stripping, and AES-128-GCM
//! decryption of QUIC Initial packets (RFC 9000, RFC 9001, RFC 9369) over UDP.
//! Extracts decrypted CRYPTO frames to compute TLS 1.3 ClientHello JA3/JA4 fingerprints.

use crate::error::{Result, SpecterError};
use crate::ja4::{compute_ja4_client, compute_ja4_server, TransportProtocol};
use crate::pcap::parse_pcap_bytes;
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use crate::quic_crypto::{aes_128_gcm_decrypt, derive_quic_initial_keys, remove_header_protection};
use crate::tls_cert::parse_tls_server_hello;
use crate::tls_ja3::parse_tls_client_hello;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

/// QUIC Packet Header Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuicPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    Short,
}

/// Parsed QUIC Initial Packet forensic report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicInitialReport {
    pub role: String,
    pub version: String,
    pub raw_version: u32,
    pub dcid: String,
    pub scid: String,
    pub packet_number: u64,
    pub token_len: usize,
    pub crypto_bytes_len: usize,
    pub handshake_type: Option<String>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub ja3: Option<String>,
    pub ja3_digest: Option<String>,
    pub ja4: Option<String>,
    pub ja3s: Option<String>,
    pub ja4s: Option<String>,
}

/// Aggregate forensic audit report across captured QUIC frames.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicAuditReport {
    pub packets_inspected: usize,
    pub quic_initial_count: usize,
    pub decrypted_count: usize,
    pub reports: Vec<QuicInitialReport>,
}

/// Reads a QUIC variable-length integer (RFC 9000 Section 16).
pub fn read_quic_varint(buf: &[u8], offset: &mut usize) -> Result<u64> {
    if *offset >= buf.len() {
        return Err(SpecterError::MalformedQuic(
            "Unexpected EOF reading varint".into(),
        ));
    }
    let first = buf[*offset];
    let len_code = first >> 6;
    let len = match len_code {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if *offset + len > buf.len() {
        return Err(SpecterError::MalformedQuic(
            "Truncated varint in QUIC packet".into(),
        ));
    }
    let mut val = (first & 0x3f) as u64;
    for i in 1..len {
        val = (val << 8) | (buf[*offset + i] as u64);
    }
    *offset += len;
    Ok(val)
}

/// Tests whether a raw packet payload begins with a QUIC RFC 9000 long header.
#[inline]
pub fn is_quic_packet(payload: &[u8]) -> bool {
    payload.len() >= 5 && (payload[0] & 0x80) != 0 && (payload[0] & 0x40) != 0
}

/// Tests whether a raw payload begins with an Initial packet header.
pub fn is_quic_initial_packet(payload: &[u8]) -> bool {
    if !is_quic_packet(payload) || payload.len() < 7 {
        return false;
    }
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    if version == 0 {
        return false; // Version Negotiation
    }
    let ptype = (payload[0] & 0x30) >> 4;
    if version == 0x6b33_43cf {
        ptype == 0x01 // RFC 9369 QUIC v2 Initial
    } else {
        ptype == 0x00 // RFC 9000 QUIC v1 / draft Initial
    }
}

/// Parsed metadata for an unencrypted or stripped QUIC Long Header.
#[derive(Debug, Clone)]
pub struct QuicLongHeader {
    pub ptype: QuicPacketType,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub payload_len: usize,
    pub pn_offset: usize,
}

/// Parses the outer Long Header up to the Packet Number field.
pub fn parse_quic_long_header(packet: &[u8]) -> Result<QuicLongHeader> {
    if packet.len() < 7 {
        return Err(SpecterError::MalformedQuic(
            "Packet too short for QUIC header".into(),
        ));
    }
    if (packet[0] & 0x80) == 0 {
        return Err(SpecterError::MalformedQuic("Not a QUIC Long Header".into()));
    }

    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    if version == 0 {
        return Err(SpecterError::MalformedQuic(
            "Version Negotiation packet".into(),
        ));
    }

    let raw_type = (packet[0] & 0x30) >> 4;
    let ptype = if version == 0x6b33_43cf {
        match raw_type {
            0x01 => QuicPacketType::Initial,
            0x02 => QuicPacketType::ZeroRtt,
            0x03 => QuicPacketType::Handshake,
            0x00 => QuicPacketType::Retry,
            _ => QuicPacketType::Short,
        }
    } else {
        match raw_type {
            0x00 => QuicPacketType::Initial,
            0x01 => QuicPacketType::ZeroRtt,
            0x02 => QuicPacketType::Handshake,
            0x03 => QuicPacketType::Retry,
            _ => QuicPacketType::Short,
        }
    };

    let dcid_len = packet[5] as usize;
    if packet.len() < 6 + dcid_len + 1 {
        return Err(SpecterError::MalformedQuic("DCID truncated".into()));
    }
    let dcid = packet[6..6 + dcid_len].to_vec();

    let scid_offset = 6 + dcid_len;
    let scid_len = packet[scid_offset] as usize;
    if packet.len() < scid_offset + 1 + scid_len {
        return Err(SpecterError::MalformedQuic("SCID truncated".into()));
    }
    let scid = packet[scid_offset + 1..scid_offset + 1 + scid_len].to_vec();

    let mut pos = scid_offset + 1 + scid_len;
    let token = if ptype == QuicPacketType::Initial {
        let token_len = read_quic_varint(packet, &mut pos)? as usize;
        if packet.len() < pos + token_len {
            return Err(SpecterError::MalformedQuic("Token truncated".into()));
        }
        let tok = packet[pos..pos + token_len].to_vec();
        pos += token_len;
        tok
    } else {
        Vec::new()
    };

    let payload_len = read_quic_varint(packet, &mut pos)? as usize;
    let pn_offset = pos;

    if packet.len() < pn_offset + payload_len {
        return Err(SpecterError::MalformedQuic(format!(
            "Packet length ({}) less than header + payload_len ({})",
            packet.len(),
            pn_offset + payload_len
        )));
    }

    Ok(QuicLongHeader {
        ptype,
        version,
        dcid,
        scid,
        token,
        payload_len,
        pn_offset,
    })
}

/// Decrypts a QUIC Initial packet and extracts CRYPTO stream bytes.
pub fn decrypt_quic_initial_packet(
    packet_bytes: &[u8],
    is_server: bool,
) -> Result<(QuicLongHeader, u64, Vec<u8>)> {
    let header = parse_quic_long_header(packet_bytes)?;
    if header.ptype != QuicPacketType::Initial {
        return Err(SpecterError::MalformedQuic(
            "Packet is not an Initial packet".into(),
        ));
    }

    let mut working_copy = packet_bytes[..header.pn_offset + header.payload_len].to_vec();
    let keys = derive_quic_initial_keys(header.version, &header.dcid, is_server)?;

    let (pn_len, pn) = remove_header_protection(&keys.hp, &mut working_copy, header.pn_offset)?;

    if header.payload_len <= pn_len + 16 {
        return Err(SpecterError::MalformedQuic(
            "Payload length too small for packet number and 16-byte auth tag".into(),
        ));
    }

    let aad = working_copy[..header.pn_offset + pn_len].to_vec();
    let ct_start = header.pn_offset + pn_len;
    let ct_end = header.pn_offset + header.payload_len;
    let ct_and_tag = &working_copy[ct_start..ct_end];

    let ct_len = ct_and_tag.len() - 16;
    let ciphertext = &ct_and_tag[..ct_len];
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ct_and_tag[ct_len..]);

    let mut nonce = keys.iv;
    let pn_bytes = pn.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }

    let decrypted = aes_128_gcm_decrypt(&keys.key, &nonce, ciphertext, &aad, &tag)?;
    Ok((header, pn, decrypted))
}

/// Reassembles CRYPTO stream bytes from decrypted QUIC frames.
pub fn parse_crypto_frames(payload: &[u8]) -> Result<Vec<u8>> {
    let mut stream_chunks = BTreeMap::new();
    let mut pos = 0;

    while pos < payload.len() {
        let ftype = read_quic_varint(payload, &mut pos)?;
        match ftype {
            0x00 => {
                // PADDING
                while pos < payload.len() && payload[pos] == 0 {
                    pos += 1;
                }
            }
            0x01 => {
                // PING
            }
            0x02 | 0x03 => {
                // ACK
                let _largest_ack = read_quic_varint(payload, &mut pos)?;
                let _ack_delay = read_quic_varint(payload, &mut pos)?;
                let ack_range_count = read_quic_varint(payload, &mut pos)?;
                let _first_ack_range = read_quic_varint(payload, &mut pos)?;
                for _ in 0..ack_range_count {
                    let _gap = read_quic_varint(payload, &mut pos)?;
                    let _len = read_quic_varint(payload, &mut pos)?;
                }
                if ftype == 0x03 {
                    let _ect0 = read_quic_varint(payload, &mut pos)?;
                    let _ect1 = read_quic_varint(payload, &mut pos)?;
                    let _ecnce = read_quic_varint(payload, &mut pos)?;
                }
            }
            0x06 => {
                // CRYPTO frame
                let offset = read_quic_varint(payload, &mut pos)?;
                let len = read_quic_varint(payload, &mut pos)? as usize;
                if pos + len > payload.len() {
                    return Err(SpecterError::MalformedQuic(
                        "CRYPTO frame data truncated".into(),
                    ));
                }
                let data = payload[pos..pos + len].to_vec();
                pos += len;
                stream_chunks.insert(offset, data);
            }
            _ => {
                // Unknown or unhandled frame in Initial: stop parsing frames
                break;
            }
        }
    }

    let mut reassembled = Vec::new();
    let mut expected_offset = 0u64;
    while let Some(chunk) = stream_chunks.remove(&expected_offset) {
        expected_offset += chunk.len() as u64;
        reassembled.extend_from_slice(&chunk);
    }

    Ok(reassembled)
}

/// Decrypts a QUIC packet and audits TLS 1.3 ClientHello / ServerHello fingerprints.
pub fn audit_quic_packet(packet_bytes: &[u8]) -> Result<QuicInitialReport> {
    // Attempt client Initial first; if auth fails, try server Initial
    let (header, pn, decrypted, role) = match decrypt_quic_initial_packet(packet_bytes, false) {
        Ok((h, p, d)) => (h, p, d, "client".to_string()),
        Err(_) => {
            let (h, p, d) = decrypt_quic_initial_packet(packet_bytes, true)?;
            (h, p, d, "server".to_string())
        }
    };

    let mut crypto_bytes = parse_crypto_frames(&decrypted)?;
    let crypto_bytes_len = crypto_bytes.len();

    let mut handshake_type = None;
    let mut sni = None;
    let mut alpn = Vec::new();
    let mut ja3 = None;
    let mut ja3_digest = None;
    let mut ja4 = None;
    let mut ja3s = None;
    let mut ja4s = None;

    if !crypto_bytes.is_empty() {
        match crypto_bytes[0] {
            0x01 => {
                // TLS 1.3 ClientHello
                handshake_type = Some("ClientHello".into());
                let mut wrapped = Vec::with_capacity(5 + crypto_bytes.len());
                wrapped.extend_from_slice(&[0x16, 0x03, 0x03]);
                wrapped.extend_from_slice(&(crypto_bytes.len() as u16).to_be_bytes());
                wrapped.extend_from_slice(&crypto_bytes);
                if let Ok(ch) = parse_tls_client_hello(&wrapped) {
                    sni = ch.sni.clone();
                    alpn = ch.alpn.clone();
                    ja3 = Some(ch.ja3_string.clone());
                    ja3_digest = Some(ch.ja3_md5.clone());
                }
                wrapped.zeroize();

                if let Ok(fp) = compute_ja4_client(&crypto_bytes, TransportProtocol::Quic) {
                    ja4 = Some(fp.ja4);
                    if sni.is_none() {
                        sni = fp.sni;
                    }
                    if alpn.is_empty() {
                        alpn = fp.alpn;
                    }
                }
            }
            0x02 => {
                // TLS 1.3 ServerHello
                handshake_type = Some("ServerHello".into());
                let mut wrapped = Vec::with_capacity(5 + crypto_bytes.len());
                wrapped.extend_from_slice(&[0x16, 0x03, 0x03]);
                wrapped.extend_from_slice(&(crypto_bytes.len() as u16).to_be_bytes());
                wrapped.extend_from_slice(&crypto_bytes);
                if let Ok(sh) = parse_tls_server_hello(&wrapped) {
                    ja3s = Some(sh.ja3s_md5);
                }
                wrapped.zeroize();

                if let Ok(fp) = compute_ja4_server(&crypto_bytes, TransportProtocol::Quic) {
                    ja4s = Some(fp.ja4s);
                    if let Some(alp) = fp.alpn {
                        alpn.push(alp);
                    }
                }
            }
            _ => {}
        }
    }

    crypto_bytes.zeroize();

    let version_str = match header.version {
        0x0000_0001 => "QUICv1 (0x00000001)".into(),
        0x6b33_43cf => "QUICv2 (0x6b3343cf)".into(),
        0xff00_001d => "QUIC-draft-29 (0xff00001d)".into(),
        v => format!("QUIC (0x{v:08x})"),
    };

    Ok(QuicInitialReport {
        role,
        version: version_str,
        raw_version: header.version,
        dcid: hex::encode(&header.dcid),
        scid: hex::encode(&header.scid),
        packet_number: pn,
        token_len: header.token.len(),
        crypto_bytes_len,
        handshake_type,
        sni,
        alpn,
        ja3,
        ja3_digest,
        ja4,
        ja3s,
        ja4s,
    })
}

/// Scans raw capture bytes (PCAP or PCAPNG) for UDP QUIC Initial packets and decrypts them.
pub fn audit_quic_capture_bytes(bytes: &[u8]) -> Result<QuicAuditReport> {
    let frames = if is_pcapng(bytes) {
        parse_pcapng_bytes(bytes)?.frames
    } else {
        parse_pcap_bytes(bytes)?.frames
    };

    let mut packets_inspected = 0;
    let mut quic_initial_count = 0;
    let mut decrypted_count = 0;
    let mut reports = Vec::new();

    for frame in &frames {
        // Inspect UDP payloads (e.g. port 443 or any UDP payload matching QUIC Initial)
        if frame.protocol == "UDP" || frame.src_port == 443 || frame.dst_port == 443 {
            packets_inspected += 1;
            if is_quic_initial_packet(&frame.payload) {
                quic_initial_count += 1;
                if let Ok(rep) = audit_quic_packet(&frame.payload) {
                    decrypted_count += 1;
                    reports.push(rep);
                }
            }
        }
    }

    Ok(QuicAuditReport {
        packets_inspected,
        quic_initial_count,
        decrypted_count,
        reports,
    })
}

/// Forensically audits raw bytes, UDP QUIC packets, or PCAP/PCAPNG captures for QUIC Initial handshakes.
pub fn audit_quic_bytes(raw: &[u8]) -> Result<QuicAuditReport> {
    if raw.is_empty() {
        return Err(SpecterError::InvalidArgument("Empty bytes".into()));
    }
    if is_pcapng(raw) || parse_pcap_bytes(raw).is_ok() {
        audit_quic_capture_bytes(raw)
    } else {
        let rep = audit_quic_packet(raw)?;
        Ok(QuicAuditReport {
            packets_inspected: 1,
            quic_initial_count: 1,
            decrypted_count: 1,
            reports: vec![rep],
        })
    }
}

/// Builds a fully valid, RFC 9001 encrypted QUIC Initial packet containing a TLS 1.3 Handshake.
pub fn build_synthetic_quic_initial(
    version: u32,
    dcid: &[u8],
    scid: &[u8],
    packet_number: u64,
    tls_handshake: &[u8],
    is_server: bool,
) -> Result<Vec<u8>> {
    let keys = derive_quic_initial_keys(version, dcid, is_server)?;

    // Construct CRYPTO frame
    let mut payload = Vec::new();
    payload.push(0x06); // CRYPTO frame
    payload.push(0x00); // offset = 0
    let hs_len = tls_handshake.len();
    if hs_len < 64 {
        payload.push(hs_len as u8);
    } else {
        payload.push(0x40 | ((hs_len >> 8) as u8));
        payload.push((hs_len & 0xff) as u8);
    }
    payload.extend_from_slice(tls_handshake);

    // If client Initial, pad payload with zeros to ensure datagram length >= 1200
    if !is_server && payload.len() < 1160 {
        payload.resize(1160, 0); // PADDING frames
    }

    let pn_len = 2usize;
    let total_len = pn_len + payload.len() + 16; // packet number + ciphertext + 16-byte auth tag

    let mut packet = Vec::new();
    let type_bits = if version == 0x6b33_43cf { 0x01 } else { 0x00 };
    let first_byte = 0xc0 | (type_bits << 4) | ((pn_len - 1) as u8);
    packet.push(first_byte);
    packet.extend_from_slice(&version.to_be_bytes());
    packet.push(dcid.len() as u8);
    packet.extend_from_slice(dcid);
    packet.push(scid.len() as u8);
    packet.extend_from_slice(scid);

    // Token length (0 for test initial)
    packet.push(0x00);

    // Length field (varint)
    if total_len < 64 {
        packet.push(total_len as u8);
    } else if total_len < 16384 {
        packet.push(0x40 | ((total_len >> 8) as u8));
        packet.push((total_len & 0xff) as u8);
    } else {
        packet.push(0x80 | ((total_len >> 24) as u8));
        packet.push(((total_len >> 16) & 0xff) as u8);
        packet.push(((total_len >> 8) & 0xff) as u8);
        packet.push((total_len & 0xff) as u8);
    }

    let pn_offset = packet.len();
    let pn_bytes = (packet_number as u16).to_be_bytes();
    packet.extend_from_slice(&pn_bytes);

    // AAD is the unmasked header up to and including Packet Number
    let aad = packet.clone();

    // Compute Nonce
    let mut nonce = keys.iv;
    let pn_u64_bytes = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_u64_bytes[i];
    }

    // Encrypt payload with AES-128-GCM
    let (ciphertext, tag) =
        crate::quic_crypto::aes_128_gcm_encrypt(&keys.key, &nonce, &payload, &aad);
    packet.extend_from_slice(&ciphertext);
    packet.extend_from_slice(&tag);

    // Apply RFC 9001 Header Protection
    crate::quic_crypto::apply_header_protection(&keys.hp, &mut packet, pn_offset, pn_len)?;

    Ok(packet)
}
