// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{Result, SpecterError};
use md5::{Digest as Md5Digest, Md5};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

/// Parsed TLS `ClientHello` handshake metadata and computed JA3 fingerprint digests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsClientHelloReport {
    pub record_version: u16,
    pub client_version: u16,
    pub random_hex: String,
    pub session_id_len: usize,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub grease_filtered_count: usize,
    pub ja3_string: String,
    pub ja3_md5: String,
    pub ja3_sha256: String,
}

/// Returns `true` if a 16-bit TLS identifier matches RFC 8701 GREASE (`0x?a?a`).
#[inline]
pub fn is_grease(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a && (val >> 8) == (val & 0x00ff)
}

#[inline]
fn read_u16_be(buf: &[u8], offset: usize) -> Result<u16> {
    if offset + 2 > buf.len() {
        return Err(SpecterError::MalformedTls(format!(
            "Unexpected EOF reading u16 at offset {offset} (len {})",
            buf.len()
        )));
    }
    Ok(u16::from_be_bytes([buf[offset], buf[offset + 1]]))
}

#[inline]
fn read_u24_be(buf: &[u8], offset: usize) -> Result<usize> {
    if offset + 3 > buf.len() {
        return Err(SpecterError::MalformedTls(format!(
            "Unexpected EOF reading u24 at offset {offset} (len {})",
            buf.len()
        )));
    }
    Ok(((buf[offset] as usize) << 16)
        | ((buf[offset + 1] as usize) << 8)
        | (buf[offset + 2] as usize))
}

/// Inspects a TLS Handshake record containing a `ClientHello` message and computes
/// its canonical JA3 string, MD5 fingerprint, and SHA-256 extended digest.
pub fn parse_tls_client_hello(payload: &[u8]) -> Result<TlsClientHelloReport> {
    if payload.len() < 9 {
        return Err(SpecterError::MalformedTls(
            "Payload shorter than minimum TLS record + handshake header (9 bytes)".into(),
        ));
    }

    // TLS Record Layer: ContentType(1) == 0x16 (Handshake), Version(2), Length(2)
    let content_type = payload[0];
    if content_type != 0x16 {
        return Err(SpecterError::MalformedTls(format!(
            "Expected TLS Handshake record (0x16), found 0x{content_type:02x}"
        )));
    }
    let record_version = read_u16_be(payload, 1)?;
    let record_len = read_u16_be(payload, 3)? as usize;
    if 5 + record_len > payload.len() {
        return Err(SpecterError::MalformedTls(format!(
            "TLS record length {record_len} exceeds available payload ({})",
            payload.len() - 5
        )));
    }

    let hs = &payload[5..5 + record_len];
    if hs.len() < 4 {
        return Err(SpecterError::MalformedTls(
            "Handshake payload too short for header".into(),
        ));
    }
    let msg_type = hs[0];
    if msg_type != 0x01 {
        return Err(SpecterError::MalformedTls(format!(
            "Expected ClientHello handshake type (0x01), found 0x{msg_type:02x}"
        )));
    }
    let hs_len = read_u24_be(hs, 1)?;
    if 4 + hs_len > hs.len() {
        return Err(SpecterError::MalformedTls(format!(
            "ClientHello body length {hs_len} exceeds handshake record ({})",
            hs.len() - 4
        )));
    }

    let body = &hs[4..4 + hs_len];
    if body.len() < 35 {
        return Err(SpecterError::MalformedTls(
            "ClientHello body shorter than fixed version + random + session_id length".into(),
        ));
    }

    let client_version = read_u16_be(body, 0)?;

    // Copy and zeroize raw random bytes after hex encoding for memory hygiene
    let mut random_bytes = [0u8; 32];
    random_bytes.copy_from_slice(&body[2..34]);
    let random_hex = hex::encode(random_bytes);
    random_bytes.zeroize();

    let mut pos = 34;
    let session_id_len = body[pos] as usize;
    pos += 1;
    if pos + session_id_len > body.len() {
        return Err(SpecterError::MalformedTls(
            "Session ID length exceeds ClientHello bounds".into(),
        ));
    }
    let mut session_id_buf = body[pos..pos + session_id_len].to_vec();
    session_id_buf.zeroize();
    pos += session_id_len;

    // Cipher Suites
    let cipher_bytes_len = read_u16_be(body, pos)? as usize;
    pos += 2;
    if cipher_bytes_len == 0 || cipher_bytes_len % 2 != 0 || pos + cipher_bytes_len > body.len() {
        return Err(SpecterError::MalformedTls(
            "Invalid Cipher Suites vector length".into(),
        ));
    }

    let mut cipher_suites = Vec::with_capacity(cipher_bytes_len / 2);
    let mut grease_filtered_count = 0usize;
    for chunk in body[pos..pos + cipher_bytes_len].chunks_exact(2) {
        let suite = u16::from_be_bytes([chunk[0], chunk[1]]);
        if is_grease(suite) {
            grease_filtered_count += 1;
        } else {
            cipher_suites.push(suite);
        }
    }
    pos += cipher_bytes_len;

    // Compression Methods
    if pos >= body.len() {
        return Err(SpecterError::MalformedTls(
            "Missing Compression Methods length".into(),
        ));
    }
    let comp_len = body[pos] as usize;
    pos += 1;
    if pos + comp_len > body.len() {
        return Err(SpecterError::MalformedTls(
            "Compression Methods vector exceeds ClientHello bounds".into(),
        ));
    }
    let compression_methods = body[pos..pos + comp_len].to_vec();
    pos += comp_len;

    // Optional Extensions
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut sni: Option<String> = None;
    let mut alpn = Vec::new();
    let mut supported_versions = Vec::new();

    if pos < body.len() {
        let ext_total_len = read_u16_be(body, pos)? as usize;
        pos += 2;
        if pos + ext_total_len > body.len() {
            return Err(SpecterError::MalformedTls(
                "Extensions total length exceeds ClientHello bounds".into(),
            ));
        }
        let ext_end = pos + ext_total_len;
        while pos < ext_end {
            if pos + 4 > ext_end {
                return Err(SpecterError::MalformedTls(
                    "Truncated TLS extension header".into(),
                ));
            }
            let ext_type = read_u16_be(body, pos)?;
            let ext_len = read_u16_be(body, pos + 2)? as usize;
            pos += 4;
            if pos + ext_len > ext_end {
                return Err(SpecterError::MalformedTls(format!(
                    "Extension 0x{ext_type:04x} length {ext_len} exceeds bounds"
                )));
            }
            let ext_data = &body[pos..pos + ext_len];
            pos += ext_len;

            if is_grease(ext_type) {
                grease_filtered_count += 1;
                continue;
            }
            extensions.push(ext_type);

            match ext_type {
                // 0x0000: server_name (SNI)
                0x0000 if ext_data.len() >= 5 => {
                    let list_len = read_u16_be(ext_data, 0)? as usize;
                    if 2 + list_len <= ext_data.len() {
                        let name_type = ext_data[2];
                        let name_len = read_u16_be(ext_data, 3)? as usize;
                        if name_type == 0 && 5 + name_len <= ext_data.len() {
                            if let Ok(host) = std::str::from_utf8(&ext_data[5..5 + name_len]) {
                                sni = Some(host.to_string());
                            }
                        }
                    }
                }
                // 0x000a: supported_groups (Elliptic Curves)
                0x000a if ext_data.len() >= 2 => {
                    let groups_len = read_u16_be(ext_data, 0)? as usize;
                    if 2 + groups_len <= ext_data.len() && groups_len % 2 == 0 {
                        for chunk in ext_data[2..2 + groups_len].chunks_exact(2) {
                            let grp = u16::from_be_bytes([chunk[0], chunk[1]]);
                            if is_grease(grp) {
                                grease_filtered_count += 1;
                            } else {
                                elliptic_curves.push(grp);
                            }
                        }
                    }
                }
                // 0x000b: ec_point_formats
                0x000b if !ext_data.is_empty() => {
                    let fmt_len = ext_data[0] as usize;
                    if fmt_len < ext_data.len() {
                        ec_point_formats.extend_from_slice(&ext_data[1..1 + fmt_len]);
                    }
                }
                // 0x0010: ALPN
                0x0010 if ext_data.len() >= 2 => {
                    let alpn_len = read_u16_be(ext_data, 0)? as usize;
                    if 2 + alpn_len <= ext_data.len() {
                        let mut idx = 2;
                        let end = 2 + alpn_len;
                        while idx < end {
                            let proto_len = ext_data[idx] as usize;
                            idx += 1;
                            if idx + proto_len <= end {
                                if let Ok(proto) =
                                    std::str::from_utf8(&ext_data[idx..idx + proto_len])
                                {
                                    alpn.push(proto.to_string());
                                }
                                idx += proto_len;
                            } else {
                                break;
                            }
                        }
                    }
                }
                // 0x002b: supported_versions
                0x002b if !ext_data.is_empty() => {
                    let ver_len = ext_data[0] as usize;
                    if ver_len < ext_data.len() && ver_len % 2 == 0 {
                        for chunk in ext_data[1..1 + ver_len].chunks_exact(2) {
                            let ver = u16::from_be_bytes([chunk[0], chunk[1]]);
                            if is_grease(ver) {
                                grease_filtered_count += 1;
                            } else {
                                supported_versions.push(ver);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let join_u16 = |items: &[u16]| -> String {
        items
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join("-")
    };
    let join_u8 = |items: &[u8]| -> String {
        items
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("-")
    };

    let ja3_string = format!(
        "{},{},{},{},{}",
        client_version,
        join_u16(&cipher_suites),
        join_u16(&extensions),
        join_u16(&elliptic_curves),
        join_u8(&ec_point_formats)
    );

    let mut md5_hasher = Md5::new();
    md5_hasher.update(ja3_string.as_bytes());
    let ja3_md5 = hex::encode(md5_hasher.finalize());

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(ja3_string.as_bytes());
    let ja3_sha256 = hex::encode(sha256_hasher.finalize());

    Ok(TlsClientHelloReport {
        record_version,
        client_version,
        random_hex,
        session_id_len,
        cipher_suites,
        compression_methods,
        extensions,
        elliptic_curves,
        ec_point_formats,
        sni,
        alpn,
        supported_versions,
        grease_filtered_count,
        ja3_string,
        ja3_md5,
        ja3_sha256,
    })
}

/// Builds a deterministic, RFC-compliant TLS 1.3 `ClientHello` record including
/// GREASE values, SNI (`sni_host`), Supported Groups (`x25519`, `secp256r1`),
/// EC Point Formats (`0`), ALPN (`h2`, `http/1.1`), and Supported Versions.
pub fn build_sample_client_hello(sni_host: &str) -> Vec<u8> {
    let host_bytes = sni_host.as_bytes();
    let mut ext_buf = Vec::new();

    // 1. GREASE extension 0x0a0a (empty)
    ext_buf.extend_from_slice(&[0x0a, 0x0a, 0x00, 0x00]);

    // 2. SNI extension (0x0000)
    let sni_list_len = (3 + host_bytes.len()) as u16;
    let sni_ext_len = sni_list_len + 2;
    ext_buf.extend_from_slice(&0x0000u16.to_be_bytes());
    ext_buf.extend_from_slice(&sni_ext_len.to_be_bytes());
    ext_buf.extend_from_slice(&sni_list_len.to_be_bytes());
    ext_buf.push(0x00); // host_name type
    ext_buf.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    ext_buf.extend_from_slice(host_bytes);

    // 3. Supported Groups (0x000a): GREASE 0x1a1a, x25519 (0x001d = 29), secp256r1 (0x0017 = 23)
    ext_buf.extend_from_slice(&0x000au16.to_be_bytes());
    ext_buf.extend_from_slice(&8u16.to_be_bytes());
    ext_buf.extend_from_slice(&6u16.to_be_bytes());
    ext_buf.extend_from_slice(&0x1a1au16.to_be_bytes());
    ext_buf.extend_from_slice(&0x001du16.to_be_bytes());
    ext_buf.extend_from_slice(&0x0017u16.to_be_bytes());

    // 4. EC Point Formats (0x000b): uncompressed (0)
    ext_buf.extend_from_slice(&0x000bu16.to_be_bytes());
    ext_buf.extend_from_slice(&2u16.to_be_bytes());
    ext_buf.push(1);
    ext_buf.push(0);

    // 5. ALPN (0x0010): "h2", "http/1.1"
    let alpn_payload = b"\x02h2\x08http/1.1";
    ext_buf.extend_from_slice(&0x0010u16.to_be_bytes());
    ext_buf.extend_from_slice(&((alpn_payload.len() + 2) as u16).to_be_bytes());
    ext_buf.extend_from_slice(&(alpn_payload.len() as u16).to_be_bytes());
    ext_buf.extend_from_slice(alpn_payload);

    // 6. Supported Versions (0x002b): GREASE 0x2a2a, TLS 1.3 (0x0304), TLS 1.2 (0x0303)
    ext_buf.extend_from_slice(&0x002bu16.to_be_bytes());
    ext_buf.extend_from_slice(&7u16.to_be_bytes());
    ext_buf.push(6);
    ext_buf.extend_from_slice(&0x2a2au16.to_be_bytes());
    ext_buf.extend_from_slice(&0x0304u16.to_be_bytes());
    ext_buf.extend_from_slice(&0x0303u16.to_be_bytes());

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // ClientVersion TLS 1.2 (771)
    body.extend_from_slice(&[0x42u8; 32]); // 32-byte deterministic random
    body.push(0x00); // Session ID length = 0

    // Cipher Suites: GREASE 0x3a3a, TLS_AES_128_GCM_SHA256 (0x1301 = 4865),
    // TLS_AES_256_GCM_SHA384 (0x1302 = 4866), TLS_CHACHA20_POLY1305_SHA256 (0x1303 = 4867),
    // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b = 49195)
    body.extend_from_slice(&10u16.to_be_bytes());
    body.extend_from_slice(&0x3a3au16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.extend_from_slice(&0x1302u16.to_be_bytes());
    body.extend_from_slice(&0x1303u16.to_be_bytes());
    body.extend_from_slice(&0xc02bu16.to_be_bytes());

    // Compression methods: null (0x00)
    body.push(1);
    body.push(0);

    // Extensions
    body.extend_from_slice(&(ext_buf.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_buf);

    // Handshake framing (0x01 + u24 length)
    let hs_len = body.len();
    let mut hs = Vec::with_capacity(4 + hs_len);
    hs.push(0x01);
    hs.push(((hs_len >> 16) & 0xff) as u8);
    hs.push(((hs_len >> 8) & 0xff) as u8);
    hs.push((hs_len & 0xff) as u8);
    hs.extend_from_slice(&body);

    // TLS Record framing (0x16 + 0x0301 + u16 length)
    let mut record = Vec::with_capacity(5 + hs.len());
    record.push(0x16);
    record.extend_from_slice(&0x0301u16.to_be_bytes());
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}
