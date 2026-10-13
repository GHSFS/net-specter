// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! JA4 & JA4S Modern TLS & QUIC Fingerprint Engine.
//!
//! Implements FoxIO-compatible JA4 client fingerprinting (`t13d1516h2_...`)
//! and JA4S server response fingerprinting (`t1302h2_1301_...`) across TCP,
//! QUIC, and DTLS transports with RFC 8701 GREASE filtering and zeroize memory hygiene.

use crate::error::{Result, SpecterError};
use crate::pcap::parse_pcap_bytes;
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use crate::tls_ja3::is_grease;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Underlying transport layer protocol for the TLS session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Quic,
    Dtls,
}

impl TransportProtocol {
    #[rustfmt::skip]
    #[inline]
    pub fn code(&self) -> char {
        match self { Self::Tcp => 't', Self::Quic => 'q', Self::Dtls => 'd' }
    }
}

/// Parsed TLS / QUIC / DTLS `ClientHello` metadata and computed JA4 fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ja4ClientReport {
    pub transport: TransportProtocol,
    pub ja4: String,
    pub ja4_a: String,
    pub ja4_b: String,
    pub ja4_c: String,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub version: String,
}

/// Parsed TLS / QUIC / DTLS `ServerHello` metadata and computed JA4S fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ja4ServerReport {
    pub transport: TransportProtocol,
    pub ja4s: String,
    pub ja4s_a: String,
    pub ja4s_b: String,
    pub ja4s_c: String,
    pub cipher_suite: u16,
    pub extensions: Vec<u16>,
    pub alpn: Option<String>,
    pub version: String,
}

/// Tagged enum representing either a client JA4 or server JA4S fingerprint report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "fingerprint_type", rename_all = "snake_case")]
pub enum Ja4Fingerprint {
    Client(Ja4ClientReport),
    Server(Ja4ServerReport),
}

#[rustfmt::skip]
#[inline]
fn read_u16_be(buf: &[u8], off: usize) -> Result<u16> {
    buf.get(off..off + 2).map(|b| u16::from_be_bytes([b[0], b[1]])).ok_or_else(|| SpecterError::MalformedTls("u16 EOF".into()))
}

#[rustfmt::skip]
#[inline]
fn read_u24_be(buf: &[u8], off: usize) -> Result<usize> {
    buf.get(off..off + 3).map(|b| ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize)).ok_or_else(|| SpecterError::MalformedTls("u24 EOF".into()))
}

/// Reads a QUIC RFC 9000 variable-length integer (varint).
pub fn read_quic_varint(buf: &[u8], offset: &mut usize) -> Result<u64> {
    let first = *buf
        .get(*offset)
        .ok_or_else(|| SpecterError::MalformedTls("QUIC varint EOF".into()))?;
    let len = 1 << ((first & 0xc0) >> 6);
    if *offset + len > buf.len() {
        return Err(SpecterError::MalformedTls("Truncated QUIC varint".into()));
    }
    let mut val = (first & 0x3f) as u64;
    for &b in &buf[*offset + 1..*offset + len] {
        val = (val << 8) | (b as u64);
    }
    *offset += len;
    Ok(val)
}

#[rustfmt::skip]
fn ver_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13", 0x0303 => "12", 0x0302 => "11", 0x0301 => "10",
        0x0300 => "s3", 0x0200 | 0x0002 => "s2",
        0xfefc => "d3", 0xfefd => "d2", 0xfeff => "d1", _ => "00",
    }
}

fn best_supported_version(vers: &[u16], fb: u16) -> (u16, &'static str) {
    for &t in &[
        0x0304, 0xfefc, 0x0303, 0xfefd, 0x0302, 0x0301, 0xfeff, 0x0300, 0x0200, 0x0002,
    ] {
        if vers.contains(&t) {
            return (t, ver_code(t));
        }
    }
    (fb, ver_code(fb))
}

fn format_version(ver_str: &str, best_ver: u16, tr: TransportProtocol) -> String {
    let p = if ver_str.starts_with('d') || tr == TransportProtocol::Dtls {
        "DTLS"
    } else {
        "TLS"
    };
    format!("{p} {ver_str} (0x{best_ver:04x})")
}

#[rustfmt::skip]
fn first_last_alpn(alpn: Option<&str>) -> String {
    let Some(s) = alpn.filter(|s| !s.is_empty()) else { return "00".to_string(); };
    let c: Vec<char> = s.chars().collect();
    let san = |ch: char| if ch.is_ascii_graphic() { ch } else { '9' };
    format!("{}{}", san(c[0]), san(c[c.len() - 1]))
}

#[rustfmt::skip]
fn sni_flag(sni: Option<&str>) -> char {
    match sni {
        Some(s) if !s.is_empty() && s.parse::<std::net::IpAddr>().is_err() => 'd',
        _ => 'i',
    }
}

#[rustfmt::skip]
fn hash_12(s: &str) -> String {
    if s.is_empty() { return "000000000000".to_string(); }
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())[..12].to_string()
}

#[rustfmt::skip]
fn hex_join(slice: &[u16]) -> String {
    slice.iter().map(|c| format!("{c:04x}")).collect::<Vec<_>>().join(",")
}

#[rustfmt::skip]
fn compute_ja4_b(ciphers: &[u16]) -> String {
    let mut sorted = ciphers.to_vec();
    sorted.sort_unstable();
    hash_12(&hex_join(&sorted))
}

#[rustfmt::skip]
fn compute_ja4_c(exts: &[u16], sigs: &[u16]) -> String {
    let mut f: Vec<u16> = exts.iter().copied().filter(|&e| e != 0 && e != 0x10).collect();
    f.sort_unstable();
    let (e, s) = (hex_join(&f), hex_join(sigs));
    let comb = match (!e.is_empty(), !s.is_empty()) {
        (true, true) => format!("{e}_{s}"),
        (true, false) => e,
        (false, true) => format!("_{s}"),
        (false, false) => String::new(),
    };
    hash_12(&comb)
}

#[rustfmt::skip]
fn compute_ja4s_c(exts: &[u16]) -> String {
    let f: Vec<u16> = exts.iter().copied().filter(|&e| e != 0x10).collect();
    hash_12(&hex_join(&f))
}

#[derive(Default)]
struct ParsedExtensions {
    exts: Vec<u16>,
    sigs: Vec<u16>,
    vers: Vec<u16>,
    sni: Option<String>,
    alpn: Vec<String>,
    sel_ver: Option<u16>,
}

#[rustfmt::skip]
fn parse_extensions(body: &[u8], mut pos: usize, is_server: bool) -> Result<ParsedExtensions> {
    let mut out = ParsedExtensions::default();
    if pos >= body.len() { return Ok(out); }
    let ext_total_len = read_u16_be(body, pos)? as usize;
    pos += 2;
    if pos + ext_total_len > body.len() {
        return Err(SpecterError::MalformedTls("Extensions overflow".into()));
    }
    let ext_end = pos + ext_total_len;
    while pos < ext_end {
        let (ext_t, ext_len) = (read_u16_be(body, pos)?, read_u16_be(body, pos + 2)? as usize);
        pos += 4;
        if pos + ext_len > ext_end {
            return Err(SpecterError::MalformedTls(format!("Extension 0x{ext_t:04x} overflow")));
        }
        let data = &body[pos..pos + ext_len];
        pos += ext_len;
        if is_grease(ext_t) { continue; }
        out.exts.push(ext_t);

        match ext_t {
            0x0000 if data.len() >= 5 && data[2] == 0 => {
                let n_len = read_u16_be(data, 3)? as usize;
                if 5 + n_len <= data.len() {
                    out.sni = std::str::from_utf8(&data[5..5 + n_len]).ok().map(String::from);
                }
            }
            0x000d if data.len() >= 2 => {
                let s_len = (read_u16_be(data, 0)? as usize).min(data.len() - 2);
                out.sigs = data[2..2 + s_len].chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]])).filter(|&s| !is_grease(s)).collect();
            }
            0x0010 if data.len() >= 2 => {
                let a_len = (read_u16_be(data, 0)? as usize).min(data.len() - 2);
                let (mut idx, end) = (2, 2 + a_len);
                while idx < end {
                    let p_len = data[idx] as usize;
                    idx += 1;
                    if idx + p_len <= end {
                        if let Ok(p) = std::str::from_utf8(&data[idx..idx + p_len]) {
                            out.alpn.push(p.to_string());
                        }
                        idx += p_len;
                    } else { break; }
                }
            }
            0x002b if !data.is_empty() => {
                if is_server && data.len() >= 2 {
                    out.sel_ver = Some(read_u16_be(data, 0)?);
                } else if data.len() > 1 {
                    let v_len = (data[0] as usize).min(data.len() - 1);
                    out.vers = data[1..1 + v_len].chunks_exact(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]])).filter(|&v| !is_grease(v)).collect();
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

#[rustfmt::skip]
fn locate_handshake_body(
    payload: &[u8],
    expected: u8,
    transport: TransportProtocol,
) -> Result<(&[u8], TransportProtocol)> {
    let (hs, tr) = if payload.first() == Some(&0x16) {
        let is_dtls = transport == TransportProtocol::Dtls || payload.get(1) == Some(&0xfe);
        let (hdr, off) = if is_dtls { (13, 11) } else { (5, 3) };
        let r_len = read_u16_be(payload, off)? as usize;
        if hdr + r_len > payload.len() {
            return Err(SpecterError::MalformedTls("Record overflow".into()));
        }
        let tr = if is_dtls { TransportProtocol::Dtls } else { transport };
        (&payload[hdr..hdr + r_len], tr)
    } else {
        (payload, transport)
    };
    if hs.is_empty() || hs[0] != expected {
        return Err(SpecterError::MalformedTls("Handshake header mismatch".into()));
    }
    let (h_len, b_len) = if tr == TransportProtocol::Dtls {
        if hs.len() < 12 { return Err(SpecterError::MalformedTls("Truncated DTLS hs".into())); }
        (12, read_u24_be(hs, 9)?)
    } else {
        if hs.len() < 4 { return Err(SpecterError::MalformedTls("Truncated TLS hs".into())); }
        (4, read_u24_be(hs, 1)?)
    };
    if h_len + b_len > hs.len() {
        return Err(SpecterError::MalformedTls("Handshake body overflow".into()));
    }
    Ok((&hs[h_len..h_len + b_len], tr))
}

#[rustfmt::skip]
fn sanitize_hello_random_and_session(body: &[u8], is_dtls_client: bool) -> Result<usize> {
    let mut rand = [0u8; 32];
    rand.copy_from_slice(body.get(2..34).ok_or_else(|| SpecterError::MalformedTls("random EOF".into()))?);
    rand.zeroize();
    let s_len = *body.get(34).ok_or_else(|| SpecterError::MalformedTls("session len EOF".into()))? as usize;
    let mut pos = 35 + s_len;
    let mut s_buf = body.get(35..pos).ok_or_else(|| SpecterError::MalformedTls("session EOF".into()))?.to_vec();
    s_buf.zeroize();
    if is_dtls_client {
        let c_len = *body.get(pos).ok_or_else(|| SpecterError::MalformedTls("cookie len EOF".into()))? as usize;
        let c_end = pos + 1 + c_len;
        let mut c_buf = body.get(pos + 1..c_end).ok_or_else(|| SpecterError::MalformedTls("cookie EOF".into()))?.to_vec();
        c_buf.zeroize();
        pos = c_end;
    }
    Ok(pos)
}

/// Computes a FoxIO-compatible JA4 client fingerprint from a TLS/QUIC/DTLS ClientHello record.
pub fn compute_ja4_client(payload: &[u8], transport: TransportProtocol) -> Result<Ja4ClientReport> {
    let (body, transport) = locate_handshake_body(payload, 0x01, transport)?;
    if body.len() < 35 {
        return Err(SpecterError::MalformedTls(
            "ClientHello body too short".into(),
        ));
    }
    let client_version = read_u16_be(body, 0)?;
    let next_pos = sanitize_hello_random_and_session(body, transport == TransportProtocol::Dtls)?;

    let c_len = read_u16_be(body, next_pos)? as usize;
    let c_end = next_pos + 2 + c_len;
    if c_len == 0 || c_len % 2 != 0 || c_end > body.len() {
        return Err(SpecterError::MalformedTls(
            "Invalid Cipher Suites vector length".into(),
        ));
    }
    let cipher_suites: Vec<u16> = body[next_pos + 2..c_end]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|&s| !is_grease(s))
        .collect();

    let comp_len = *body
        .get(c_end)
        .ok_or_else(|| SpecterError::MalformedTls("Missing Compression".into()))?
        as usize;
    let ext_pos = c_end + 1 + comp_len;
    let exts = parse_extensions(body, ext_pos, false)?;
    let (best_ver, ver_str) = best_supported_version(&exts.vers, client_version);
    let (sn, al) = (
        sni_flag(exts.sni.as_deref()),
        first_last_alpn(exts.alpn.first().map(String::as_str)),
    );
    let (cc, ec) = (cipher_suites.len().min(99), exts.exts.len().min(99));
    let ja4_a = format!("{}{ver_str}{sn}{cc:02}{ec:02}{al}", transport.code());
    let (ja4_b, ja4_c) = (
        compute_ja4_b(&cipher_suites),
        compute_ja4_c(&exts.exts, &exts.sigs),
    );
    let ja4 = format!("{ja4_a}_{ja4_b}_{ja4_c}");
    let version = format_version(ver_str, best_ver, transport);

    Ok(Ja4ClientReport {
        transport,
        ja4,
        ja4_a,
        ja4_b,
        ja4_c,
        cipher_suites,
        extensions: exts.exts,
        signature_algorithms: exts.sigs,
        sni: exts.sni,
        alpn: exts.alpn,
        version,
    })
}

/// Computes a FoxIO-compatible JA4S server fingerprint from a TLS/QUIC/DTLS ServerHello record.
pub fn compute_ja4_server(payload: &[u8], transport: TransportProtocol) -> Result<Ja4ServerReport> {
    let (body, transport) = locate_handshake_body(payload, 0x02, transport)?;
    if body.len() < 38 {
        return Err(SpecterError::MalformedTls(
            "ServerHello body shorter than fixed minimum length".into(),
        ));
    }
    let server_version = read_u16_be(body, 0)?;
    let next_pos = sanitize_hello_random_and_session(body, false)?;
    let cipher_suite = read_u16_be(body, next_pos)?;
    let ext_pos = next_pos + 3;

    let exts = parse_extensions(body, ext_pos, true)?;
    let sel_slice = exts.sel_ver.map(|v| vec![v]).unwrap_or_default();
    let (best_ver, ver_str) = best_supported_version(&sel_slice, server_version);

    let al = first_last_alpn(exts.alpn.first().map(String::as_str));
    let ec = exts.exts.len().min(99);
    let ja4s_a = format!("{}{ver_str}{ec:02}{al}", transport.code());
    let (ja4s_b, ja4s_c) = (format!("{cipher_suite:04x}"), compute_ja4s_c(&exts.exts));
    let ja4s = format!("{ja4s_a}_{ja4s_b}_{ja4s_c}");
    let version = format_version(ver_str, best_ver, transport);

    Ok(Ja4ServerReport {
        transport,
        ja4s,
        ja4s_a,
        ja4s_b,
        ja4s_c,
        cipher_suite,
        extensions: exts.exts,
        alpn: exts.alpn.into_iter().next(),
        version,
    })
}

/// Tests whether a raw packet payload begins with a QUIC RFC 9000 long header.
#[inline]
pub fn is_quic_packet(payload: &[u8]) -> bool {
    payload.len() >= 5 && (payload[0] & 0x80) != 0 && (payload[0] & 0x40) != 0
}

/// Attempts to extract an embedded TLS Handshake message from a QUIC Initial packet.
pub fn extract_quic_tls_payload(p: &[u8]) -> Option<&[u8]> {
    if !is_quic_packet(p) || (p[0] & 0x30) != 0 {
        return None;
    }
    let mut off = 6 + *p.get(5)? as usize;
    let scil = *p.get(off)? as usize;
    off += 1 + scil;
    off += read_quic_varint(p, &mut off).ok()? as usize;
    let _ = read_quic_varint(p, &mut off).ok()?;

    let rest = p.get(off..)?;
    for (i, &b) in rest.iter().enumerate() {
        if b == 6 && i + 3 < rest.len() {
            let mut fo = i + 1;
            let _ = read_quic_varint(rest, &mut fo).ok()?;
            let cl = read_quic_varint(rest, &mut fo).ok()? as usize;
            if fo + cl <= rest.len() && rest.get(fo).is_some_and(|&h| h == 1 || h == 2) {
                return Some(&rest[fo..fo + cl]);
            }
        }
        if (b == 1 || b == 2) && i + 4 < rest.len() {
            if let Ok(len) = read_u24_be(rest, i + 1) {
                if i + 4 + len <= rest.len() && len > 30 {
                    return Some(&rest[i..i + 4 + len]);
                }
            }
        }
    }
    None
}

/// Parses either a ClientHello or ServerHello into a JA4 / JA4S fingerprint.
pub fn parse_ja4(p: &[u8], tr: Option<TransportProtocol>) -> Result<Ja4Fingerprint> {
    let tr = tr.unwrap_or(if is_quic_packet(p) {
        TransportProtocol::Quic
    } else if p.first() == Some(&0x16) && p.get(1) == Some(&0xfe) {
        TransportProtocol::Dtls
    } else {
        TransportProtocol::Tcp
    });
    if let Some(b) = extract_quic_tls_payload(p) {
        return if b.first() == Some(&0x02) {
            compute_ja4_server(b, TransportProtocol::Quic).map(Ja4Fingerprint::Server)
        } else {
            compute_ja4_client(b, TransportProtocol::Quic).map(Ja4Fingerprint::Client)
        };
    }
    if is_quic_packet(p) {
        if let Ok(rep) = crate::quic::audit_quic_packet(p) {
            if rep.ja4.is_some() {
                if let Ok((_, _, dec)) = crate::quic::decrypt_quic_initial_packet(p, false) {
                    if let Ok(crypto) = crate::quic::parse_crypto_frames(&dec) {
                        if let Ok(client) = compute_ja4_client(&crypto, TransportProtocol::Quic) {
                            return Ok(Ja4Fingerprint::Client(client));
                        }
                    }
                }
            } else if rep.ja4s.is_some() {
                if let Ok((_, _, dec)) = crate::quic::decrypt_quic_initial_packet(p, true) {
                    if let Ok(crypto) = crate::quic::parse_crypto_frames(&dec) {
                        if let Ok(server) = compute_ja4_server(&crypto, TransportProtocol::Quic) {
                            return Ok(Ja4Fingerprint::Server(server));
                        }
                    }
                }
            }
        }
    }
    compute_ja4_client(p, tr)
        .map(Ja4Fingerprint::Client)
        .or_else(|_| compute_ja4_server(p, tr).map(Ja4Fingerprint::Server))
}

/// Extracts all JA4 and JA4S fingerprints found across frames in a PCAP or PCAPNG capture.
pub fn extract_ja4_from_capture_bytes(raw: &[u8], force_quic: bool) -> Result<Vec<Ja4Fingerprint>> {
    let mut out = Vec::new();
    let def_tr = if force_quic {
        TransportProtocol::Quic
    } else {
        TransportProtocol::Tcp
    };
    let frames = if is_pcapng(raw) {
        parse_pcapng_bytes(raw)?.frames
    } else if let Ok(r) = parse_pcap_bytes(raw) {
        r.frames
    } else {
        return Ok(vec![parse_ja4(raw, Some(def_tr))?]);
    };
    for f in frames {
        let tr = if f.payload.first() == Some(&0x16) && f.payload.get(1) == Some(&0xfe) {
            TransportProtocol::Dtls
        } else if f.protocol == "UDP" || force_quic {
            TransportProtocol::Quic
        } else {
            def_tr
        };
        if let Ok(fp) = parse_ja4(&f.payload, Some(tr)) {
            out.push(fp);
        }
    }
    Ok(out)
}
