// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! TLS ServerHello JA3S fingerprinting and ASN.1 DER X.509 certificate chain forensics.
//!
//! Zero-dependency ASN.1 DER parser for X.509 certificates (Subject/Issuer DN, validity,
//! SANs, serial numbers, signature algorithms, self-signed and anomaly detection),
//! TLS ServerHello JA3S fingerprint extraction with RFC 8701 GREASE immunity, and TLS 1.2 / 1.3
//! Certificate message decoding across PCAP / PCAPNG captures and reassembled TCP streams.

use crate::error::{Result, SpecterError};
use crate::pcap::parse_pcap_bytes;
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use crate::tcp_stream::reassemble_capture_bytes;
use crate::tls_ja3::is_grease;
use md5::{Digest as _, Md5};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parsed TLS `ServerHello` handshake metadata and computed JA3S fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsServerHelloReport {
    pub server_version: u16,
    pub cipher_suite: u16,
    pub extensions: Vec<u16>,
    pub selected_version: Option<u16>,
    pub alpn: Option<String>,
    pub grease_filtered_count: usize,
    pub ja3s_string: String,
    pub ja3s_md5: String,
    pub ja3s_sha256: String,
}

/// Parsed X.509 certificate metadata and anomaly forensics report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct X509CertReport {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_algorithm: String,
    pub sans_dns: Vec<String>,
    pub sans_ip: Vec<String>,
    pub is_self_signed: bool,
    pub anomalies: Vec<String>,
}

/// Unified forensic audit report containing ServerHello JA3S and X.509 certificate findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertAuditReport {
    pub server_hellos: Vec<TlsServerHelloReport>,
    pub certificates: Vec<X509CertReport>,
    pub total_anomalies: usize,
}

#[inline]
fn read_u16(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or_else(|| SpecterError::MalformedTls(format!("EOF u16 at {o}")))
}

#[inline]
fn read_u24(b: &[u8], o: usize) -> Result<usize> {
    b.get(o..o + 3)
        .map(|s| ((s[0] as usize) << 16) | ((s[1] as usize) << 8) | (s[2] as usize))
        .ok_or_else(|| SpecterError::MalformedTls(format!("EOF u24 at {o}")))
}

/// Lightweight DER element view.
#[derive(Debug, Clone, Copy)]
pub struct DerElement<'a> {
    pub tag: u8,
    pub data: &'a [u8],
    pub total_len: usize,
}

/// Reads a single DER TLV element from a buffer slice.
#[rustfmt::skip]
pub fn read_der_element(buf: &[u8]) -> Result<DerElement<'_>> {
    if buf.len() < 2 { return Err(SpecterError::MalformedCert("DER buffer too short".into())); }
    let (tag, b1) = (buf[0], buf[1]);
    let (len, h_len) = if b1 < 0x80 { (b1 as usize, 2) } else {
        let n = (b1 & 0x7f) as usize;
        if n == 0 || n > 4 || 2 + n > buf.len() { return Err(SpecterError::MalformedCert("Invalid DER length octets".into())); }
        let l = buf[2..2 + n].iter().fold(0usize, |acc, &b| (acc << 8) | (b as usize));
        (l, 2 + n)
    };
    let total_len = h_len.checked_add(len).filter(|&tot| tot <= buf.len())
        .ok_or_else(|| SpecterError::MalformedCert("DER element truncated or length overflow".into()))?;
    Ok(DerElement { tag, data: &buf[h_len..total_len], total_len })
}

/// Parses all top-level DER elements inside a SEQUENCE or SET body.
pub fn parse_der_sequence<'a>(data: &'a [u8]) -> Result<Vec<DerElement<'a>>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < data.len() {
        let el = read_der_element(&data[off..])?;
        off += el.total_len;
        out.push(el);
    }
    Ok(out)
}

/// Decodes ASN.1 Object Identifier octets into dot-delimited string format.
#[rustfmt::skip]
pub fn decode_oid(data: &[u8]) -> String {
    if data.is_empty() { return String::new(); }
    let mut parts = vec![(data[0] / 40).to_string(), (data[0] % 40).to_string()];
    let mut val: u64 = 0;
    for &b in &data[1..] {
        val = (val << 7) | ((b & 0x7f) as u64);
        if (b & 0x80) == 0 { parts.push(val.to_string()); val = 0; }
    }
    parts.join(".")
}

/// Translates standard signature algorithm OIDs to canonical identifiers.
#[rustfmt::skip]
pub fn signature_algorithm_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.5"  => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.4"  => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.2"  => "md2WithRSAEncryption",
        "1.2.840.10045.4.3.2"   => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3"   => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4"   => "ecdsa-with-SHA512",
        "1.2.840.10045.4.1"     => "ecdsa-with-SHA1",
        "1.3.101.112"           => "Ed25519",
        "1.3.101.113"           => "Ed448",
        _ => "unknown",
    }
}

/// Checks whether a signature algorithm represents legacy or compromised crypto.
#[rustfmt::skip]
pub fn is_weak_signature_algorithm(oid: &str, name: &str) -> bool {
    name.contains("md2") || name.contains("md5") || name.contains("sha1") || name.contains("SHA1")
        || oid == "1.2.840.113549.1.1.4" || oid == "1.2.840.113549.1.1.5" || oid == "1.2.840.10045.4.1"
}

/// Parses an X.509 Name sequence into an RFC 4514-like Distinguished Name string.
#[rustfmt::skip]
pub fn parse_dn(data: &[u8]) -> Result<String> {
    let mut parts = Vec::new();
    for s in parse_der_sequence(data)? {
        if s.tag == 0x31 {
            for atv in parse_der_sequence(s.data)? {
                let seq = parse_der_sequence(atv.data)?;
                if seq.len() >= 2 && seq[0].tag == 0x06 {
                    let oid = decode_oid(seq[0].data);
                    let val = String::from_utf8_lossy(seq[1].data);
                    let label = match oid.as_str() {
                        "2.5.4.3" => "CN", "2.5.4.6" => "C", "2.5.4.7" => "L",
                        "2.5.4.8" => "ST", "2.5.4.10" => "O", "2.5.4.11" => "OU",
                        "1.2.840.113549.1.9.1" => "emailAddress", _ => oid.as_str(),
                    };
                    parts.push(format!("{label}={val}"));
                }
            }
        }
    }
    Ok(parts.join(", "))
}

#[rustfmt::skip]
fn to_epoch_seconds(mut y: i64, m: u32, d: u32, h: u32, min: u32, s: u32) -> i64 {
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d.saturating_sub(1);
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe as i64 - 719468;
    days * 86400 + (h as i64) * 3600 + (min as i64) * 60 + (s as i64)
}

/// Parses DER UTCTime (0x17) or GeneralizedTime (0x18) into ISO 8601 string and epoch seconds.
#[rustfmt::skip]
pub fn parse_der_time(tag: u8, data: &[u8]) -> Result<(String, i64)> {
    if !data.is_ascii() { return Err(SpecterError::MalformedCert("Non-ASCII time data".into())); }
    let s = std::str::from_utf8(data).map_err(|e| SpecterError::MalformedCert(format!("Invalid time: {e}")))?;
    let (y, m, d, h, min, sec) = if tag == 0x17 && s.len() >= 10 {
        let yy: i64 = s[0..2].parse().map_err(|_| SpecterError::MalformedCert("Bad year in UTCTime".into()))?;
        let yr = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        let sc = if s.len() >= 12 && s.as_bytes()[10].is_ascii_digit() { s[10..12].parse().unwrap_or(0) } else { 0 };
        (yr, s[2..4].parse().unwrap_or(1), s[4..6].parse().unwrap_or(1), s[6..8].parse().unwrap_or(0), s[8..10].parse().unwrap_or(0), sc)
    } else if tag == 0x18 && s.len() >= 12 {
        let yr: i64 = s[0..4].parse().map_err(|_| SpecterError::MalformedCert("Bad year in GeneralizedTime".into()))?;
        let sc = if s.len() >= 14 && s.as_bytes()[12].is_ascii_digit() { s[12..14].parse().unwrap_or(0) } else { 0 };
        (yr, s[4..6].parse().unwrap_or(1), s[6..8].parse().unwrap_or(1), s[8..10].parse().unwrap_or(0), s[10..12].parse().unwrap_or(0), sc)
    } else {
        return Err(SpecterError::MalformedCert(format!("Bad time tag/len 0x{tag:02x}")));
    };
    Ok((format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{sec:02}Z"), to_epoch_seconds(y, m, d, h, min, sec)))
}

#[rustfmt::skip]
fn parse_sans(data: &[u8], dns: &mut Vec<String>, ips: &mut Vec<String>) {
    let items = if let Ok(el) = read_der_element(data) {
        if el.tag == 0x30 { parse_der_sequence(el.data).unwrap_or_default() } else { parse_der_sequence(data).unwrap_or_default() }
    } else {
        parse_der_sequence(data).unwrap_or_default()
    };
    for gn in items {
        if gn.tag == 0x82 {
            if let Ok(n) = std::str::from_utf8(gn.data) { dns.push(n.to_string()); }
        } else if gn.tag == 0x87 {
            if gn.data.len() == 4 {
                ips.push(format!("{}.{}.{}.{}", gn.data[0], gn.data[1], gn.data[2], gn.data[3]));
            } else if gn.data.len() == 16 {
                if let Ok(arr) = <[u8; 16]>::try_from(gn.data) { ips.push(std::net::Ipv6Addr::from(arr).to_string()); }
            }
        }
    }
}

/// Parses a zero-dependency ASN.1 DER encoded X.509 certificate.
#[rustfmt::skip]
pub fn parse_x509_der(der_bytes: &[u8]) -> Result<X509CertReport> {
    let root = read_der_element(der_bytes)?;
    if root.tag != 0x30 { return Err(SpecterError::MalformedCert("Cert root not SEQUENCE".into())); }
    let cert_seq = parse_der_sequence(root.data)?;
    if cert_seq.len() < 3 || cert_seq[0].tag != 0x30 { return Err(SpecterError::MalformedCert("Invalid cert TBS".into())); }
    let tbs = parse_der_sequence(cert_seq[0].data)?;
    let mut i = if tbs.first().map(|e| e.tag) == Some(0xa0) { 1 } else { 0 };
    let serial = hex::encode(tbs.get(i).ok_or_else(|| SpecterError::MalformedCert("No serial".into()))?.data);
    i += 1;
    let sig_seq = parse_der_sequence(tbs.get(i).ok_or_else(|| SpecterError::MalformedCert("No sig".into()))?.data)?;
    let sig_oid = sig_seq.first().filter(|e| e.tag == 0x06).map(|e| decode_oid(e.data)).unwrap_or_default();
    let signature_algorithm = signature_algorithm_name(&sig_oid).to_string();
    i += 1;
    let issuer = parse_dn(tbs.get(i).ok_or_else(|| SpecterError::MalformedCert("No issuer".into()))?.data)?;
    i += 1;
    let val_seq = parse_der_sequence(tbs.get(i).ok_or_else(|| SpecterError::MalformedCert("No val".into()))?.data)?;
    if val_seq.len() < 2 { return Err(SpecterError::MalformedCert("Truncated validity".into())); }
    let (not_before, nb_ep) = parse_der_time(val_seq[0].tag, val_seq[0].data)?;
    let (not_after, na_ep) = parse_der_time(val_seq[1].tag, val_seq[1].data)?;
    i += 1;
    let subject = parse_dn(tbs.get(i).ok_or_else(|| SpecterError::MalformedCert("No subject".into()))?.data)?;
    i += 1;
    if tbs.get(i).is_none() { return Err(SpecterError::MalformedCert("No SPKI".into())); }
    i += 1;
    let mut sans_dns = Vec::new();
    let mut sans_ip = Vec::new();
    while i < tbs.len() {
        if tbs[i].tag == 0xa3 {
            if let Ok(ext_seq) = parse_der_sequence(tbs[i].data) {
                if let Some(r) = ext_seq.first().filter(|e| e.tag == 0x30) {
                    for ext in parse_der_sequence(r.data).unwrap_or_default() {
                        let parts = parse_der_sequence(ext.data).unwrap_or_default();
                        if parts.iter().any(|p| p.tag == 0x06 && decode_oid(p.data) == "2.5.29.17") {
                            if let Some(oct) = parts.iter().find(|p| p.tag == 0x04) {
                                parse_sans(oct.data, &mut sans_dns, &mut sans_ip);
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
    let is_self_signed = !subject.is_empty() && subject == issuer;
    let mut anomalies = Vec::new();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    if na_ep < nb_ep { anomalies.push("inverted_validity".into()); }
    else {
        if now > na_ep { anomalies.push("expired".into()); }
        if now < nb_ep { anomalies.push("not_yet_valid".into()); }
    }
    if is_weak_signature_algorithm(&sig_oid, &signature_algorithm) { anomalies.push("weak_algorithm".into()); }
    if is_self_signed { anomalies.push("self_signed".into()); }
    Ok(X509CertReport {
        subject, issuer, serial_number: serial, not_before, not_after,
        signature_algorithm, sans_dns, sans_ip, is_self_signed, anomalies,
    })
}

/// Parses a TLS ServerHello (0x02) handshake payload and computes JA3S digests.
#[rustfmt::skip]
pub fn parse_tls_server_hello(payload: &[u8]) -> Result<TlsServerHelloReport> {
    let body = if payload.first() == Some(&0x16) && payload.len() >= 9 {
        let r_len = read_u16(payload, 3)? as usize;
        let hs = payload.get(5..5 + r_len).ok_or_else(|| SpecterError::MalformedTls("Overflow".into()))?;
        if hs.first() != Some(&0x02) { return Err(SpecterError::MalformedTls("Not ServerHello".into())); }
        let h_len = read_u24(hs, 1)?;
        hs.get(4..4 + h_len).ok_or_else(|| SpecterError::MalformedTls("Body overflow".into()))?
    } else if payload.first() == Some(&0x02) && payload.len() >= 4 {
        let h_len = read_u24(payload, 1)?;
        payload.get(4..4 + h_len).ok_or_else(|| SpecterError::MalformedTls("Body overflow".into()))?
    } else {
        return Err(SpecterError::MalformedTls("Not ServerHello".into()));
    };
    if body.len() < 38 { return Err(SpecterError::MalformedTls("ServerHello too short".into())); }
    let server_version = read_u16(body, 0)?;
    let s_len = *body.get(34).ok_or_else(|| SpecterError::MalformedTls("No s_len".into()))? as usize;
    let mut pos = 35 + s_len;
    let cipher_suite = read_u16(body, pos)?;
    pos += 3;
    let mut extensions = Vec::new();
    let mut selected_version = None;
    let mut alpn = None;
    let mut grease_filtered_count = 0;
    if pos + 2 <= body.len() {
        let ext_tot = read_u16(body, pos)? as usize;
        pos += 2;
        let ext_end = pos + ext_tot;
        if ext_end <= body.len() {
            while pos + 4 <= ext_end {
                let (e_type, e_len) = (read_u16(body, pos)?, read_u16(body, pos + 2)? as usize);
                pos += 4;
                if pos + e_len > ext_end { break; }
                let e_data = &body[pos..pos + e_len];
                pos += e_len;
                if is_grease(e_type) { grease_filtered_count += 1; continue; }
                extensions.push(e_type);
                if e_type == 0x0010 && e_data.len() >= 3 {
                    let p_len = e_data[2] as usize;
                    if 3 + p_len <= e_data.len() {
                        alpn = std::str::from_utf8(&e_data[3..3 + p_len]).ok().map(String::from);
                    }
                } else if e_type == 0x002b && e_data.len() >= 2 {
                    selected_version = Some(read_u16(e_data, 0)?);
                }
            }
        }
    }
    let ext_str = extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-");
    let ja3s_string = format!("{server_version},{cipher_suite},{ext_str}");
    let mut md5_h = Md5::new(); md5_h.update(ja3s_string.as_bytes());
    let mut sha_h = Sha256::new(); sha_h.update(ja3s_string.as_bytes());
    Ok(TlsServerHelloReport {
        server_version, cipher_suite, extensions, selected_version, alpn,
        grease_filtered_count, ja3s_string, ja3s_md5: hex::encode(md5_h.finalize()),
        ja3s_sha256: hex::encode(sha_h.finalize()),
    })
}

/// Parses TLS Certificate messages (0x0b) supporting both TLS 1.2 and TLS 1.3 formats.
#[rustfmt::skip]
pub fn parse_tls_certificates(payload: &[u8]) -> Result<Vec<X509CertReport>> {
    if payload.is_empty() { return Err(SpecterError::MalformedCert("Empty".into())); }
    if payload.starts_with(&[0x30]) { return Ok(vec![parse_x509_der(payload)?]); }
    let body = if payload.first() == Some(&0x16) && payload.len() >= 9 {
        let r_len = read_u16(payload, 3)? as usize;
        let hs = payload.get(5..5 + r_len).ok_or_else(|| SpecterError::MalformedCert("Overflow".into()))?;
        if hs.first() != Some(&0x0b) { return Err(SpecterError::MalformedCert("Not Cert hs".into())); }
        let h_len = read_u24(hs, 1)?;
        hs.get(4..4 + h_len).ok_or_else(|| SpecterError::MalformedCert("Overflow".into()))?
    } else if payload.first() == Some(&0x0b) && payload.len() >= 4 {
        let h_len = read_u24(payload, 1)?;
        payload.get(4..4 + h_len).ok_or_else(|| SpecterError::MalformedCert("Overflow".into()))?
    } else {
        return Err(SpecterError::MalformedCert("Not Cert hs".into()));
    };
    if body.len() < 3 { return Err(SpecterError::MalformedCert("Cert body short".into())); }
    let mut slices = Vec::new();
    let ctx_len = body[0] as usize;
    if 1 + ctx_len + 3 <= body.len() {
        let l_len = read_u24(body, 1 + ctx_len)?;
        let (mut pos, end) = (1 + ctx_len + 3, 1 + ctx_len + 3 + l_len);
        if end <= body.len() {
            let mut cand = Vec::new();
            while pos + 3 <= end {
                let c_len = read_u24(body, pos)?;
                pos += 3;
                if pos + c_len > end { break; }
                let c_data = &body[pos..pos + c_len];
                pos += c_len;
                if pos + 2 > end { break; }
                let e_len = read_u16(body, pos)? as usize;
                pos += 2 + e_len;
                if c_data.starts_with(&[0x30]) { cand.push(c_data); }
            }
            if !cand.is_empty() && pos == end { slices = cand; }
        }
    }
    if slices.is_empty() {
        let l_len = read_u24(body, 0)?;
        let (mut pos, end) = (3, 3 + l_len);
        if end <= body.len() {
            while pos + 3 <= end {
                let c_len = read_u24(body, pos)?;
                pos += 3;
                if pos + c_len > end { break; }
                let c_data = &body[pos..pos + c_len];
                pos += c_len;
                if c_data.starts_with(&[0x30]) { slices.push(c_data); }
            }
        }
    }
    if slices.is_empty() { return Err(SpecterError::MalformedCert("No certs found in message".into())); }
    slices.into_iter().map(parse_x509_der).collect()
}

#[rustfmt::skip]
fn scan_tls_payload(payload: &[u8], hellos: &mut Vec<TlsServerHelloReport>, certs: &mut Vec<X509CertReport>) {
    let mut r_off = 0;
    while r_off + 5 <= payload.len() {
        if payload[r_off] != 0x16 { r_off += 1; continue; }
        let r_len = match read_u16(payload, r_off + 3) { Ok(l) => l as usize, Err(_) => { r_off += 1; continue; } };
        let r_end = r_off + 5 + r_len;
        if r_end > payload.len() { r_off += 1; continue; }
        let body = &payload[r_off + 5..r_end];
        let mut h_off = 0;
        while h_off + 4 <= body.len() {
            let (h_type, h_len) = (body[h_off], match read_u24(body, h_off + 1) { Ok(l) => l, Err(_) => break });
            let h_end = h_off + 4 + h_len;
            if h_end > body.len() { break; }
            let h_msg = &body[h_off..h_end];
            if h_type == 0x02 {
                if let Ok(sh) = parse_tls_server_hello(h_msg) {
                    if !hellos.iter().any(|h| h.ja3s_md5 == sh.ja3s_md5) { hellos.push(sh); }
                }
            } else if h_type == 0x0b {
                if let Ok(cs) = parse_tls_certificates(h_msg) {
                    for c in cs {
                        if !certs.iter().any(|x| x.serial_number == c.serial_number && x.subject == c.subject) { certs.push(c); }
                    }
                }
            }
            h_off = h_end;
        }
        r_off = r_end;
    }
}

/// Forensically audits raw bytes, TLS handshakes, or PCAP/PCAPNG captures for certificates and JA3S.
pub fn audit_cert_bytes(raw: &[u8]) -> Result<CertAuditReport> {
    if raw.is_empty() {
        return Err(SpecterError::InvalidArgument("Empty bytes".into()));
    }
    let mut hellos = Vec::new();
    let mut certs = Vec::new();
    if is_pcapng(raw) || parse_pcap_bytes(raw).is_ok() {
        let frames = if is_pcapng(raw) {
            parse_pcapng_bytes(raw)?.frames
        } else {
            parse_pcap_bytes(raw)?.frames
        };
        for f in &frames {
            scan_tls_payload(&f.payload, &mut hellos, &mut certs);
        }
        if let Ok(streams) = reassemble_capture_bytes(raw, true) {
            for s in streams {
                if let Some(h) = s
                    .server_payload_hex
                    .as_deref()
                    .and_then(|x| hex::decode(x).ok())
                {
                    scan_tls_payload(&h, &mut hellos, &mut certs);
                }
                if let Some(h) = s
                    .client_payload_hex
                    .as_deref()
                    .and_then(|x| hex::decode(x).ok())
                {
                    scan_tls_payload(&h, &mut hellos, &mut certs);
                }
            }
        }
    } else if raw.starts_with(&[0x30]) {
        if let Ok(c) = parse_x509_der(raw) {
            certs.push(c);
        }
    } else if raw.starts_with(&[0x16]) {
        scan_tls_payload(raw, &mut hellos, &mut certs);
    } else if raw.starts_with(&[0x02]) {
        if let Ok(sh) = parse_tls_server_hello(raw) {
            hellos.push(sh);
        }
    } else if raw.starts_with(&[0x0b]) {
        if let Ok(cs) = parse_tls_certificates(raw) {
            certs.extend(cs);
        }
    }
    if hellos.is_empty() && certs.is_empty() {
        return Err(SpecterError::MalformedCert(
            "No TLS ServerHello or Certificate messages found".into(),
        ));
    }
    let total_anomalies = certs.iter().map(|c| c.anomalies.len()).sum();
    Ok(CertAuditReport {
        server_hellos: hellos,
        certificates: certs,
        total_anomalies,
    })
}
