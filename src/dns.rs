// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{Result, SpecterError};
use serde::{Deserialize, Serialize};

/// Covert tunneling / C2 DNS anomaly severity tier.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TunnelRisk {
    Low,
    Elevated,
    High,
}

/// Parsed DNS question entry and covert-channel entropy diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsQuestionAudit {
    pub qname: String,
    pub qtype: u16,
    pub qtype_name: String,
    pub qclass: u16,
    pub subdomain_entropy: f64,
    pub longest_label_len: usize,
    pub total_qname_len: usize,
    pub encoded_char_ratio: f64,
    pub risk_score: u8,
    pub risk_level: TunnelRisk,
    pub reasons: Vec<String>,
}

/// Complete DNS packet audit report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsPacketReport {
    pub transaction_id: u16,
    pub flags: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub questions: Vec<DnsQuestionAudit>,
}

/// Maps standard DNS QTYPE numeric codes to human-readable record names.
pub fn qtype_to_str(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        10 => "NULL".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

/// Computes Shannon entropy ($0.0 \le H \le 8.0$ bits/byte) of a byte slice.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / len;
            entropy -= p * p.log2();
        }
    }
    (entropy * 1000.0).round() / 1000.0
}

/// Decodes an RFC 1035 domain name starting at `start_offset`, enforcing a strict
/// compression pointer hop limit (`<= 32`) to prevent cyclic pointer DoS loops.
pub fn decode_qname(packet: &[u8], start_offset: usize) -> Result<(String, usize)> {
    if start_offset >= packet.len() {
        return Err(SpecterError::MalformedDns(
            "QNAME start offset exceeds DNS packet length".into(),
        ));
    }

    let mut labels = Vec::new();
    let mut pos = start_offset;
    let mut next_offset_after_name = None;
    let mut hops = 0usize;
    let mut total_chars = 0usize;

    loop {
        if pos >= packet.len() {
            return Err(SpecterError::MalformedDns(
                "Unexpected EOF while decoding DNS label".into(),
            ));
        }
        let len_byte = packet[pos];
        if len_byte == 0 {
            if next_offset_after_name.is_none() {
                next_offset_after_name = Some(pos + 1);
            }
            break;
        }

        // RFC 1035 Section 4.1.4 compression pointer: top two bits 11 (0xC0)
        if (len_byte & 0xC0) == 0xC0 {
            if pos + 1 >= packet.len() {
                return Err(SpecterError::MalformedDns(
                    "Truncated DNS compression pointer".into(),
                ));
            }
            hops += 1;
            if hops > 32 {
                return Err(SpecterError::MalformedDns(
                    "DNS compression pointer hop limit (32) exceeded".into(),
                ));
            }
            let ptr = (((len_byte & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);
            if ptr >= packet.len() || ptr == pos {
                return Err(SpecterError::MalformedDns(format!(
                    "Invalid DNS compression pointer target 0x{ptr:04x}"
                )));
            }
            if next_offset_after_name.is_none() {
                next_offset_after_name = Some(pos + 2);
            }
            pos = ptr;
            continue;
        }

        if (len_byte & 0xC0) != 0 {
            return Err(SpecterError::MalformedDns(format!(
                "Reserved DNS label flag bits in 0x{len_byte:02x}"
            )));
        }

        let label_len = len_byte as usize;
        pos += 1;
        if pos + label_len > packet.len() {
            return Err(SpecterError::MalformedDns(
                "DNS label length exceeds packet bounds".into(),
            ));
        }
        total_chars += label_len + 1;
        if total_chars > 255 {
            return Err(SpecterError::MalformedDns(
                "Decoded DNS QNAME exceeds 255-byte RFC 1035 limit".into(),
            ));
        }
        let label_str = String::from_utf8_lossy(&packet[pos..pos + label_len]).into_owned();
        labels.push(label_str);
        pos += label_len;
    }

    let final_offset = next_offset_after_name.unwrap_or(pos);
    Ok((labels.join("."), final_offset))
}

fn evaluate_question_tunnel_risk(qname: &str, qtype: u16, qclass: u16) -> DnsQuestionAudit {
    let labels: Vec<&str> = if qname.is_empty() {
        Vec::new()
    } else {
        qname.split('.').collect()
    };

    let longest_label_len = labels.iter().map(|l| l.len()).max().unwrap_or(0);
    let total_qname_len = qname.len();

    // Isolate subdomain labels ahead of the registrable 2-label root (e.g., sub1.sub2.example.com -> sub1.sub2)
    let subdomain_str = if labels.len() > 2 {
        labels[..labels.len() - 2].join("")
    } else if let Some(first) = labels.first() {
        (*first).to_string()
    } else {
        String::new()
    };

    let subdomain_entropy = shannon_entropy(subdomain_str.as_bytes());
    let encoded_chars = subdomain_str
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || matches!(c, '2'..='7'))
        .count();
    let encoded_char_ratio = if subdomain_str.is_empty() {
        0.0
    } else {
        ((encoded_chars as f64 / subdomain_str.len() as f64) * 1000.0).round() / 1000.0
    };

    let mut score: u16 = 0;
    let mut reasons = Vec::new();

    if subdomain_entropy >= 3.8 && subdomain_str.len() >= 16 {
        score += 35;
        reasons.push(format!(
            "High subdomain Shannon entropy ({subdomain_entropy:.2} bits/byte)"
        ));
    } else if subdomain_entropy >= 3.3 && subdomain_str.len() >= 12 {
        score += 20;
        reasons.push(format!(
            "Elevated subdomain Shannon entropy ({subdomain_entropy:.2} bits/byte)"
        ));
    }

    if longest_label_len >= 32 {
        score += 30;
        reasons.push(format!(
            "Oversized subdomain label ({longest_label_len} chars >= 32)"
        ));
    } else if longest_label_len >= 20 {
        score += 15;
        reasons.push(format!(
            "Long subdomain label ({longest_label_len} chars >= 20)"
        ));
    }

    if total_qname_len >= 70 {
        score += 15;
        reasons.push(format!(
            "Extended total QNAME length ({total_qname_len} chars)"
        ));
    }

    if matches!(qtype, 10 | 16) {
        score += 15;
        reasons.push(format!(
            "High-capacity record type ({}) commonly abused for covert data exfiltration",
            qtype_to_str(qtype)
        ));
    }

    if subdomain_str.len() >= 20 && encoded_char_ratio >= 0.85 {
        score += 15;
        reasons.push(format!(
            "Dense hex/base32 payload encoding ratio ({:.1}%)",
            encoded_char_ratio * 100.0
        ));
    }

    let capped_score = score.min(100) as u8;
    let risk_level = if capped_score >= 60 {
        TunnelRisk::High
    } else if capped_score >= 30 {
        TunnelRisk::Elevated
    } else {
        TunnelRisk::Low
    };

    DnsQuestionAudit {
        qname: qname.to_string(),
        qtype,
        qtype_name: qtype_to_str(qtype),
        qclass,
        subdomain_entropy,
        longest_label_len,
        total_qname_len,
        encoded_char_ratio,
        risk_score: capped_score,
        risk_level,
        reasons,
    }
}

/// Parses a raw DNS wire-format packet and audits all question entries for covert
/// tunneling or C2 beacon indicators.
pub fn parse_dns_packet(packet: &[u8]) -> Result<DnsPacketReport> {
    if packet.len() < 12 {
        return Err(SpecterError::MalformedDns(format!(
            "DNS packet shorter than 12-byte header ({} bytes)",
            packet.len()
        )));
    }

    let transaction_id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let is_response = (flags & 0x8000) != 0;
    let opcode = ((flags >> 11) & 0x0f) as u8;
    let rcode = (flags & 0x000f) as u8;

    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    let answer_count = u16::from_be_bytes([packet[6], packet[7]]);
    let authority_count = u16::from_be_bytes([packet[8], packet[9]]);
    let additional_count = u16::from_be_bytes([packet[10], packet[11]]);

    if question_count > 64 {
        return Err(SpecterError::MalformedDns(format!(
            "Excessive DNS QDCOUNT ({question_count})"
        )));
    }

    let mut offset = 12;
    let mut questions = Vec::with_capacity(question_count as usize);

    for _ in 0..question_count {
        let (qname, next_off) = decode_qname(packet, offset)?;
        if next_off + 4 > packet.len() {
            return Err(SpecterError::MalformedDns(
                "Truncated DNS question QTYPE/QCLASS fields".into(),
            ));
        }
        let qtype = u16::from_be_bytes([packet[next_off], packet[next_off + 1]]);
        let qclass = u16::from_be_bytes([packet[next_off + 2], packet[next_off + 3]]);
        offset = next_off + 4;

        questions.push(evaluate_question_tunnel_risk(&qname, qtype, qclass));
    }

    Ok(DnsPacketReport {
        transaction_id,
        flags,
        is_response,
        opcode,
        rcode,
        question_count,
        answer_count,
        authority_count,
        additional_count,
        questions,
    })
}

/// Builds a deterministic wire-format DNS query packet for `domain` and `qtype`.
pub fn build_dns_query_packet(transaction_id: u16, domain: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&transaction_id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    for label in domain.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        pkt.push(len as u8);
        pkt.extend_from_slice(&bytes[..len]);
    }
    pkt.push(0x00); // root label terminator
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN (1)
    pkt
}
