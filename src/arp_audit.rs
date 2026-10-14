// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! ARP Spoofing & Layer-2 MITM Anomaly Detector.
//!
//! Decodes Ethernet ARP requests and replies (RFC 826, EtherType 0x0806),
//! tracks IP-to-MAC dynamic bindings, detects gratuitous ARP floods,
//! identifies conflicting IP ownership, flags gateway MAC flapping,
//! and uncovers Ethernet L2 header vs ARP payload hardware address discrepancies.

use crate::error::{Result, SpecterError};
use crate::pcap::{decode_frame, format_mac, parse_pcap_bytes, DecodedFrame};
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

pub const ARP_HTYPE_ETHERNET: u16 = 1;
pub const ARP_PTYPE_IPV4: u16 = 0x0800;

pub const ARP_OPER_REQUEST: u16 = 1;
pub const ARP_OPER_REPLY: u16 = 2;
pub const ARP_OPER_RARP_REQUEST: u16 = 3;
pub const ARP_OPER_RARP_REPLY: u16 = 4;

/// ARP message operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArpOpcode {
    Request,
    Reply,
    RarpRequest,
    RarpReply,
    Other(u16),
}

impl From<u16> for ArpOpcode {
    fn from(val: u16) -> Self {
        match val {
            ARP_OPER_REQUEST => Self::Request,
            ARP_OPER_REPLY => Self::Reply,
            ARP_OPER_RARP_REQUEST => Self::RarpRequest,
            ARP_OPER_RARP_REPLY => Self::RarpReply,
            other => Self::Other(other),
        }
    }
}

/// Specialized ARP message subtype classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArpSubtype {
    StandardRequest,
    StandardReply,
    GratuitousRequest,
    GratuitousReply,
    ArpProbe,
    ArpAnnouncement,
    Other,
}

/// Overall security verdict for the analyzed capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArpVerdict {
    Clean,
    Suspicious,
    AttackDetected,
}

/// Parsed ARP packet with security inspection telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpPacket {
    pub frame_index: usize,
    pub timestamp_ns: u64,
    pub opcode: ArpOpcode,
    pub subtype: ArpSubtype,
    pub sender_mac: String,
    pub sender_ip: String,
    pub target_mac: String,
    pub target_ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eth_src_mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eth_dst_mac: Option<String>,
    pub is_gratuitous: bool,
    pub anomalies: Vec<String>,
}

/// Tracked IP-to-MAC binding and historical transition state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpMacBinding {
    pub ip: String,
    pub current_mac: String,
    pub observed_macs: Vec<String>,
    pub mac_transitions: usize,
    pub is_gateway: bool,
    pub is_flapping: bool,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub requests_sent: usize,
    pub replies_sent: usize,
    pub gratuitous_count: usize,
    pub anomalies: Vec<String>,
}

/// Configuration parameters for ARP anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpAuditConfig {
    pub gateway_ips: Vec<String>,
    pub flood_threshold_per_sec: f64,
    pub flapping_transition_threshold: usize,
}

impl Default for ArpAuditConfig {
    fn default() -> Self {
        Self {
            gateway_ips: Vec::new(),
            flood_threshold_per_sec: 5.0,
            flapping_transition_threshold: 2,
        }
    }
}

/// Comprehensive ARP audit and Layer-2 MITM forensic report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpAuditReport {
    pub source: String,
    pub total_capture_frames: usize,
    pub total_arp_frames: usize,
    pub requests: usize,
    pub replies: usize,
    pub gratuitous_count: usize,
    pub bindings: Vec<IpMacBinding>,
    pub anomalous_frames: Vec<ArpPacket>,
    pub detected_threats: Vec<String>,
    pub overall_verdict: ArpVerdict,
    pub summary: String,
}

/// Parses a 28-byte Ethernet IPv4 ARP payload slice into an `ArpPacket`.
pub fn parse_arp_payload(
    frame_index: usize,
    timestamp_ns: u64,
    payload: &[u8],
    eth_src: Option<&str>,
    eth_dst: Option<&str>,
) -> Result<ArpPacket> {
    if payload.len() < 28 {
        return Err(SpecterError::MalformedArp(format!(
            "ARP payload truncated ({} bytes, expected >= 28)",
            payload.len()
        )));
    }

    let htype = u16::from_be_bytes([payload[0], payload[1]]);
    let ptype = u16::from_be_bytes([payload[2], payload[3]]);
    let hlen = payload[4];
    let plen = payload[5];
    let oper_val = u16::from_be_bytes([payload[6], payload[7]]);

    if htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 || hlen != 6 || plen != 4 {
        return Err(SpecterError::MalformedArp(format!(
            "Unsupported ARP parameters: htype=0x{htype:04x}, ptype=0x{ptype:04x}, hlen={hlen}, plen={plen}"
        )));
    }

    let sender_mac_bytes = &payload[8..14];
    let sender_ip_bytes = [payload[14], payload[15], payload[16], payload[17]];
    let target_mac_bytes = &payload[18..24];
    let target_ip_bytes = [payload[24], payload[25], payload[26], payload[27]];

    let sender_mac = format_mac(sender_mac_bytes);
    let sender_ip = Ipv4Addr::from(sender_ip_bytes).to_string();
    let target_mac = format_mac(target_mac_bytes);
    let target_ip = Ipv4Addr::from(target_ip_bytes).to_string();

    let opcode = ArpOpcode::from(oper_val);
    let is_sender_zero_ip = sender_ip_bytes == [0, 0, 0, 0];
    let is_sender_zero_mac = sender_mac_bytes == [0; 6];
    let is_target_zero_mac = target_mac_bytes == [0; 6];
    let is_ip_match = sender_ip_bytes == target_ip_bytes;

    let subtype = match opcode {
        ArpOpcode::Request => {
            if is_sender_zero_ip && is_target_zero_mac && !is_ip_match {
                ArpSubtype::ArpProbe
            } else if is_ip_match {
                if is_target_zero_mac || target_mac_bytes == [0xff; 6] {
                    ArpSubtype::ArpAnnouncement
                } else {
                    ArpSubtype::GratuitousRequest
                }
            } else {
                ArpSubtype::StandardRequest
            }
        }
        ArpOpcode::Reply => {
            if is_ip_match {
                ArpSubtype::GratuitousReply
            } else {
                ArpSubtype::StandardReply
            }
        }
        _ => ArpSubtype::Other,
    };

    let is_gratuitous = matches!(
        subtype,
        ArpSubtype::GratuitousRequest | ArpSubtype::GratuitousReply | ArpSubtype::ArpAnnouncement
    );

    let mut anomalies = Vec::new();

    // 1. Ethernet L2 src MAC vs ARP sender MAC discrepancy
    if let Some(eth_s) = eth_src {
        if !eth_s.is_empty() && !eth_s.eq_ignore_ascii_case(&sender_mac) {
            anomalies.push(format!(
                "Ethernet L2 source MAC ({eth_s}) does not match ARP sender MAC ({sender_mac})"
            ));
        }
    }

    // 2. Broadcast ARP reply violation
    if opcode == ArpOpcode::Reply {
        if let Some(eth_d) = eth_dst {
            if eth_d.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff") {
                anomalies.push(
                    "RFC 826 violation: Unicast ARP reply sent to broadcast Ethernet MAC (ff:ff:ff:ff:ff:ff)".into()
                );
            }
        }
        if is_sender_zero_ip {
            anomalies.push("Invalid ARP reply with 0.0.0.0 sender IP".into());
        }
    }

    // 3. Sender MAC sanity checks
    if is_sender_zero_mac {
        anomalies.push("Invalid sender MAC: all zeroes (00:00:00:00:00:00)".into());
    } else if sender_mac_bytes[0] & 0x01 != 0 {
        anomalies.push(format!(
            "Invalid sender MAC: multicast/broadcast bit set ({sender_mac})"
        ));
    }

    // 4. IP address sanity checks
    if sender_ip_bytes[0] == 127 {
        anomalies.push(format!("Illegal loopback IP in ARP sender: {sender_ip}"));
    } else if sender_ip_bytes[0] >= 224 && sender_ip_bytes[0] <= 239 {
        anomalies.push(format!("Illegal multicast IP in ARP sender: {sender_ip}"));
    } else if sender_ip_bytes == [255, 255, 255, 255] {
        anomalies.push("Illegal broadcast IP in ARP sender: 255.255.255.255".into());
    }

    Ok(ArpPacket {
        frame_index,
        timestamp_ns,
        opcode,
        subtype,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
        eth_src_mac: eth_src.map(|s| s.to_string()),
        eth_dst_mac: eth_dst.map(|s| s.to_string()),
        is_gratuitous,
        anomalies,
    })
}

#[derive(Default)]
struct IpTracker {
    initial_mac: String,
    current_mac: String,
    mac_history: Vec<(String, u64)>,
    requests_sent: usize,
    replies_sent: usize,
    gratuitous_count: usize,
    first_seen_ns: u64,
    last_seen_ns: u64,
}

/// Audits arbitrary capture data (PCAP, PCAPNG, or raw packet bytes) for ARP spoofing and Layer-2 MITM anomalies.
pub fn audit_arp_bytes(
    data: &[u8],
    source_name: &str,
    config_opt: Option<ArpAuditConfig>,
) -> Result<ArpAuditReport> {
    let config = config_opt.unwrap_or_default();
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
        if let Ok(df) = decode_frame(1, 0, 0, data.len() as u32, 1, data) {
            frames.push(df);
        } else {
            return Err(SpecterError::MalformedArp(
                "Provided buffer is not a valid PCAP, PCAPNG, or raw Ethernet frame".into(),
            ));
        }
    }

    let total_capture_frames = frames.len();
    let mut arp_packets = Vec::new();
    let mut requests = 0usize;
    let mut replies = 0usize;
    let mut gratuitous_count = 0usize;

    for frame in &frames {
        if frame.protocol.eq_ignore_ascii_case("ARP") {
            let ts_ns = (frame.ts_sec as u64) * 1_000_000_000 + (frame.ts_subsec as u64);
            if let Ok(pkt) = parse_arp_payload(
                frame.index,
                ts_ns,
                &frame.payload,
                frame.src_mac.as_deref(),
                frame.dst_mac.as_deref(),
            ) {
                match pkt.opcode {
                    ArpOpcode::Request => requests += 1,
                    ArpOpcode::Reply => replies += 1,
                    _ => {}
                }
                if pkt.is_gratuitous {
                    gratuitous_count += 1;
                }
                arp_packets.push(pkt);
            }
        }
    }

    // IP State & Flapping Tracker
    let mut ip_trackers: HashMap<String, IpTracker> = HashMap::new();
    let mut candidate_gateways: HashSet<String> = config.gateway_ips.iter().cloned().collect();

    for pkt in &arp_packets {
        if pkt.sender_ip == "0.0.0.0" {
            continue;
        }

        // Auto-infer common gateway patterns (.1, .254) if none provided
        if candidate_gateways.is_empty()
            && (pkt.sender_ip.ends_with(".1") || pkt.sender_ip.ends_with(".254"))
        {
            candidate_gateways.insert(pkt.sender_ip.clone());
        }

        let tracker = ip_trackers
            .entry(pkt.sender_ip.clone())
            .or_insert_with(|| IpTracker {
                initial_mac: pkt.sender_mac.clone(),
                current_mac: pkt.sender_mac.clone(),
                mac_history: Vec::new(),
                requests_sent: 0,
                replies_sent: 0,
                gratuitous_count: 0,
                first_seen_ns: pkt.timestamp_ns,
                last_seen_ns: pkt.timestamp_ns,
            });

        if tracker.current_mac != pkt.sender_mac {
            tracker
                .mac_history
                .push((pkt.sender_mac.clone(), pkt.timestamp_ns));
            tracker.current_mac = pkt.sender_mac.clone();
        }

        match pkt.opcode {
            ArpOpcode::Request => tracker.requests_sent += 1,
            ArpOpcode::Reply => tracker.replies_sent += 1,
            _ => {}
        }
        if pkt.is_gratuitous {
            tracker.gratuitous_count += 1;
        }
        tracker.last_seen_ns = pkt.timestamp_ns;
    }

    let mut bindings = Vec::new();
    let mut detected_threats = Vec::new();
    let mut has_attack = false;
    let mut has_suspicious = false;

    for (ip, tracker) in &ip_trackers {
        let mut observed = Vec::new();
        let mut seen = HashSet::new();
        observed.push(tracker.initial_mac.clone());
        seen.insert(tracker.initial_mac.clone());

        for (mac, _) in &tracker.mac_history {
            if seen.insert(mac.clone()) {
                observed.push(mac.clone());
            }
        }

        let transitions = tracker.mac_history.len();
        let is_gw = candidate_gateways.contains(ip);
        let is_flapping = transitions >= config.flapping_transition_threshold;
        let mut anomalies = Vec::new();

        if observed.len() > 1 {
            let mac_list = observed.join(", ");
            anomalies.push(format!(
                "Conflicting IP-to-MAC bindings observed ({transitions} transition(s)): [{mac_list}]"
            ));
            if is_gw {
                anomalies.push(format!(
                    "CRITICAL: Gateway MAC flapping detected on {ip}! Multiple MAC addresses claiming default gateway."
                ));
                detected_threats.push(format!(
                    "Gateway MAC Flapping / MITM Poisoning on {ip} ([{mac_list}])"
                ));
                has_attack = true;
            } else {
                detected_threats.push(format!(
                    "Conflicting IP Ownership on host {ip} ([{mac_list}])"
                ));
                has_suspicious = true;
                if is_flapping {
                    has_attack = true;
                }
            }
        }

        bindings.push(IpMacBinding {
            ip: ip.clone(),
            current_mac: tracker.current_mac.clone(),
            observed_macs: observed,
            mac_transitions: transitions,
            is_gateway: is_gw,
            is_flapping,
            first_seen_ns: tracker.first_seen_ns,
            last_seen_ns: tracker.last_seen_ns,
            requests_sent: tracker.requests_sent,
            replies_sent: tracker.replies_sent,
            gratuitous_count: tracker.gratuitous_count,
            anomalies,
        });
    }

    // Sort bindings deterministically by IP
    bindings.sort_by(|a, b| a.ip.cmp(&b.ip));

    // Flood detection across entire capture duration
    if !arp_packets.is_empty() {
        let first_ts = arp_packets.first().map(|p| p.timestamp_ns).unwrap_or(0);
        let last_ts = arp_packets.last().map(|p| p.timestamp_ns).unwrap_or(0);
        let duration_secs = ((last_ts.saturating_sub(first_ts)) as f64) / 1_000_000_000.0;
        let effective_duration = if duration_secs < 0.1 {
            1.0
        } else {
            duration_secs
        };
        let garp_rate = (gratuitous_count as f64) / effective_duration;

        if gratuitous_count >= 10 && garp_rate >= config.flood_threshold_per_sec {
            detected_threats.push(format!(
                "Gratuitous ARP Flood: {gratuitous_count} packet(s) at {garp_rate:.1} pkt/s"
            ));
            has_attack = true;
        }
    }

    // Check individual packet anomalies
    let mut anomalous_frames = Vec::new();
    for pkt in &arp_packets {
        if !pkt.anomalies.is_empty() {
            for a in &pkt.anomalies {
                if a.starts_with("Ethernet L2 source MAC") || a.starts_with("RFC 826 violation") {
                    has_attack = true;
                    if !detected_threats.contains(a) {
                        detected_threats.push(a.clone());
                    }
                } else {
                    has_suspicious = true;
                }
            }
            anomalous_frames.push(pkt.clone());
        }
    }

    let overall_verdict = if has_attack {
        ArpVerdict::AttackDetected
    } else if has_suspicious {
        ArpVerdict::Suspicious
    } else {
        ArpVerdict::Clean
    };

    let summary = match overall_verdict {
        ArpVerdict::AttackDetected => format!(
            "CRITICAL: Active ARP spoofing, Layer-2 MITM, or gateway flapping detected across {} threat indicator(s).",
            detected_threats.len()
        ),
        ArpVerdict::Suspicious => format!(
            "WARNING: Suspicious Layer-2 ARP activity detected ({} anomaly indicator(s)).",
            detected_threats.len()
        ),
        ArpVerdict::Clean => {
            "CLEAN: All ARP exchanges exhibit consistent IP-to-MAC bindings with zero anomalies.".into()
        }
    };

    Ok(ArpAuditReport {
        source: source_name.to_string(),
        total_capture_frames,
        total_arp_frames: arp_packets.len(),
        requests,
        replies,
        gratuitous_count,
        bindings,
        anomalous_frames,
        detected_threats,
        overall_verdict,
        summary,
    })
}

/// Scenario configurations for deterministic synthetic ARP PCAP generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpScenario {
    CleanResolution,
    ConflictingBinding,
    GatewayFlapping,
    GratuitousFlood,
    EthernetMacMismatch,
    BroadcastReply,
    ArpProbeAndAnnouncement,
}

/// Deterministically constructs a raw Ethernet ARP packet frame.
pub fn build_raw_arp_frame(
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    opcode: u16,
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    // Ethernet Header (14 bytes)
    frame.extend_from_slice(&eth_dst);
    frame.extend_from_slice(&eth_src);
    frame.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType ARP

    // ARP Payload (28 bytes)
    frame.extend_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    frame.extend_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    frame.push(6); // HLEN
    frame.push(4); // PLEN
    frame.extend_from_slice(&opcode.to_be_bytes());
    frame.extend_from_slice(&sender_mac);
    frame.extend_from_slice(&sender_ip);
    frame.extend_from_slice(&target_mac);
    frame.extend_from_slice(&target_ip);

    frame
}

/// Builds a deterministic synthetic `.pcap` capture modeling diverse Layer-2 ARP scenarios.
pub fn build_synthetic_arp_pcap(scenario: ArpScenario) -> Vec<u8> {
    let mut pcap = Vec::new();
    // Global PCAP Header (24 bytes)
    pcap.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // Magic (microsecond LE)
    pcap.extend_from_slice(&2u16.to_le_bytes()); // Major 2
    pcap.extend_from_slice(&4u16.to_le_bytes()); // Minor 4
    pcap.extend_from_slice(&0u32.to_le_bytes()); // Thiszone
    pcap.extend_from_slice(&0u32.to_le_bytes()); // Sigfigs
    pcap.extend_from_slice(&65535u32.to_le_bytes()); // Snaplen
    pcap.extend_from_slice(&1u32.to_le_bytes()); // LinkType 1 (Ethernet)

    let mut append_pkt = |sec: u32, usec: u32, raw_pkt: &[u8]| {
        let len = raw_pkt.len() as u32;
        pcap.extend_from_slice(&sec.to_le_bytes());
        pcap.extend_from_slice(&usec.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(raw_pkt);
    };

    let bcast_mac = [0xff; 6];
    let client_mac = [0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33];
    let client_ip = [192, 168, 1, 50];
    let gateway_mac = [0x00, 0x50, 0x56, 0xc0, 0x00, 0x08];
    let gateway_ip = [192, 168, 1, 1];
    let attacker_mac = [0xde, 0xad, 0xbe, 0xef, 0x13, 0x37];

    match scenario {
        ArpScenario::CleanResolution => {
            // Frame 1: Request
            let req = build_raw_arp_frame(
                bcast_mac,
                client_mac,
                ARP_OPER_REQUEST,
                client_mac,
                client_ip,
                [0; 6],
                gateway_ip,
            );
            append_pkt(1700000000, 100000, &req);

            // Frame 2: Reply
            let rep = build_raw_arp_frame(
                client_mac,
                gateway_mac,
                ARP_OPER_REPLY,
                gateway_mac,
                gateway_ip,
                client_mac,
                client_ip,
            );
            append_pkt(1700000000, 105000, &rep);
        }
        ArpScenario::ConflictingBinding => {
            // Frame 1: Normal Host A claims 192.168.1.100
            let host_a_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
            let host_ip = [192, 168, 1, 100];
            let rep1 = build_raw_arp_frame(
                bcast_mac,
                host_a_mac,
                ARP_OPER_REPLY,
                host_a_mac,
                host_ip,
                client_mac,
                client_ip,
            );
            append_pkt(1700000000, 100000, &rep1);

            // Frame 2: Rogue Host B claims same 192.168.1.100 with different MAC
            let rep2 = build_raw_arp_frame(
                bcast_mac,
                attacker_mac,
                ARP_OPER_REPLY,
                attacker_mac,
                host_ip,
                client_mac,
                client_ip,
            );
            append_pkt(1700000000, 200000, &rep2);
        }
        ArpScenario::GatewayFlapping => {
            // Legitimate gateway -> Attacker -> Legitimate gateway -> Attacker
            let rep_legit = build_raw_arp_frame(
                client_mac,
                gateway_mac,
                ARP_OPER_REPLY,
                gateway_mac,
                gateway_ip,
                client_mac,
                client_ip,
            );
            let rep_rogue = build_raw_arp_frame(
                client_mac,
                attacker_mac,
                ARP_OPER_REPLY,
                attacker_mac,
                gateway_ip,
                client_mac,
                client_ip,
            );

            append_pkt(1700000000, 100000, &rep_legit);
            append_pkt(1700000000, 200000, &rep_rogue);
            append_pkt(1700000000, 300000, &rep_legit);
            append_pkt(1700000000, 400000, &rep_rogue);
        }
        ArpScenario::GratuitousFlood => {
            for i in 0..15 {
                let garp = build_raw_arp_frame(
                    bcast_mac,
                    attacker_mac,
                    ARP_OPER_REPLY,
                    attacker_mac,
                    gateway_ip,
                    bcast_mac,
                    gateway_ip,
                );
                append_pkt(1700000000, i * 20000, &garp);
            }
        }
        ArpScenario::EthernetMacMismatch => {
            // L2 frame has attacker MAC, but ARP SHA claims gateway MAC
            let spoof = build_raw_arp_frame(
                client_mac,
                attacker_mac, // L2 source
                ARP_OPER_REPLY,
                gateway_mac, // ARP SHA forged
                gateway_ip,
                client_mac,
                client_ip,
            );
            append_pkt(1700000000, 100000, &spoof);
        }
        ArpScenario::BroadcastReply => {
            // Reply sent to broadcast L2 address
            let bcast_rep = build_raw_arp_frame(
                bcast_mac, // L2 destination is broadcast!
                gateway_mac,
                ARP_OPER_REPLY,
                gateway_mac,
                gateway_ip,
                client_mac,
                client_ip,
            );
            append_pkt(1700000000, 100000, &bcast_rep);
        }
        ArpScenario::ArpProbeAndAnnouncement => {
            // RFC 5227 ACD Probe
            let probe = build_raw_arp_frame(
                bcast_mac,
                client_mac,
                ARP_OPER_REQUEST,
                client_mac,
                [0, 0, 0, 0], // probe sender IP is 0.0.0.0
                [0; 6],
                client_ip,
            );
            append_pkt(1700000000, 100000, &probe);

            // RFC 5227 ACD Announcement
            let announce = build_raw_arp_frame(
                bcast_mac,
                client_mac,
                ARP_OPER_REQUEST,
                client_mac,
                client_ip,
                [0; 6],
                client_ip,
            );
            append_pkt(1700000000, 300000, &announce);
        }
    }

    pcap
}
