// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::dns::{build_dns_query_packet, parse_dns_packet, DnsPacketReport};
use crate::error::{Result, SpecterError};
use crate::tls_ja3::{build_sample_client_hello, parse_tls_client_hello, TlsClientHelloReport};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const PCAP_MAGIC_USEC_LE: u32 = 0xA1B2_C3D4;
pub const PCAP_MAGIC_NSEC_LE: u32 = 0xA1B2_3C4D;
pub const PCAP_MAGIC_USEC_BE: u32 = 0xD4C3_B2A1;
pub const PCAP_MAGIC_NSEC_BE: u32 = 0x4D3C_B2A1;

pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW_IP: u32 = 101;

/// Global header metadata of a classic libpcap `.pcap` file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcapGlobalHeader {
    pub version_major: u16,
    pub version_minor: u16,
    pub snaplen: u32,
    pub linktype: u32,
    pub nanosecond_precision: bool,
    pub big_endian: bool,
}

/// Decoded L4 TCP flags.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
}

/// Decoded L3/L4 packet metadata and application payload slice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecodedFrame {
    pub index: usize,
    pub ts_sec: u32,
    pub ts_subsec: u32,
    pub orig_len: u32,
    pub src_ip: String,
    pub dst_ip: String,
    pub ip_version: u8,
    pub ttl: u8,
    pub protocol: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub tcp_flags: Option<TcpFlags>,
    pub tcp_window: Option<u16>,
    pub tcp_options: Option<Vec<u8>>,
    pub ip_df: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_mac: Option<String>,
    pub payload: Vec<u8>,
}

/// Formats a 6-byte Ethernet MAC address slice as lowercase hex with colons.
#[inline]
pub fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() >= 6 {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    } else {
        hex::encode(bytes)
    }
}

/// Comprehensive summary of a `.pcap` capture file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapInspectReport {
    pub header: PcapGlobalHeader,
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

/// Parses a raw `.pcap` byte buffer, decodes all L2/L3/L4 packets, and extracts
/// any embedded TLS `ClientHello` handshakes and DNS messages.
pub fn parse_pcap_bytes(data: &[u8]) -> Result<PcapInspectReport> {
    if data.len() < 24 {
        return Err(SpecterError::InvalidPcap(
            "Buffer shorter than 24-byte PCAP global header".into(),
        ));
    }

    let raw_magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (big_endian, nanosecond_precision) = match raw_magic {
        PCAP_MAGIC_USEC_LE => (false, false),
        PCAP_MAGIC_NSEC_LE => (false, true),
        PCAP_MAGIC_USEC_BE => (true, false),
        PCAP_MAGIC_NSEC_BE => (true, true),
        other => {
            return Err(SpecterError::InvalidPcap(format!(
                "Unrecognized PCAP magic number 0x{other:08x}"
            )))
        }
    };

    let version_major = read_u16(&data[4..6], big_endian);
    let version_minor = read_u16(&data[6..8], big_endian);
    if version_major != 2 || version_minor != 4 {
        return Err(SpecterError::InvalidPcap(format!(
            "Unsupported PCAP version {version_major}.{version_minor} (expected 2.4)"
        )));
    }

    let snaplen = read_u32(&data[16..20], big_endian);
    let linktype = read_u32(&data[20..24], big_endian);
    if snaplen == 0 || snaplen > 16 * 1024 * 1024 {
        return Err(SpecterError::InvalidPcap(format!(
            "Invalid PCAP snaplen {snaplen}"
        )));
    }
    if linktype != LINKTYPE_ETHERNET && linktype != LINKTYPE_RAW_IP {
        return Err(SpecterError::InvalidPcap(format!(
            "Unsupported PCAP linktype {linktype} (supported: 1 Ethernet, 101 Raw IP)"
        )));
    }

    let header = PcapGlobalHeader {
        version_major,
        version_minor,
        snaplen,
        linktype,
        nanosecond_precision,
        big_endian,
    };

    let mut pos = 24usize;
    let mut index = 0usize;
    let mut tcp_packets = 0usize;
    let mut udp_packets = 0usize;
    let mut frames = Vec::new();
    let mut tls_handshakes = Vec::new();
    let mut dns_messages = Vec::new();

    while pos < data.len() {
        if pos + 16 > data.len() {
            return Err(SpecterError::InvalidPcap(format!(
                "Truncated 16-byte packet record header at offset {pos}"
            )));
        }
        let ts_sec = read_u32(&data[pos..pos + 4], big_endian);
        let ts_subsec = read_u32(&data[pos + 4..pos + 8], big_endian);
        let incl_len = read_u32(&data[pos + 8..pos + 12], big_endian) as usize;
        let orig_len = read_u32(&data[pos + 12..pos + 16], big_endian);
        pos += 16;

        if incl_len > snaplen as usize || pos + incl_len > data.len() {
            return Err(SpecterError::InvalidPcap(format!(
                "Packet #{index} incl_len ({incl_len}) exceeds snaplen ({snaplen}) or file bounds"
            )));
        }

        let raw_pkt = &data[pos..pos + incl_len];
        pos += incl_len;

        let decoded = decode_frame(index, ts_sec, ts_subsec, orig_len, linktype, raw_pkt)?;
        index += 1;

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

    Ok(PcapInspectReport {
        header,
        total_packets: index,
        tcp_packets,
        udp_packets,
        frames,
        tls_handshakes,
        dns_messages,
    })
}

/// Decodes a single L2/L3/L4 frame from an Ethernet II or Raw IP slice.
pub fn decode_frame(
    index: usize,
    ts_sec: u32,
    ts_subsec: u32,
    orig_len: u32,
    linktype: u32,
    raw: &[u8],
) -> Result<DecodedFrame> {
    let (l3_slice, src_mac, dst_mac) = match linktype {
        LINKTYPE_ETHERNET => {
            if raw.len() < 14 {
                return Err(SpecterError::InvalidPacket(
                    "Ethernet II frame shorter than 14 bytes".into(),
                ));
            }
            let dst_mac = format_mac(&raw[0..6]);
            let src_mac = format_mac(&raw[6..12]);
            let mut ethertype = u16::from_be_bytes([raw[12], raw[13]]);
            let mut l3_offset = 14usize;
            // IEEE 802.1Q VLAN tag unwrap
            if ethertype == 0x8100 {
                if raw.len() < 18 {
                    return Err(SpecterError::InvalidPacket(
                        "Truncated 802.1Q VLAN header".into(),
                    ));
                }
                ethertype = u16::from_be_bytes([raw[16], raw[17]]);
                l3_offset = 18;
            }
            if ethertype == 0x0806 {
                let arp_slice = &raw[l3_offset..];
                if arp_slice.len() < 28 {
                    return Err(SpecterError::InvalidPacket(
                        "ARP packet shorter than 28 bytes".into(),
                    ));
                }
                let hlen = arp_slice[4];
                let plen = arp_slice[5];
                let oper = u16::from_be_bytes([arp_slice[6], arp_slice[7]]);
                let (src_ip, dst_ip) = if hlen == 6 && plen == 4 && arp_slice.len() >= 28 {
                    let spa =
                        Ipv4Addr::new(arp_slice[14], arp_slice[15], arp_slice[16], arp_slice[17])
                            .to_string();
                    let tpa =
                        Ipv4Addr::new(arp_slice[24], arp_slice[25], arp_slice[26], arp_slice[27])
                            .to_string();
                    (spa, tpa)
                } else {
                    ("0.0.0.0".to_string(), "0.0.0.0".to_string())
                };
                return Ok(DecodedFrame {
                    index,
                    ts_sec,
                    ts_subsec,
                    orig_len,
                    src_ip,
                    dst_ip,
                    ip_version: 0,
                    ttl: 0,
                    protocol: "ARP".into(),
                    src_port: 0,
                    dst_port: oper,
                    tcp_seq: None,
                    tcp_ack: None,
                    tcp_flags: None,
                    tcp_window: None,
                    tcp_options: None,
                    ip_df: None,
                    src_mac: Some(src_mac),
                    dst_mac: Some(dst_mac),
                    payload: arp_slice.to_vec(),
                });
            }
            if ethertype != 0x0800 && ethertype != 0x86DD {
                return Err(SpecterError::InvalidPacket(format!(
                    "Unsupported EtherType 0x{ethertype:04x}"
                )));
            }
            (&raw[l3_offset..], Some(src_mac), Some(dst_mac))
        }
        LINKTYPE_RAW_IP => (raw, None, None),
        other => {
            return Err(SpecterError::InvalidPacket(format!(
                "Unsupported linktype {other}"
            )))
        }
    };

    if l3_slice.is_empty() {
        return Err(SpecterError::InvalidPacket("Empty L3 packet".into()));
    }

    let ip_version = l3_slice[0] >> 4;
    let (src_ip, dst_ip, ttl, proto_num, ip_df, l4_slice) = match ip_version {
        4 => {
            if l3_slice.len() < 20 {
                return Err(SpecterError::InvalidPacket(
                    "IPv4 header shorter than 20 bytes".into(),
                ));
            }
            let ihl = ((l3_slice[0] & 0x0f) as usize) * 4;
            let total_len = u16::from_be_bytes([l3_slice[2], l3_slice[3]]) as usize;
            if ihl < 20 || ihl > l3_slice.len() || total_len < ihl {
                return Err(SpecterError::InvalidPacket(
                    "Invalid IPv4 IHL or total length".into(),
                ));
            }
            let clamped_end = total_len.min(l3_slice.len());
            let ttl = l3_slice[8];
            let proto = l3_slice[9];
            let df = (l3_slice[6] & 0x40) != 0;
            let src =
                Ipv4Addr::new(l3_slice[12], l3_slice[13], l3_slice[14], l3_slice[15]).to_string();
            let dst =
                Ipv4Addr::new(l3_slice[16], l3_slice[17], l3_slice[18], l3_slice[19]).to_string();
            (src, dst, ttl, proto, Some(df), &l3_slice[ihl..clamped_end])
        }
        6 => {
            if l3_slice.len() < 40 {
                return Err(SpecterError::InvalidPacket(
                    "IPv6 header shorter than 40 bytes".into(),
                ));
            }
            let payload_len = u16::from_be_bytes([l3_slice[4], l3_slice[5]]) as usize;
            let next_header = l3_slice[6];
            let hop_limit = l3_slice[7];
            let mut src_octets = [0u8; 16];
            let mut dst_octets = [0u8; 16];
            src_octets.copy_from_slice(&l3_slice[8..24]);
            dst_octets.copy_from_slice(&l3_slice[24..40]);
            let src = Ipv6Addr::from(src_octets).to_string();
            let dst = Ipv6Addr::from(dst_octets).to_string();
            let end = (40 + payload_len).min(l3_slice.len());
            (src, dst, hop_limit, next_header, None, &l3_slice[40..end])
        }
        other => {
            return Err(SpecterError::InvalidPacket(format!(
                "Unsupported IP version {other}"
            )))
        }
    };

    match proto_num {
        6 => {
            if l4_slice.len() < 20 {
                return Err(SpecterError::InvalidPacket(
                    "TCP segment shorter than 20-byte header".into(),
                ));
            }
            let src_port = u16::from_be_bytes([l4_slice[0], l4_slice[1]]);
            let dst_port = u16::from_be_bytes([l4_slice[2], l4_slice[3]]);
            let seq = u32::from_be_bytes([l4_slice[4], l4_slice[5], l4_slice[6], l4_slice[7]]);
            let ack = u32::from_be_bytes([l4_slice[8], l4_slice[9], l4_slice[10], l4_slice[11]]);
            let data_offset = ((l4_slice[12] >> 4) as usize) * 4;
            if data_offset < 20 || data_offset > l4_slice.len() {
                return Err(SpecterError::InvalidPacket(
                    "Invalid TCP data offset".into(),
                ));
            }
            let flags_byte = l4_slice[13];
            let flags = TcpFlags {
                fin: (flags_byte & 0x01) != 0,
                syn: (flags_byte & 0x02) != 0,
                rst: (flags_byte & 0x04) != 0,
                psh: (flags_byte & 0x08) != 0,
                ack: (flags_byte & 0x10) != 0,
            };
            let tcp_window = u16::from_be_bytes([l4_slice[14], l4_slice[15]]);
            let tcp_options = l4_slice[20..data_offset].to_vec();
            Ok(DecodedFrame {
                index,
                ts_sec,
                ts_subsec,
                orig_len,
                src_ip,
                dst_ip,
                ip_version,
                ttl,
                protocol: "TCP".into(),
                src_port,
                dst_port,
                tcp_seq: Some(seq),
                tcp_ack: Some(ack),
                tcp_flags: Some(flags),
                tcp_window: Some(tcp_window),
                tcp_options: Some(tcp_options),
                ip_df,
                src_mac,
                dst_mac,
                payload: l4_slice[data_offset..].to_vec(),
            })
        }
        17 => {
            if l4_slice.len() < 8 {
                return Err(SpecterError::InvalidPacket(
                    "UDP datagram shorter than 8-byte header".into(),
                ));
            }
            let src_port = u16::from_be_bytes([l4_slice[0], l4_slice[1]]);
            let dst_port = u16::from_be_bytes([l4_slice[2], l4_slice[3]]);
            let udp_len = u16::from_be_bytes([l4_slice[4], l4_slice[5]]) as usize;
            let end = udp_len.clamp(8, l4_slice.len());
            Ok(DecodedFrame {
                index,
                ts_sec,
                ts_subsec,
                orig_len,
                src_ip,
                dst_ip,
                ip_version,
                ttl,
                protocol: "UDP".into(),
                src_port,
                dst_port,
                tcp_seq: None,
                tcp_ack: None,
                tcp_flags: None,
                tcp_window: None,
                tcp_options: None,
                ip_df,
                src_mac,
                dst_mac,
                payload: l4_slice[8..end].to_vec(),
            })
        }
        1 => Ok(DecodedFrame {
            index,
            ts_sec,
            ts_subsec,
            orig_len,
            src_ip,
            dst_ip,
            ip_version,
            ttl,
            protocol: "ICMP".into(),
            src_port: 0,
            dst_port: 0,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            tcp_window: None,
            tcp_options: None,
            ip_df,
            src_mac,
            dst_mac,
            payload: l4_slice.to_vec(),
        }),
        58 => Ok(DecodedFrame {
            index,
            ts_sec,
            ts_subsec,
            orig_len,
            src_ip,
            dst_ip,
            ip_version,
            ttl,
            protocol: "ICMPv6".into(),
            src_port: 0,
            dst_port: 0,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            tcp_window: None,
            tcp_options: None,
            ip_df,
            src_mac,
            dst_mac,
            payload: l4_slice.to_vec(),
        }),
        other => Ok(DecodedFrame {
            index,
            ts_sec,
            ts_subsec,
            orig_len,
            src_ip,
            dst_ip,
            ip_version,
            ttl,
            protocol: format!("IP_{other}"),
            src_port: 0,
            dst_port: 0,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            tcp_window: None,
            tcp_options: None,
            ip_df,
            src_mac,
            dst_mac,
            payload: l4_slice.to_vec(),
        }),
    }
}

fn wrap_ipv4_ethernet(src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8, l4_bytes: &[u8]) -> Vec<u8> {
    let total_ip_len = (20 + l4_bytes.len()) as u16;
    let mut frame = Vec::with_capacity(14 + total_ip_len as usize);
    // Ethernet II header (dst MAC, src MAC, EtherType 0x0800)
    frame.extend_from_slice(&[0x00, 0x16, 0x3e, 0x10, 0x20, 0x30]);
    frame.extend_from_slice(&[0x00, 0x16, 0x3e, 0xaa, 0xbb, 0xcc]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());

    // IPv4 header (20 bytes)
    frame.push(0x45); // Version 4, IHL 5
    frame.push(0x00); // DSCP/ECN
    frame.extend_from_slice(&total_ip_len.to_be_bytes());
    frame.extend_from_slice(&0x1337u16.to_be_bytes()); // Identification
    frame.extend_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    frame.push(64); // TTL
    frame.push(proto);
    frame.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);
    frame.extend_from_slice(l4_bytes);
    frame
}

/// Generates the standard test frames containing:
/// 1. A TCP TLS 1.3 `ClientHello` handshake packet to `api.telemetry.example.org:443`.
/// 2. A benign UDP DNS `A` query for `api.telemetry.example.org`.
/// 3. A suspicious high-entropy UDP DNS `TXT` query exhibiting covert tunneling traits.
pub fn synthetic_test_packets() -> Vec<Vec<u8>> {
    let tls_payload = build_sample_client_hello("api.telemetry.example.org");
    let mut tcp_seg = Vec::with_capacity(20 + tls_payload.len());
    tcp_seg.extend_from_slice(&51422u16.to_be_bytes()); // src port
    tcp_seg.extend_from_slice(&443u16.to_be_bytes()); // dst port
    tcp_seg.extend_from_slice(&1001u32.to_be_bytes()); // seq
    tcp_seg.extend_from_slice(&2001u32.to_be_bytes()); // ack
    tcp_seg.push(0x50); // data offset = 5 (20 bytes)
    tcp_seg.push(0x18); // PSH | ACK
    tcp_seg.extend_from_slice(&65535u16.to_be_bytes()); // window
    tcp_seg.extend_from_slice(&0u16.to_be_bytes()); // checksum
    tcp_seg.extend_from_slice(&0u16.to_be_bytes()); // urgent ptr
    tcp_seg.extend_from_slice(&tls_payload);
    let pkt1 = wrap_ipv4_ethernet([10, 0, 0, 15], [93, 184, 216, 34], 6, &tcp_seg);

    let dns_normal = build_dns_query_packet(0x1001, "api.telemetry.example.org", 1);
    let mut udp1 = Vec::with_capacity(8 + dns_normal.len());
    udp1.extend_from_slice(&54111u16.to_be_bytes());
    udp1.extend_from_slice(&53u16.to_be_bytes());
    udp1.extend_from_slice(&((8 + dns_normal.len()) as u16).to_be_bytes());
    udp1.extend_from_slice(&0u16.to_be_bytes());
    udp1.extend_from_slice(&dns_normal);
    let pkt2 = wrap_ipv4_ethernet([10, 0, 0, 15], [8, 8, 8, 8], 17, &udp1);

    let covert_qname =
        "9f4b2c8e1a7d3f6b0c5e9a2d4f8b1c7e3a6d0f9b2c4e8a1d.stage2.tunnel-relay.example.net";
    let dns_covert = build_dns_query_packet(0x2002, covert_qname, 16); // TXT (16)
    let mut udp2 = Vec::with_capacity(8 + dns_covert.len());
    udp2.extend_from_slice(&54112u16.to_be_bytes());
    udp2.extend_from_slice(&53u16.to_be_bytes());
    udp2.extend_from_slice(&((8 + dns_covert.len()) as u16).to_be_bytes());
    udp2.extend_from_slice(&0u16.to_be_bytes());
    udp2.extend_from_slice(&dns_covert);
    let pkt3 = wrap_ipv4_ethernet([10, 0, 0, 15], [8, 8, 4, 4], 17, &udp2);

    vec![pkt1, pkt2, pkt3]
}

/// Generates a deterministic multi-packet `.pcap` capture containing:
/// 1. A TCP TLS 1.3 `ClientHello` handshake packet to `api.telemetry.example.org:443`.
/// 2. A benign UDP DNS `A` query for `api.telemetry.example.org`.
/// 3. A suspicious high-entropy UDP DNS `TXT` query exhibiting covert tunneling traits.
pub fn build_synthetic_pcap() -> Vec<u8> {
    let packets = synthetic_test_packets();
    let mut pcap = Vec::with_capacity(512);
    pcap.extend_from_slice(&PCAP_MAGIC_USEC_LE.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());

    for (idx, frame) in packets.iter().enumerate() {
        let ts_sec = 1_700_000_000u32 + (idx as u32);
        let ts_usec = (idx as u32) * 125_000;
        let len = frame.len() as u32;
        pcap.extend_from_slice(&ts_sec.to_le_bytes());
        pcap.extend_from_slice(&ts_usec.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(frame);
    }
    pcap
}
