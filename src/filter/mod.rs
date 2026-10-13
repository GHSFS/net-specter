// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

mod parser;

use crate::error::Result;
use crate::pcap::{parse_pcap_bytes, DecodedFrame, TcpFlags};
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;
pub const TCP_FLAG_ECE: u8 = 0x40;
pub const TCP_FLAG_CWR: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Src,
    Dst,
    SrcOrDst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpNetwork {
    V4 { net: Ipv4Addr, prefix: u8 },
    V6 { net: Ipv6Addr, prefix: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpMatch {
    pub direction: Direction,
    pub network: IpNetwork,
}

impl IpMatch {
    pub fn matches_frame_ip(&self, frame: &DecodedFrame) -> bool {
        let src_matches = match &self.network {
            IpNetwork::V4 { net, prefix } => frame
                .src_ip
                .parse::<Ipv4Addr>()
                .map(|ip| matches_ipv4(ip, *net, *prefix))
                .unwrap_or(false),
            IpNetwork::V6 { net, prefix } => frame
                .src_ip
                .parse::<Ipv6Addr>()
                .map(|ip| matches_ipv6(ip, *net, *prefix))
                .unwrap_or(false),
        };

        let dst_matches = match &self.network {
            IpNetwork::V4 { net, prefix } => frame
                .dst_ip
                .parse::<Ipv4Addr>()
                .map(|ip| matches_ipv4(ip, *net, *prefix))
                .unwrap_or(false),
            IpNetwork::V6 { net, prefix } => frame
                .dst_ip
                .parse::<Ipv6Addr>()
                .map(|ip| matches_ipv6(ip, *net, *prefix))
                .unwrap_or(false),
        };

        match self.direction {
            Direction::Src => src_matches,
            Direction::Dst => dst_matches,
            Direction::SrcOrDst => src_matches || dst_matches,
        }
    }
}

fn matches_ipv4(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let ip_u32 = u32::from(ip);
    let net_u32 = u32::from(net);
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    (ip_u32 & mask) == (net_u32 & mask)
}

fn matches_ipv6(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let ip_u128 = u128::from(ip);
    let net_u128 = u128::from(net);
    let mask = if prefix == 128 {
        u128::MAX
    } else {
        !((1u128 << (128 - prefix)) - 1)
    };
    (ip_u128 & mask) == (net_u128 & mask)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMatch {
    pub direction: Direction,
    pub start: u16,
    pub end: u16,
}

impl PortMatch {
    pub fn matches_frame_port(&self, frame: &DecodedFrame) -> bool {
        let src_matches = frame.src_port >= self.start && frame.src_port <= self.end;
        let dst_matches = frame.dst_port >= self.start && frame.dst_port <= self.end;
        match self.direction {
            Direction::Src => src_matches,
            Direction::Dst => dst_matches,
            Direction::SrcOrDst => src_matches || dst_matches,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpFlagComparison {
    NonZero,
    AllSet,
    Zero,
    Exact(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFlagMatch {
    pub mask: u8,
    pub comparison: TcpFlagComparison,
}

impl TcpFlagMatch {
    pub fn matches_flags(&self, flags: &TcpFlags) -> bool {
        let mut b = 0u8;
        if flags.fin {
            b |= TCP_FLAG_FIN;
        }
        if flags.syn {
            b |= TCP_FLAG_SYN;
        }
        if flags.rst {
            b |= TCP_FLAG_RST;
        }
        if flags.psh {
            b |= TCP_FLAG_PSH;
        }
        if flags.ack {
            b |= TCP_FLAG_ACK;
        }

        match self.comparison {
            TcpFlagComparison::NonZero => (b & self.mask) != 0,
            TcpFlagComparison::AllSet => (b & self.mask) == self.mask,
            TcpFlagComparison::Zero => (b & self.mask) == 0,
            TcpFlagComparison::Exact(expected) => (b & self.mask) == expected,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LenOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LenMatch {
    pub op: LenOp,
    pub value: u32,
}

impl LenMatch {
    pub fn matches_frame_len(&self, frame: &DecodedFrame) -> bool {
        let len = frame.orig_len;
        match self.op {
            LenOp::Eq => len == self.value,
            LenOp::Ne => len != self.value,
            LenOp::Lt => len < self.value,
            LenOp::Le => len <= self.value,
            LenOp::Gt => len > self.value,
            LenOp::Ge => len >= self.value,
        }
    }
}

/// Abstract syntax tree representing a compiled BPF-style packet filter expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterExpr {
    True,
    False,
    Protocol(Protocol),
    Ip(IpMatch),
    Port(PortMatch),
    TcpFlag(TcpFlagMatch),
    Length(LenMatch),
    Not(Box<FilterExpr>),
    And(Vec<FilterExpr>),
    Or(Vec<FilterExpr>),
}

impl FilterExpr {
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(Self::True);
        }
        parser::parse_filter_expr(trimmed)
    }

    pub fn matches(&self, frame: &DecodedFrame) -> bool {
        match self {
            Self::True => true,
            Self::False => false,
            Self::Protocol(proto) => match proto {
                Protocol::Tcp => frame.protocol.eq_ignore_ascii_case("TCP"),
                Protocol::Udp => frame.protocol.eq_ignore_ascii_case("UDP"),
                Protocol::Icmp => {
                    frame.protocol.eq_ignore_ascii_case("ICMP")
                        || frame.protocol.eq_ignore_ascii_case("ICMPv6")
                }
                Protocol::Ipv4 => frame.ip_version == 4,
                Protocol::Ipv6 => frame.ip_version == 6,
            },
            Self::Ip(ip_match) => ip_match.matches_frame_ip(frame),
            Self::Port(port_match) => port_match.matches_frame_port(frame),
            Self::TcpFlag(flag_match) => {
                if let Some(ref flags) = frame.tcp_flags {
                    flag_match.matches_flags(flags)
                } else {
                    false
                }
            }
            Self::Length(len_match) => len_match.matches_frame_len(frame),
            Self::Not(inner) => !inner.matches(frame),
            Self::And(exprs) => exprs.iter().all(|e| e.matches(frame)),
            Self::Or(exprs) => exprs.iter().any(|e| e.matches(frame)),
        }
    }

    pub fn filter_frames<'a>(&self, frames: &'a [DecodedFrame]) -> Vec<&'a DecodedFrame> {
        frames.iter().filter(|f| self.matches(f)).collect()
    }
}

impl fmt::Display for FilterExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::True => write!(f, "true"),
            Self::False => write!(f, "false"),
            Self::Protocol(proto) => match proto {
                Protocol::Tcp => write!(f, "tcp"),
                Protocol::Udp => write!(f, "udp"),
                Protocol::Icmp => write!(f, "icmp"),
                Protocol::Ipv4 => write!(f, "ip"),
                Protocol::Ipv6 => write!(f, "ip6"),
            },
            Self::Ip(m) => {
                let dir_str = match m.direction {
                    Direction::Src => "src ",
                    Direction::Dst => "dst ",
                    Direction::SrcOrDst => "",
                };
                match &m.network {
                    IpNetwork::V4 { net, prefix } => {
                        if *prefix == 32 {
                            write!(f, "{dir_str}host {net}")
                        } else {
                            write!(f, "{dir_str}net {net}/{prefix}")
                        }
                    }
                    IpNetwork::V6 { net, prefix } => {
                        if *prefix == 128 {
                            write!(f, "{dir_str}host {net}")
                        } else {
                            write!(f, "{dir_str}net {net}/{prefix}")
                        }
                    }
                }
            }
            Self::Port(m) => {
                let dir_str = match m.direction {
                    Direction::Src => "src ",
                    Direction::Dst => "dst ",
                    Direction::SrcOrDst => "",
                };
                if m.start == m.end {
                    write!(f, "{dir_str}port {}", m.start)
                } else {
                    write!(f, "{dir_str}portrange {}-{}", m.start, m.end)
                }
            }
            Self::TcpFlag(m) => match m.comparison {
                TcpFlagComparison::NonZero => write!(f, "tcp[tcpflags] & 0x{:02x} != 0", m.mask),
                TcpFlagComparison::AllSet => {
                    write!(f, "tcp[tcpflags] & 0x{:02x} == 0x{:02x}", m.mask, m.mask)
                }
                TcpFlagComparison::Zero => write!(f, "tcp[tcpflags] & 0x{:02x} == 0", m.mask),
                TcpFlagComparison::Exact(v) => {
                    write!(f, "tcp[tcpflags] & 0x{:02x} == 0x{:02x}", m.mask, v)
                }
            },
            Self::Length(m) => {
                let op_str = match m.op {
                    LenOp::Eq => "==",
                    LenOp::Ne => "!=",
                    LenOp::Lt => "<",
                    LenOp::Le => "<=",
                    LenOp::Gt => ">",
                    LenOp::Ge => ">=",
                };
                write!(f, "len {op_str} {}", m.value)
            }
            Self::Not(inner) => write!(f, "not ({inner})"),
            Self::And(items) => {
                let parts: Vec<String> = items.iter().map(|i| i.to_string()).collect();
                write!(f, "({})", parts.join(" and "))
            }
            Self::Or(items) => {
                let parts: Vec<String> = items.iter().map(|i| i.to_string()).collect();
                write!(f, "({})", parts.join(" or "))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterReport {
    pub filter_expression: String,
    pub canonical_expression: String,
    pub total_input_packets: usize,
    pub matched_packets: usize,
    pub tcp_matched: usize,
    pub udp_matched: usize,
    pub other_matched: usize,
    pub frames: Vec<DecodedFrame>,
}

pub fn evaluate_filter_on_capture(capture_bytes: &[u8], expr_str: &str) -> Result<FilterReport> {
    let filter = FilterExpr::parse(expr_str)?;
    let frames = if is_pcapng(capture_bytes) {
        let pcapng = parse_pcapng_bytes(capture_bytes)?;
        pcapng.frames
    } else {
        let pcap = parse_pcap_bytes(capture_bytes)?;
        pcap.frames
    };

    let total_input_packets = frames.len();
    let mut matched_frames = Vec::new();
    let mut tcp_matched = 0;
    let mut udp_matched = 0;
    let mut other_matched = 0;

    for frame in frames {
        if filter.matches(&frame) {
            if frame.protocol.eq_ignore_ascii_case("TCP") {
                tcp_matched += 1;
            } else if frame.protocol.eq_ignore_ascii_case("UDP") {
                udp_matched += 1;
            } else {
                other_matched += 1;
            }
            matched_frames.push(frame);
        }
    }

    Ok(FilterReport {
        filter_expression: expr_str.to_string(),
        canonical_expression: filter.to_string(),
        total_input_packets,
        matched_packets: matched_frames.len(),
        tcp_matched,
        udp_matched,
        other_matched,
        frames: matched_frames,
    })
}
