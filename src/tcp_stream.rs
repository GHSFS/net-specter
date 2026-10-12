// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Bidirectional TCP stream reassembly, sequence number tracking,
//! out-of-order segment buffering, retransmission deduplication, and
//! multi-segment application protocol (TLS JA3/JA4, HTTP) inspection.

use crate::error::{Result, SpecterError};
use crate::ja4::{compute_ja4_client, Ja4ClientReport, TransportProtocol};
use crate::pcap::{parse_pcap_bytes, DecodedFrame, TcpFlags};
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use crate::tls_ja3::{parse_tls_client_hello, TlsClientHelloReport};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use zeroize::Zeroize;

/// Default maximum memory in bytes allowed for out-of-order buffering per stream half.
pub const DEFAULT_MAX_OUT_OF_ORDER_BUFFER: usize = 10 * 1024 * 1024; // 10 MB

/// Signed sequence comparison modulo 2^32 as defined in RFC 793.
#[inline]
pub fn seq_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

/// Unidirectional half of a bidirectional TCP stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamHalf {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub syn_seen: bool,
    pub syn_seq: Option<u32>,
    pub fin_seen: bool,
    pub fin_seq: Option<u32>,
    pub rst_seen: bool,
    pub expected_seq: u32,
    pub has_started: bool,
    pub packets_count: usize,
    pub payload_bytes_total: usize,
    pub retransmitted_packets: usize,
    pub retransmitted_bytes: usize,
    pub out_of_order_packets: usize,
    #[serde(skip_serializing)]
    pub reassembled_data: Vec<u8>,
    #[serde(skip_serializing)]
    pub out_of_order_buffer: BTreeMap<u32, Vec<u8>>,
    #[serde(skip_serializing)]
    pub max_buffer_bytes: usize,
    #[serde(skip_serializing)]
    pub current_buffer_bytes: usize,
}

impl StreamHalf {
    pub fn new(
        src_ip: String,
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
        max_buf: usize,
    ) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            syn_seen: false,
            syn_seq: None,
            fin_seen: false,
            fin_seq: None,
            rst_seen: false,
            expected_seq: 0,
            has_started: false,
            packets_count: 0,
            payload_bytes_total: 0,
            retransmitted_packets: 0,
            retransmitted_bytes: 0,
            out_of_order_packets: 0,
            reassembled_data: Vec::new(),
            out_of_order_buffer: BTreeMap::new(),
            max_buffer_bytes: max_buf,
            current_buffer_bytes: 0,
        }
    }

    /// Process an inbound TCP segment on this stream direction.
    pub fn process_segment(&mut self, seq: u32, flags: TcpFlags, payload: &[u8]) {
        self.packets_count += 1;

        if flags.rst {
            self.rst_seen = true;
        }

        if flags.syn {
            self.syn_seen = true;
            self.syn_seq = Some(seq);
            self.expected_seq = seq.wrapping_add(1);
            self.has_started = true;
        }

        if !self.has_started {
            self.has_started = true;
            self.expected_seq = seq;
        }

        if payload.is_empty() {
            if flags.fin {
                self.fin_seen = true;
                self.fin_seq = Some(seq);
            }
            return;
        }

        let len = payload.len() as u32;
        let diff = seq_diff(seq, self.expected_seq);

        if diff < 0 {
            // Segment starts before expected_seq
            let end_seq = seq.wrapping_add(len);
            let end_diff = seq_diff(end_seq, self.expected_seq);
            if end_diff <= 0 {
                // Completely duplicate / retransmitted segment
                self.retransmitted_packets += 1;
                self.retransmitted_bytes += payload.len();
            } else {
                // Partial overlap
                let overlap = self.expected_seq.wrapping_sub(seq) as usize;
                self.retransmitted_packets += 1;
                self.retransmitted_bytes += overlap;
                let new_slice = &payload[overlap..];
                self.reassembled_data.extend_from_slice(new_slice);
                self.expected_seq = self.expected_seq.wrapping_add(new_slice.len() as u32);
                self.payload_bytes_total += new_slice.len();
                self.drain_out_of_order_buffer();
            }
        } else if diff == 0 {
            // Strictly in-order segment
            self.reassembled_data.extend_from_slice(payload);
            self.expected_seq = self.expected_seq.wrapping_add(len);
            self.payload_bytes_total += payload.len();
            self.drain_out_of_order_buffer();
        } else {
            // Out-of-order segment (gap detected)
            self.out_of_order_packets += 1;
            if self.current_buffer_bytes + payload.len() <= self.max_buffer_bytes {
                let existing = self
                    .out_of_order_buffer
                    .get(&seq)
                    .map(|v| v.len())
                    .unwrap_or(0);
                if payload.len() > existing {
                    self.current_buffer_bytes = self.current_buffer_bytes.saturating_sub(existing);
                    self.current_buffer_bytes += payload.len();
                    self.out_of_order_buffer.insert(seq, payload.to_vec());
                }
            }
        }

        if flags.fin {
            self.fin_seen = true;
            self.fin_seq = Some(seq.wrapping_add(len));
        }
    }

    /// Drains any contiguous segments queued in the out-of-order buffer.
    fn drain_out_of_order_buffer(&mut self) {
        while let Some(&next_key) = self.out_of_order_buffer.keys().next() {
            let diff = seq_diff(next_key, self.expected_seq);
            if diff <= 0 {
                let seg = self.out_of_order_buffer.remove(&next_key).unwrap();
                self.current_buffer_bytes = self.current_buffer_bytes.saturating_sub(seg.len());
                let end_seq = next_key.wrapping_add(seg.len() as u32);
                if seq_diff(end_seq, self.expected_seq) > 0 {
                    let overlap = self.expected_seq.wrapping_sub(next_key) as usize;
                    if overlap < seg.len() {
                        let new_slice = &seg[overlap..];
                        self.reassembled_data.extend_from_slice(new_slice);
                        self.expected_seq = self.expected_seq.wrapping_add(new_slice.len() as u32);
                        self.payload_bytes_total += new_slice.len();
                    }
                }
            } else {
                break;
            }
        }
    }
}

/// Canonical 4-tuple conversation key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConversationKey {
    pub ep_low: (String, u16),
    pub ep_high: (String, u16),
}

impl ConversationKey {
    pub fn new(ip_a: &str, port_a: u16, ip_b: &str, port_b: u16) -> Self {
        let a = (ip_a.to_string(), port_a);
        let b = (ip_b.to_string(), port_b);
        if a <= b {
            Self {
                ep_low: a,
                ep_high: b,
            }
        } else {
            Self {
                ep_low: b,
                ep_high: a,
            }
        }
    }
}

/// Bidirectional stateful TCP conversation.
#[derive(Debug, Clone)]
pub struct TcpConversation {
    pub stream_id: usize,
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub client_to_server: StreamHalf,
    pub server_to_client: StreamHalf,
    pub first_ts: (u32, u32),
    pub last_ts: (u32, u32),
}

impl TcpConversation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stream_id: usize,
        client_ip: String,
        client_port: u16,
        server_ip: String,
        server_port: u16,
        max_buf: usize,
        ts_sec: u32,
        ts_subsec: u32,
    ) -> Self {
        let c2s = StreamHalf::new(
            client_ip.clone(),
            client_port,
            server_ip.clone(),
            server_port,
            max_buf,
        );
        let s2c = StreamHalf::new(
            server_ip.clone(),
            server_port,
            client_ip.clone(),
            client_port,
            max_buf,
        );
        Self {
            stream_id,
            client_ip,
            client_port,
            server_ip,
            server_port,
            client_to_server: c2s,
            server_to_client: s2c,
            first_ts: (ts_sec, ts_subsec),
            last_ts: (ts_sec, ts_subsec),
        }
    }

    pub fn process_frame(&mut self, frame: &DecodedFrame) {
        self.last_ts = (frame.ts_sec, frame.ts_subsec);
        let seq = frame.tcp_seq.unwrap_or(0);
        let flags = frame.tcp_flags.unwrap_or(TcpFlags {
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: false,
        });

        if frame.src_ip == self.client_ip && frame.src_port == self.client_port {
            self.client_to_server
                .process_segment(seq, flags, &frame.payload);
        } else {
            self.server_to_client
                .process_segment(seq, flags, &frame.payload);
        }
    }
}

/// Report summarizing reassembly status, statistics, and L7 discoveries for a TCP stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpStreamReport {
    pub stream_id: usize,
    pub client: String,
    pub server: String,
    pub duration_ms: f64,
    pub client_packets: usize,
    pub server_packets: usize,
    pub client_payload_bytes: usize,
    pub server_payload_bytes: usize,
    pub client_retransmissions: usize,
    pub client_retransmitted_bytes: usize,
    pub server_retransmissions: usize,
    pub server_retransmitted_bytes: usize,
    pub client_out_of_order: usize,
    pub server_out_of_order: usize,
    pub syn_seen: bool,
    pub fin_seen: bool,
    pub rst_seen: bool,
    pub handshake_complete: bool,
    pub detected_protocols: Vec<String>,
    pub ja3: Option<TlsClientHelloReport>,
    pub ja4: Option<Ja4ClientReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_payload_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_payload_hex: Option<String>,
}

/// Stateful engine for reassembling multiple concurrent TCP streams.
#[derive(Debug)]
pub struct TcpReassembler {
    pub max_buffer_bytes: usize,
    conversations: HashMap<ConversationKey, TcpConversation>,
    ordered_keys: Vec<ConversationKey>,
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_OUT_OF_ORDER_BUFFER)
    }
}

impl TcpReassembler {
    pub fn new(max_buffer_bytes: usize) -> Self {
        Self {
            max_buffer_bytes,
            conversations: HashMap::new(),
            ordered_keys: Vec::new(),
        }
    }

    /// Process a decoded frame and feed its TCP segment into the active stream.
    pub fn process_frame(&mut self, frame: &DecodedFrame) {
        if frame.protocol != "TCP" || frame.tcp_seq.is_none() {
            return;
        }

        let key =
            ConversationKey::new(&frame.src_ip, frame.src_port, &frame.dst_ip, frame.dst_port);

        if !self.conversations.contains_key(&key) {
            let stream_id = self.ordered_keys.len();
            // Client is assumed to be the sender of the first frame or SYN
            let conv = TcpConversation::new(
                stream_id,
                frame.src_ip.clone(),
                frame.src_port,
                frame.dst_ip.clone(),
                frame.dst_port,
                self.max_buffer_bytes,
                frame.ts_sec,
                frame.ts_subsec,
            );
            self.conversations.insert(key.clone(), conv);
            self.ordered_keys.push(key.clone());
        }

        if let Some(conv) = self.conversations.get_mut(&key) {
            conv.process_frame(frame);
        }
    }

    /// Finish reassembly and generate structured stream reports.
    pub fn finish(mut self, dump_payload: bool) -> Vec<TcpStreamReport> {
        let mut reports = Vec::with_capacity(self.ordered_keys.len());

        for key in &self.ordered_keys {
            if let Some(mut conv) = self.conversations.remove(key) {
                let start_sec = conv.first_ts.0 as f64 + (conv.first_ts.1 as f64 / 1_000_000_000.0);
                let end_sec = conv.last_ts.0 as f64 + (conv.last_ts.1 as f64 / 1_000_000_000.0);
                let duration_ms = ((end_sec - start_sec).max(0.0)) * 1000.0;

                let syn_seen = conv.client_to_server.syn_seen || conv.server_to_client.syn_seen;
                let fin_seen = conv.client_to_server.fin_seen || conv.server_to_client.fin_seen;
                let rst_seen = conv.client_to_server.rst_seen || conv.server_to_client.rst_seen;
                let handshake_complete =
                    conv.client_to_server.syn_seen && conv.server_to_client.syn_seen;

                let mut detected_protocols = Vec::new();
                let client_bytes = &conv.client_to_server.reassembled_data;
                let server_bytes = &conv.server_to_client.reassembled_data;

                // Inspect TLS from reassembled client stream
                let mut ja3 = None;
                let mut ja4 = None;
                if client_bytes.len() >= 5 && client_bytes[0] == 0x16 {
                    detected_protocols.push("TLS".into());
                    if let Ok(report) = parse_tls_client_hello(client_bytes) {
                        ja3 = Some(report);
                    }
                    if let Ok(ja4_rep) = compute_ja4_client(client_bytes, TransportProtocol::Tcp) {
                        ja4 = Some(ja4_rep);
                    }
                }

                // Inspect HTTP/1.x
                if is_http_request(client_bytes) || is_http_response(server_bytes) {
                    detected_protocols.push("HTTP/1.1".into());
                }

                // Inspect HTTP/2
                if client_bytes.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
                    detected_protocols.push("HTTP/2".into());
                }

                // Inspect SSH
                if client_bytes.starts_with(b"SSH-") || server_bytes.starts_with(b"SSH-") {
                    detected_protocols.push("SSH".into());
                }

                let client_payload_hex = if dump_payload && !client_bytes.is_empty() {
                    Some(hex::encode(client_bytes))
                } else {
                    None
                };

                let server_payload_hex = if dump_payload && !server_bytes.is_empty() {
                    Some(hex::encode(server_bytes))
                } else {
                    None
                };

                let report = TcpStreamReport {
                    stream_id: conv.stream_id,
                    client: format!("{}:{}", conv.client_ip, conv.client_port),
                    server: format!("{}:{}", conv.server_ip, conv.server_port),
                    duration_ms,
                    client_packets: conv.client_to_server.packets_count,
                    server_packets: conv.server_to_client.packets_count,
                    client_payload_bytes: conv.client_to_server.payload_bytes_total,
                    server_payload_bytes: conv.server_to_client.payload_bytes_total,
                    client_retransmissions: conv.client_to_server.retransmitted_packets,
                    client_retransmitted_bytes: conv.client_to_server.retransmitted_bytes,
                    server_retransmissions: conv.server_to_client.retransmitted_packets,
                    server_retransmitted_bytes: conv.server_to_client.retransmitted_bytes,
                    client_out_of_order: conv.client_to_server.out_of_order_packets,
                    server_out_of_order: conv.server_to_client.out_of_order_packets,
                    syn_seen,
                    fin_seen,
                    rst_seen,
                    handshake_complete,
                    detected_protocols,
                    ja3,
                    ja4,
                    client_payload_hex,
                    server_payload_hex,
                };

                // Zeroize transient reassembly buffers for memory wiping hygiene
                conv.client_to_server.reassembled_data.zeroize();
                conv.server_to_client.reassembled_data.zeroize();

                reports.push(report);
            }
        }

        reports
    }
}

/// Helper function to check if bytes resemble an HTTP/1.x request line.
fn is_http_request(bytes: &[u8]) -> bool {
    let prefixes: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"CONNECT ",
        b"PATCH ",
    ];
    prefixes.iter().any(|&p| bytes.starts_with(p))
}

/// Helper function to check if bytes resemble an HTTP/1.x response status line.
fn is_http_response(bytes: &[u8]) -> bool {
    bytes.starts_with(b"HTTP/1.")
}

/// Reassembles all TCP streams from a slice of decoded frames.
pub fn reassemble_frames(frames: &[DecodedFrame], dump_payload: bool) -> Vec<TcpStreamReport> {
    let mut reassembler = TcpReassembler::default();
    for f in frames {
        reassembler.process_frame(f);
    }
    reassembler.finish(dump_payload)
}

/// Reassembles all TCP streams from a raw `.pcap` or `.pcapng` byte slice.
pub fn reassemble_capture_bytes(bytes: &[u8], dump_payload: bool) -> Result<Vec<TcpStreamReport>> {
    let frames = if is_pcapng(bytes) {
        let rep = parse_pcapng_bytes(bytes)?;
        rep.frames
    } else {
        let rep = parse_pcap_bytes(bytes)?;
        rep.frames
    };

    if frames.is_empty() {
        return Err(SpecterError::InvalidPacket(
            "Capture contains no decoded packets".into(),
        ));
    }

    Ok(reassemble_frames(&frames, dump_payload))
}
