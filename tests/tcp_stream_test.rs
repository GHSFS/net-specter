// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use net_specter::pcap::{build_synthetic_pcap, DecodedFrame, TcpFlags};
use net_specter::pcapng::build_synthetic_pcapng;
use net_specter::tcp_stream::{reassemble_capture_bytes, reassemble_frames, StreamHalf};
use net_specter::tls_ja3::build_sample_client_hello;
use std::fs;
use std::process::Command;

#[allow(clippy::too_many_arguments)]
fn make_tcp_frame(
    index: usize,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    payload: &[u8],
) -> DecodedFrame {
    DecodedFrame {
        index,
        ts_sec: 1700000000 + index as u32,
        ts_subsec: 100_000,
        orig_len: (40 + payload.len()) as u32,
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        ip_version: 4,
        ttl: 64,
        protocol: "TCP".to_string(),
        src_port,
        dst_port,
        tcp_seq: Some(seq),
        tcp_ack: Some(ack),
        tcp_flags: Some(flags),
        payload: payload.to_vec(),
    }
}

#[test]
fn test_in_order_tcp_reassembly_and_http_detection() {
    let syn = TcpFlags {
        syn: true,
        ack: false,
        fin: false,
        rst: false,
        psh: false,
    };
    let syn_ack = TcpFlags {
        syn: true,
        ack: true,
        fin: false,
        rst: false,
        psh: false,
    };
    let ack = TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: false,
    };
    let psh_ack = TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: true,
    };
    let fin_ack = TcpFlags {
        syn: false,
        ack: true,
        fin: true,
        rst: false,
        psh: false,
    };

    let f1 = make_tcp_frame(1, "192.168.1.50", 49152, "10.0.0.1", 80, 1000, 0, syn, b"");
    let f2 = make_tcp_frame(
        2,
        "10.0.0.1",
        80,
        "192.168.1.50",
        49152,
        5000,
        1001,
        syn_ack,
        b"",
    );
    let f3 = make_tcp_frame(
        3,
        "192.168.1.50",
        49152,
        "10.0.0.1",
        80,
        1001,
        5001,
        ack,
        b"",
    );

    let req_part1 = b"GET /api/v1/status HTTP/1.1\r\n";
    let req_part2 = b"Host: 10.0.0.1\r\nConnection: close\r\n\r\n";
    let f4 = make_tcp_frame(
        4,
        "192.168.1.50",
        49152,
        "10.0.0.1",
        80,
        1001,
        5001,
        psh_ack,
        req_part1,
    );
    let f5 = make_tcp_frame(
        5,
        "192.168.1.50",
        49152,
        "10.0.0.1",
        80,
        1001 + req_part1.len() as u32,
        5001,
        psh_ack,
        req_part2,
    );

    let resp_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    let f6 = make_tcp_frame(
        6,
        "10.0.0.1",
        80,
        "192.168.1.50",
        49152,
        5001,
        1001 + (req_part1.len() + req_part2.len()) as u32,
        psh_ack,
        resp_payload,
    );
    let f7 = make_tcp_frame(
        7,
        "10.0.0.1",
        80,
        "192.168.1.50",
        49152,
        5001 + resp_payload.len() as u32,
        1001 + (req_part1.len() + req_part2.len()) as u32,
        fin_ack,
        b"",
    );

    let frames = vec![f1, f2, f3, f4, f5, f6, f7];
    let reports = reassemble_frames(&frames, true);

    assert_eq!(reports.len(), 1);
    let rep = &reports[0];
    assert_eq!(rep.client, "192.168.1.50:49152");
    assert_eq!(rep.server, "10.0.0.1:80");
    assert!(rep.handshake_complete);
    assert!(rep.syn_seen);
    assert!(rep.fin_seen);
    assert_eq!(rep.client_packets, 4);
    assert_eq!(rep.server_packets, 3);
    assert_eq!(rep.client_payload_bytes, req_part1.len() + req_part2.len());
    assert_eq!(rep.server_payload_bytes, resp_payload.len());
    assert!(rep.detected_protocols.contains(&"HTTP/1.1".to_string()));

    let hex_c = rep.client_payload_hex.as_ref().unwrap();
    let reassembled_client_str = String::from_utf8(hex::decode(hex_c).unwrap()).unwrap();
    assert_eq!(
        reassembled_client_str,
        "GET /api/v1/status HTTP/1.1\r\nHost: 10.0.0.1\r\nConnection: close\r\n\r\n"
    );
}

#[test]
fn test_out_of_order_segments_and_gap_draining() {
    let mut half = StreamHalf::new(
        "10.1.1.2".into(),
        1234,
        "10.1.1.3".into(),
        8080,
        1024 * 1024,
    );
    let ack_flags = TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: false,
    };

    // Initial sequence number = 1000
    // Segment 1 arrives late: seq 1000..1020 ("01234567890123456789")
    // Segment 2 arrives first: seq 1020..1030 ("ABCDEFGHIJ")
    // Segment 3 arrives in between: seq 1030..1040 ("KLMNOPQRST")

    // Deliver segment 2 (out of order gap from 1000 to 1020)
    // Note: since half has not started, let's start with SYN at 999
    let syn_flags = TcpFlags {
        syn: true,
        ack: false,
        fin: false,
        rst: false,
        psh: false,
    };
    half.process_segment(999, syn_flags, b"");
    assert_eq!(half.expected_seq, 1000);

    // Segment 2: seq 1020, len 10
    half.process_segment(1020, ack_flags, b"ABCDEFGHIJ");
    assert_eq!(half.out_of_order_packets, 1);
    assert_eq!(half.reassembled_data.len(), 0);

    // Segment 3: seq 1030, len 10
    half.process_segment(1030, ack_flags, b"KLMNOPQRST");
    assert_eq!(half.out_of_order_packets, 2);
    assert_eq!(half.reassembled_data.len(), 0);

    // Now Segment 1 arrives: seq 1000, len 20
    half.process_segment(1000, ack_flags, b"01234567890123456789");

    // All should be drained!
    assert_eq!(half.reassembled_data.len(), 40);
    assert_eq!(half.expected_seq, 1040);
    assert_eq!(
        &half.reassembled_data[..],
        b"01234567890123456789ABCDEFGHIJKLMNOPQRST"
    );
}

#[test]
fn test_retransmissions_and_overlapping_slices() {
    let mut half = StreamHalf::new(
        "10.1.1.2".into(),
        1234,
        "10.1.1.3".into(),
        8080,
        1024 * 1024,
    );
    let ack_flags = TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: false,
    };

    let syn_flags = TcpFlags {
        syn: true,
        ack: false,
        fin: false,
        rst: false,
        psh: false,
    };
    half.process_segment(100, syn_flags, b""); // expected_seq = 101

    // 1. Initial 10 bytes: seq 101..111
    half.process_segment(101, ack_flags, b"AAAAAAAAAA");
    assert_eq!(half.payload_bytes_total, 10);
    assert_eq!(half.expected_seq, 111);

    // 2. Exact duplicate retransmission: seq 101..111
    half.process_segment(101, ack_flags, b"AAAAAAAAAA");
    assert_eq!(half.retransmitted_packets, 1);
    assert_eq!(half.retransmitted_bytes, 10);
    assert_eq!(half.payload_bytes_total, 10);

    // 3. Overlapping segment: seq 106..121 (5 bytes overlap, 10 new bytes)
    half.process_segment(106, ack_flags, b"AAAAABBBBBBBBBB");
    assert_eq!(half.retransmitted_packets, 2);
    assert_eq!(half.retransmitted_bytes, 15);
    assert_eq!(half.payload_bytes_total, 20);
    assert_eq!(half.expected_seq, 121);
    assert_eq!(&half.reassembled_data[..], b"AAAAAAAAAABBBBBBBBBB");
}

#[test]
fn test_fragmented_tls_client_hello_multi_segment_reassembly() {
    let client_hello = build_sample_client_hello("specter.fragment.test");
    assert!(client_hello.len() > 100);

    let split1 = 40;
    let split2 = 90;
    let part1 = &client_hello[..split1];
    let part2 = &client_hello[split1..split2];
    let part3 = &client_hello[split2..];

    let syn = TcpFlags {
        syn: true,
        ack: false,
        fin: false,
        rst: false,
        psh: false,
    };
    let ack = TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: false,
    };

    let f_syn = make_tcp_frame(
        1,
        "172.16.0.10",
        55555,
        "93.184.216.34",
        443,
        2000,
        0,
        syn,
        b"",
    );

    // Deliver segments out of order: Part 2, then Part 3, then Part 1
    let f_part2 = make_tcp_frame(
        2,
        "172.16.0.10",
        55555,
        "93.184.216.34",
        443,
        2001 + split1 as u32,
        1,
        ack,
        part2,
    );
    let f_part3 = make_tcp_frame(
        3,
        "172.16.0.10",
        55555,
        "93.184.216.34",
        443,
        2001 + split2 as u32,
        1,
        ack,
        part3,
    );
    let f_part1 = make_tcp_frame(
        4,
        "172.16.0.10",
        55555,
        "93.184.216.34",
        443,
        2001,
        1,
        ack,
        part1,
    );

    let frames = vec![f_syn, f_part2, f_part3, f_part1];
    let reports = reassemble_frames(&frames, true);

    assert_eq!(reports.len(), 1);
    let rep = &reports[0];
    assert!(rep.detected_protocols.contains(&"TLS".to_string()));
    assert!(rep.ja3.is_some());
    let ja3 = rep.ja3.as_ref().unwrap();
    assert_eq!(ja3.sni.as_deref(), Some("specter.fragment.test"));
    assert!(rep.ja4.is_some());
}

#[test]
fn test_sequence_number_32bit_wrap_around() {
    let mut half = StreamHalf::new("1.1.1.1".into(), 80, "2.2.2.2".into(), 80, 1024 * 1024);
    let ack_flags = TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: false,
    };

    // Initial sequence near u32::MAX
    let syn_flags = TcpFlags {
        syn: true,
        ack: false,
        fin: false,
        rst: false,
        psh: false,
    };
    half.process_segment(u32::MAX - 5, syn_flags, b"");
    assert_eq!(half.expected_seq, u32::MAX - 4);

    // Segment 1: 10 bytes crossing boundary: (u32::MAX - 4) .. 5
    let payload1 = b"0123456789";
    half.process_segment(u32::MAX - 4, ack_flags, payload1);
    assert_eq!(half.expected_seq, 5);

    // Segment 2: 5 bytes from 5 .. 10
    let payload2 = b"ABCDE";
    half.process_segment(5, ack_flags, payload2);
    assert_eq!(half.expected_seq, 10);
    assert_eq!(&half.reassembled_data[..], b"0123456789ABCDE");
}

#[test]
fn test_out_of_order_buffer_memory_limit_protection() {
    let mut half = StreamHalf::new(
        "1.1.1.1".into(),
        80,
        "2.2.2.2".into(),
        80,
        50, // max 50 bytes buffer limit
    );
    let syn_flags = TcpFlags {
        syn: true,
        ack: false,
        fin: false,
        rst: false,
        psh: false,
    };
    half.process_segment(100, syn_flags, b"");

    let ack_flags = TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: false,
    };

    // Huge out-of-order segment exceeding max_buffer_bytes
    let big_payload = [0x55u8; 100];
    half.process_segment(500, ack_flags, &big_payload);

    // Buffer should remain bounded
    assert_eq!(half.current_buffer_bytes, 0);
    assert_eq!(half.out_of_order_buffer.len(), 0);
}

#[test]
fn test_pcap_and_pcapng_capture_bytes_reassembly() {
    let pcap_bytes = build_synthetic_pcap();
    let pcap_reports = reassemble_capture_bytes(&pcap_bytes, false).unwrap();
    assert!(!pcap_reports.is_empty());

    let pcapng_bytes = build_synthetic_pcapng();
    let pcapng_reports = reassemble_capture_bytes(&pcapng_bytes, false).unwrap();
    assert!(!pcapng_reports.is_empty());
}

#[test]
fn test_cli_tcp_stream_command_execution() {
    let pcap_bytes = build_synthetic_pcap();
    let temp_dir = std::env::temp_dir();
    let temp_pcap = temp_dir.join("nspecter_tcp_test.pcap");
    fs::write(&temp_pcap, &pcap_bytes).unwrap();

    let exe = env!("CARGO_BIN_EXE_nspecter");
    let output = Command::new(exe)
        .arg("tcp-stream")
        .arg(&temp_pcap)
        .arg("--json")
        .output()
        .expect("Failed to execute nspecter tcp-stream");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json_val: serde_json::Value =
        serde_json::from_str(&stdout).expect("Valid JSON output expected");
    assert!(json_val.is_array());
    assert!(!json_val.as_array().unwrap().is_empty());

    let _ = fs::remove_file(temp_pcap);
}
