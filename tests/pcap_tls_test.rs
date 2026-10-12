// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use md5::{Digest as Md5Digest, Md5};
use net_specter::pcap::{
    build_synthetic_pcap, decode_frame, parse_pcap_bytes, LINKTYPE_ETHERNET, LINKTYPE_RAW_IP,
};
use net_specter::tls_ja3::{build_sample_client_hello, is_grease, parse_tls_client_hello};
use sha2::Sha256;
use std::process::Command;

#[test]
fn test_grease_detection_rfc8701() {
    for &g in &[
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ] {
        assert!(
            is_grease(g),
            "Expected 0x{g:04x} to be recognized as GREASE"
        );
    }
    for &non_grease in &[0x0000, 0x1301, 0x1302, 0xc02b, 0x0a1a, 0x1a0a, 0x001d] {
        assert!(
            !is_grease(non_grease),
            "Expected 0x{non_grease:04x} NOT to be recognized as GREASE"
        );
    }
}

#[test]
fn test_tls_client_hello_and_exact_ja3_digest() {
    let raw_hello = build_sample_client_hello("api.telemetry.example.org");
    let report = parse_tls_client_hello(&raw_hello).expect("valid sample ClientHello");

    assert_eq!(report.record_version, 0x0301);
    assert_eq!(report.client_version, 0x0303); // 771
    assert_eq!(report.sni.as_deref(), Some("api.telemetry.example.org"));
    assert_eq!(report.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    assert_eq!(report.supported_versions, vec![0x0304, 0x0303]);
    assert_eq!(report.grease_filtered_count, 4);

    let expected_ja3_str = "771,4865-4866-4867-49195,0-10-11-16-43,29-23,0";
    assert_eq!(report.ja3_string, expected_ja3_str);

    let mut md5_hasher = Md5::new();
    md5_hasher.update(expected_ja3_str.as_bytes());
    let expected_md5 = hex::encode(md5_hasher.finalize());
    assert_eq!(report.ja3_md5, expected_md5);

    let mut sha_hasher = Sha256::new();
    sha_hasher.update(expected_ja3_str.as_bytes());
    let expected_sha256 = hex::encode(sha_hasher.finalize());
    assert_eq!(report.ja3_sha256, expected_sha256);
}

#[test]
fn test_synthetic_pcap_decoding_and_flows() {
    let pcap_bytes = build_synthetic_pcap();
    let report = parse_pcap_bytes(&pcap_bytes).expect("synthetic PCAP should parse cleanly");

    assert_eq!(report.header.version_major, 2);
    assert_eq!(report.header.version_minor, 4);
    assert_eq!(report.header.linktype, LINKTYPE_ETHERNET);
    assert_eq!(report.total_packets, 3);
    assert_eq!(report.tcp_packets, 1);
    assert_eq!(report.udp_packets, 2);
    assert_eq!(report.tls_handshakes.len(), 1);
    assert_eq!(report.dns_messages.len(), 2);

    let tcp_frame = &report.frames[0];
    assert_eq!(tcp_frame.src_ip, "10.0.0.15");
    assert_eq!(tcp_frame.dst_ip, "93.184.216.34");
    assert_eq!(tcp_frame.src_port, 51422);
    assert_eq!(tcp_frame.dst_port, 443);
    assert_eq!(tcp_frame.protocol, "TCP");
    let flags = tcp_frame.tcp_flags.expect("TCP flags present");
    assert!(flags.psh && flags.ack && !flags.syn && !flags.fin);
}

#[test]
fn test_vlan_and_raw_ipv6_decoding() {
    // Construct an IPv6 UDP packet in Raw IP mode (linktype 101)
    let mut ipv6_pkt = Vec::with_capacity(56);
    ipv6_pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version 6
    ipv6_pkt.extend_from_slice(&12u16.to_be_bytes()); // payload len = 8 UDP hdr + 4 data
    ipv6_pkt.push(17); // Next Header = UDP
    ipv6_pkt.push(64); // Hop Limit
    ipv6_pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
    ipv6_pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
                                                                                   // UDP header
    ipv6_pkt.extend_from_slice(&12345u16.to_be_bytes());
    ipv6_pkt.extend_from_slice(&8080u16.to_be_bytes());
    ipv6_pkt.extend_from_slice(&12u16.to_be_bytes());
    ipv6_pkt.extend_from_slice(&0u16.to_be_bytes());
    ipv6_pkt.extend_from_slice(b"PING");

    let decoded =
        decode_frame(0, 100, 0, ipv6_pkt.len() as u32, LINKTYPE_RAW_IP, &ipv6_pkt).unwrap();
    assert_eq!(decoded.ip_version, 6);
    assert_eq!(decoded.src_ip, "::1");
    assert_eq!(decoded.protocol, "UDP");
    assert_eq!(decoded.payload, b"PING");
}

#[test]
fn test_malformed_pcap_and_tls_bounds_rejection() {
    assert!(parse_pcap_bytes(&[0u8; 10]).is_err());
    assert!(parse_tls_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x50, 0x01]).is_err());
}

#[test]
fn test_cli_synth_and_ja3_json_output() {
    let exe = env!("CARGO_BIN_EXE_nspecter");
    let temp_pcap = std::env::temp_dir().join("net_specter_test_capture.pcap");

    let synth_out = Command::new(exe)
        .args(["synth-pcap", temp_pcap.to_str().unwrap(), "--json"])
        .output()
        .expect("run synth-pcap");
    assert!(synth_out.status.success());

    let ja3_out = Command::new(exe)
        .args(["ja3", temp_pcap.to_str().unwrap(), "--json"])
        .output()
        .expect("run ja3");
    assert!(ja3_out.status.success());

    let parsed: serde_json::Value =
        serde_json::from_slice(&ja3_out.stdout).expect("valid JSON from ja3 command");
    assert_eq!(parsed["sni"], "api.telemetry.example.org");
    assert_eq!(
        parsed["ja3_string"],
        "771,4865-4866-4867-49195,0-10-11-16-43,29-23,0"
    );

    let _ = std::fs::remove_file(&temp_pcap);
}
