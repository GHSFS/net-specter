// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use net_specter::icmp_tunnel::{
    audit_icmp_bytes, build_synthetic_icmp_pcap, compute_shannon_entropy, detect_payload_pattern,
    parse_icmp_echo, IcmpEchoType, IcmpTunnelVerdict, IcmpVersion, ICMPV6_TYPE_ECHO_REQUEST,
    WINDOWS_PING_PAYLOAD,
};
use std::fs;
use std::process::Command;

#[test]
fn test_shannon_entropy_calculation() {
    assert_eq!(compute_shannon_entropy(&[]), 0.0);

    // Uniform single byte: entropy is 0
    let zeroes = vec![0u8; 100];
    assert_eq!(compute_shannon_entropy(&zeroes), 0.0);

    // Two equally frequent bytes: entropy is 1.0 bit
    let mut binary = vec![0u8; 50];
    binary.extend(vec![1u8; 50]);
    let h = compute_shannon_entropy(&binary);
    assert!((h - 1.0).abs() < 1e-4);

    // Full 256 bytes byte-distribution: entropy is 8.0 bits
    let all_bytes: Vec<u8> = (0..=255).collect();
    let h_max = compute_shannon_entropy(&all_bytes);
    assert!((h_max - 8.0).abs() < 1e-4);
}

#[test]
fn test_payload_pattern_detection() {
    // Windows 32-byte pattern
    let (label, std) = detect_payload_pattern(WINDOWS_PING_PAYLOAD);
    assert!(std);
    assert!(label.contains("Windows Standard"));

    // Linux 56-byte pattern
    let mut linux = vec![0u8; 56];
    for (i, b) in linux[16..].iter_mut().enumerate() {
        *b = (0x10 + i) as u8;
    }
    let (label_linux, std_linux) = detect_payload_pattern(&linux);
    assert!(std_linux);
    assert!(label_linux.contains("Linux Standard"));

    // Zero-filled pattern
    let zero = vec![0u8; 32];
    let (label_zero, std_zero) = detect_payload_pattern(&zero);
    assert!(std_zero);
    assert!(label_zero.contains("Zero-Filled"));

    // Non-standard random bytes
    let rand_data = vec![0x42, 0x13, 0x37, 0xfe, 0xca, 0xbe];
    let (label_rand, std_rand) = detect_payload_pattern(&rand_data);
    assert!(!std_rand);
    assert_eq!(label_rand, "Non-Standard Payload");
}

#[test]
fn test_synthetic_icmp_pcap_audit_outcomes() {
    let pcap_bytes = build_synthetic_icmp_pcap();
    assert!(pcap_bytes.len() > 100);

    let report = audit_icmp_bytes(&pcap_bytes, "synthetic_test.pcap").unwrap();

    assert_eq!(report.total_capture_frames, 9);
    assert_eq!(report.total_icmp_frames, 9);
    assert_eq!(report.echo_requests, 5);
    assert_eq!(report.echo_replies, 4);
    assert_eq!(report.conversations.len(), 3);

    // Overall verdict must be TunnelDetected due to flow 3 (mismatched payloads + commands)
    assert_eq!(report.overall_verdict, IcmpTunnelVerdict::TunnelDetected);

    // Conversation 1: Windows ping (clean)
    let win_conv = report
        .conversations
        .iter()
        .find(|c| c.client_ip == "192.168.1.50" && c.server_ip == "8.8.8.8")
        .expect("Windows conversation not found");
    assert_eq!(win_conv.verdict, IcmpTunnelVerdict::Clean);
    assert_eq!(win_conv.request_count, 2);
    assert_eq!(win_conv.reply_count, 2);
    assert_eq!(win_conv.payload_mismatches, 0);
    assert_eq!(win_conv.sequence_gaps, 0);
    assert_eq!(win_conv.max_payload_len, 32);

    // Conversation 2: Linux ping (clean)
    let linux_conv = report
        .conversations
        .iter()
        .find(|c| c.client_ip == "10.0.0.15" && c.server_ip == "1.1.1.1")
        .expect("Linux conversation not found");
    assert_eq!(linux_conv.verdict, IcmpTunnelVerdict::Clean);
    assert_eq!(linux_conv.request_count, 1);
    assert_eq!(linux_conv.reply_count, 1);
    assert_eq!(linux_conv.payload_mismatches, 0);
    assert_eq!(linux_conv.max_payload_len, 56);

    // Conversation 3: Covert Tunnel Flow (TunnelDetected)
    let tunnel_conv = report
        .conversations
        .iter()
        .find(|c| c.client_ip == "172.16.0.99" && c.server_ip == "198.51.100.7")
        .expect("Tunnel conversation not found");
    assert_eq!(tunnel_conv.verdict, IcmpTunnelVerdict::TunnelDetected);
    assert_eq!(tunnel_conv.payload_mismatches, 1);
    assert!(tunnel_conv.sequence_gaps > 0);
    assert!(tunnel_conv
        .detected_threats
        .iter()
        .any(|t| t.contains("Payload mismatch")));
    assert!(tunnel_conv
        .detected_threats
        .iter()
        .any(|t| t.contains("cmd.exe")));
}

#[test]
fn test_icmpv6_echo_parsing_and_audit() {
    // Construct raw ICMPv6 echo frame
    let mut v6_echo = Vec::new();
    v6_echo.push(ICMPV6_TYPE_ECHO_REQUEST);
    v6_echo.push(0); // code
    v6_echo.extend_from_slice(&[0x1a, 0x2b]); // checksum
    v6_echo.extend_from_slice(&0x4321u16.to_be_bytes()); // id
    v6_echo.extend_from_slice(&0x0001u16.to_be_bytes()); // seq
    v6_echo.extend_from_slice(WINDOWS_PING_PAYLOAD);

    let parsed = parse_icmp_echo(
        &v6_echo,
        1,
        1_700_000_000_000_000_000,
        "2001:db8::1",
        "2001:db8::2",
        IcmpVersion::V6,
    )
    .expect("Failed to parse ICMPv6 echo");

    assert_eq!(parsed.version, IcmpVersion::V6);
    assert_eq!(parsed.echo_type, IcmpEchoType::EchoRequest);
    assert_eq!(parsed.identifier, 0x4321);
    assert_eq!(parsed.sequence, 1);
    assert_eq!(parsed.payload_len, 32);
    assert!(parsed.is_standard_pattern);
}

#[test]
fn test_adversarial_truncated_icmp_bounds() {
    // 0-byte slice
    assert!(parse_icmp_echo(&[], 1, 0, "1.1.1.1", "2.2.2.2", IcmpVersion::V4).is_none());

    // 7-byte slice (shorter than 8-byte minimum header)
    let short_header = [8, 0, 0, 0, 1, 2, 3];
    assert!(parse_icmp_echo(&short_header, 1, 0, "1.1.1.1", "2.2.2.2", IcmpVersion::V4).is_none());

    // Arbitrary garbage slice in audit_icmp_bytes returns error safely
    let garbage = vec![0xff; 12];
    assert!(audit_icmp_bytes(&garbage, "garbage.bin").is_err());
}

#[test]
fn test_cli_icmp_tunnel_command() {
    let pcap_bytes = build_synthetic_icmp_pcap();
    let temp_path = std::env::temp_dir().join("test_icmp_sample.pcap");
    fs::write(&temp_path, &pcap_bytes).expect("Failed to write temporary test PCAP");

    // Test text mode output
    let status_text = Command::new(env!("CARGO_BIN_EXE_nspecter"))
        .args(["icmp-tunnel", temp_path.to_str().unwrap(), "--dump-payload"])
        .status()
        .expect("Failed to execute nspecter icmp-tunnel");
    assert!(status_text.success());

    // Test JSON mode output
    let output_json = Command::new(env!("CARGO_BIN_EXE_nspecter"))
        .args(["icmp-tunnel", temp_path.to_str().unwrap(), "--json"])
        .output()
        .expect("Failed to execute nspecter icmp-tunnel --json");
    assert!(output_json.status.success());

    let stdout_str = String::from_utf8(output_json.stdout).unwrap();
    let val: serde_json::Value =
        serde_json::from_str(&stdout_str).expect("Output is not valid JSON");
    assert_eq!(val["overall_verdict"], "TunnelDetected");
    assert_eq!(val["total_capture_frames"], 9);

    let _ = fs::remove_file(temp_path);
}
