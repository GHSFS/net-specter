// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration tests for TCP SYN Passive OS Fingerprinting & FoxIO JA4T/JA4TS (`nspecter os-fp`).

use net_specter::commands::os_fp::handle_os_fp;
use net_specter::p0f::{
    audit_os_fingerprints, build_synthetic_syn_pcap, classify_os, compute_ja4t,
    compute_p0f_signature, estimate_initial_ttl, parse_tcp_options, ParsedTcpOption,
};
use std::fs;

#[test]
fn test_exact_ja4t_fingerprint_calculation_and_hashing() {
    // Windows 10/11 options layout: MSS(2), NOP(1), WS(3), NOP(1), NOP(1), SACK_PERMITTED(4)
    let win_opts = vec![2, 1, 3, 1, 1, 4];
    let (raw_win, hash_win) = compute_ja4t(64240, &win_opts, Some(8), Some(1460));
    assert_eq!(raw_win, "64240_2-1-3-1-1-4_8_1460");
    assert_eq!(hash_win.len(), 12);

    // Linux kernel options layout: MSS(2), SACK_PERMITTED(4), TS(8), NOP(1), WS(3)
    let linux_opts = vec![2, 4, 8, 1, 3];
    let (raw_linux, hash_linux) = compute_ja4t(64240, &linux_opts, Some(7), Some(1460));
    assert_eq!(raw_linux, "64240_2-4-8-1-3_7_1460");
    assert_eq!(hash_linux.len(), 12);
    assert_ne!(hash_win, hash_linux);

    // Empty options (Masscan/ZMap raw SYN)
    let (raw_empty, hash_empty) = compute_ja4t(1024, &[], None, None);
    assert_eq!(raw_empty, "1024_0_0_0");
    assert_eq!(hash_empty.len(), 12);
}

#[test]
fn test_p0f_v3_signature_and_distance_estimation() {
    // TTL distance estimation
    assert_eq!(estimate_initial_ttl(128), (128, 0));
    assert_eq!(estimate_initial_ttl(122), (128, 6));
    assert_eq!(estimate_initial_ttl(64), (64, 0));
    assert_eq!(estimate_initial_ttl(54), (64, 10));
    assert_eq!(estimate_initial_ttl(240), (255, 15));
    assert_eq!(estimate_initial_ttl(28), (32, 4));

    let options = vec![
        ParsedTcpOption {
            kind: 2,
            length: 4,
            name: "mss".into(),
        },
        ParsedTcpOption {
            kind: 1,
            length: 1,
            name: "nop".into(),
        },
        ParsedTcpOption {
            kind: 3,
            length: 3,
            name: "ws".into(),
        },
        ParsedTcpOption {
            kind: 4,
            length: 2,
            name: "sok".into(),
        },
    ];
    let quirks = vec!["df".to_string()];

    let sig = compute_p0f_signature(
        4,
        128,
        5,
        12,
        Some(1460),
        64240,
        Some(8),
        &options,
        &quirks,
        0,
    );
    assert_eq!(sig, "4:128:5:12:1460:64240,8:mss,nop,ws,sok:df:0");
}

#[test]
fn test_os_classification_profiles() {
    // Windows 10/11
    let class_win = classify_os(
        128,
        &[2, 1, 3, 1, 1, 4],
        Some(8),
        Some(1460),
        64240,
        false,
        true,
    );
    assert_eq!(class_win.family, "Windows");
    assert!(class_win.flavor.contains("Windows 10/11"));
    assert!(class_win.confidence >= 0.90);

    // Windows 7/8
    let class_win7 = classify_os(
        128,
        &[2, 1, 3, 1, 1, 4],
        Some(2),
        Some(1460),
        8192,
        false,
        true,
    );
    assert_eq!(class_win7.family, "Windows");
    assert!(class_win7.flavor.contains("Windows 7/8"));

    // Linux 3.x - 6.x
    let class_linux = classify_os(64, &[2, 4, 8, 1, 3], Some(7), Some(1460), 64240, true, true);
    assert_eq!(class_linux.family, "Linux");
    assert!(class_linux.flavor.contains("Linux 3.x-6.x"));
    assert!(class_linux.confidence >= 0.90);

    // Apple macOS / iOS
    let class_mac = classify_os(
        64,
        &[2, 1, 3, 1, 1, 8, 4, 0],
        Some(6),
        Some(1460),
        65535,
        true,
        true,
    );
    assert_eq!(class_mac.family, "Apple");
    assert!(class_mac.flavor.contains("macOS"));

    // Nmap SYN Scan
    let class_nmap = classify_os(64, &[2], None, Some(1460), 1024, false, true);
    assert_eq!(class_nmap.family, "Scanner");
    assert!(class_nmap.flavor.contains("Nmap"));

    // Masscan
    let class_masscan = classify_os(64, &[], None, None, 1024, false, false);
    assert_eq!(class_masscan.family, "Scanner");
    assert!(class_masscan.flavor.contains("Masscan"));
}

#[test]
fn test_adversarial_malformed_options_bounds() {
    // Truncated multi-byte option header (only kind byte, missing length)
    let (opts, _, _, _, _, quirks) = parse_tcp_options(&[2]);
    assert!(opts.is_empty());
    assert!(quirks.iter().any(|q| q.contains("truncated_option_header")));

    // Malformed length: length byte 1 (illegal for options with kind >= 2)
    let (opts, _, _, _, _, quirks) = parse_tcp_options(&[2, 1]);
    assert!(opts.is_empty());
    assert!(quirks.iter().any(|q| q.contains("malformed_option_length")));

    // Option length exceeding buffer
    let (opts, _, _, _, _, quirks) = parse_tcp_options(&[2, 10, 0x05, 0xb4]);
    assert!(opts.is_empty());
    assert!(quirks.iter().any(|q| q.contains("malformed_option_length")));

    // Trailing data past EOL
    let (opts, _, _, _, _, quirks) = parse_tcp_options(&[1, 0, 0xaa, 0xbb]);
    assert_eq!(opts.len(), 2);
    assert_eq!(opts[0].name, "nop");
    assert_eq!(opts[1].name, "eol");
    assert!(quirks
        .iter()
        .any(|q| q.contains("trailing_non_zero_past_eol")));

    // Excessive WSCALE (> 14)
    let (opts, _, ws, _, _, quirks) = parse_tcp_options(&[3, 3, 16]);
    assert_eq!(opts.len(), 1);
    assert_eq!(ws, Some(16));
    assert!(quirks.iter().any(|q| q.contains("excessive_wscale_16")));
}

#[test]
fn test_synthetic_syn_pcap_audit() {
    let pcap_bytes = build_synthetic_syn_pcap();
    assert!(pcap_bytes.len() > 100);

    let report = audit_os_fingerprints(&pcap_bytes, "synthetic_syn_test.pcap")
        .expect("Synthetic PCAP audit must succeed");

    assert_eq!(report.total_capture_frames, 5);
    assert_eq!(report.total_tcp_frames, 5);
    assert_eq!(report.total_syn_frames, 5);
    assert_eq!(report.hosts.len(), 4);

    // Host 1: Windows 10/11 (192.168.1.50)
    let win_host = report
        .hosts
        .iter()
        .find(|h| h.ip == "192.168.1.50")
        .expect("Windows host must be present");
    assert_eq!(win_host.os_family, "Windows");
    assert!(win_host.os_flavor.contains("Windows 10/11"));
    assert_eq!(win_host.ja4t, "64240_2-1-3-1-1-4_8_1460");
    assert_eq!(win_host.initial_ttl, 128);

    // Host 2: Linux 6.x (192.168.1.60)
    let linux_host = report
        .hosts
        .iter()
        .find(|h| h.ip == "192.168.1.60")
        .expect("Linux host must be present");
    assert_eq!(linux_host.os_family, "Linux");
    assert!(linux_host.os_flavor.contains("Linux 3.x-6.x"));
    assert_eq!(linux_host.ja4t, "64240_2-4-8-1-3_7_1460");
    assert_eq!(linux_host.initial_ttl, 64);

    // Host 3: Apple macOS (192.168.1.70)
    let mac_host = report
        .hosts
        .iter()
        .find(|h| h.ip == "192.168.1.70")
        .expect("macOS host must be present");
    assert_eq!(mac_host.os_family, "Apple");
    assert!(mac_host.os_flavor.contains("macOS"));
    assert_eq!(mac_host.initial_ttl, 64);

    // Host 4: Port Scanner (10.10.10.99)
    let scanner_host = report
        .hosts
        .iter()
        .find(|h| h.ip == "10.10.10.99")
        .expect("Scanner host must be present");
    assert_eq!(scanner_host.total_syn_packets, 2);
    assert!(!scanner_host.anomalies.is_empty());

    // Anomalous frame checks
    assert!(!report.anomalous_frames.is_empty());
    assert!(report
        .anomalous_frames
        .iter()
        .any(|f| f.anomalies.iter().any(|a| a.contains("SYN+FIN"))));
    assert!(report
        .anomalous_frames
        .iter()
        .any(|f| f.anomalies.iter().any(|a| a.contains("Zero TCP window"))));
}

#[test]
fn test_cli_os_fp_subcommand() {
    let pcap_bytes = build_synthetic_syn_pcap();
    let temp_path = std::env::temp_dir().join("test_syn_sample.pcap");
    fs::write(&temp_path, pcap_bytes).expect("Failed to write temp test pcap");

    let path_str = temp_path.to_str().unwrap();

    // Human readable output
    let res_text = handle_os_fp(path_str, false);
    assert!(res_text.is_ok());

    // JSON structured output
    let res_json = handle_os_fp(path_str, true);
    assert!(res_json.is_ok());

    let _ = fs::remove_file(temp_path);
}
