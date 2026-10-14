// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration tests for ARP Spoofing & Layer-2 MITM Anomaly Detector (`nspecter arp-audit`).

use net_specter::arp_audit::{
    audit_arp_bytes, build_raw_arp_frame, build_synthetic_arp_pcap, parse_arp_payload,
    ArpAuditConfig, ArpOpcode, ArpScenario, ArpSubtype, ArpVerdict, ARP_OPER_REPLY,
    ARP_OPER_REQUEST,
};
use net_specter::commands::arp::handle_arp_audit;
use std::fs;

#[test]
fn test_arp_frame_parsing_and_subtypes() {
    let client_mac = [0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33];
    let client_ip = [192, 168, 1, 50];
    let gateway_mac = [0x00, 0x50, 0x56, 0xc0, 0x00, 0x08];
    let gateway_ip = [192, 168, 1, 1];

    // Standard Request
    let raw_req = build_raw_arp_frame(
        [0xff; 6],
        client_mac,
        ARP_OPER_REQUEST,
        client_mac,
        client_ip,
        [0; 6],
        gateway_ip,
    );
    let pkt_req = parse_arp_payload(
        1,
        1_000_000_000,
        &raw_req[14..],
        Some("aa:bb:cc:11:22:33"),
        Some("ff:ff:ff:ff:ff:ff"),
    )
    .expect("Should parse standard ARP request");
    assert_eq!(pkt_req.opcode, ArpOpcode::Request);
    assert_eq!(pkt_req.subtype, ArpSubtype::StandardRequest);
    assert_eq!(pkt_req.sender_ip, "192.168.1.50");
    assert_eq!(pkt_req.target_ip, "192.168.1.1");
    assert_eq!(pkt_req.sender_mac, "aa:bb:cc:11:22:33");
    assert!(!pkt_req.is_gratuitous);
    assert!(pkt_req.anomalies.is_empty());

    // Standard Reply
    let raw_rep = build_raw_arp_frame(
        client_mac,
        gateway_mac,
        ARP_OPER_REPLY,
        gateway_mac,
        gateway_ip,
        client_mac,
        client_ip,
    );
    let pkt_rep = parse_arp_payload(
        2,
        1_000_005_000,
        &raw_rep[14..],
        Some("00:50:56:c0:00:08"),
        Some("aa:bb:cc:11:22:33"),
    )
    .expect("Should parse standard ARP reply");
    assert_eq!(pkt_rep.opcode, ArpOpcode::Reply);
    assert_eq!(pkt_rep.subtype, ArpSubtype::StandardReply);
    assert_eq!(pkt_rep.sender_ip, "192.168.1.1");
    assert_eq!(pkt_rep.target_ip, "192.168.1.50");
    assert!(!pkt_rep.is_gratuitous);
    assert!(pkt_rep.anomalies.is_empty());

    // RFC 5227 ACD Probe (sender IP is 0.0.0.0)
    let raw_probe = build_raw_arp_frame(
        [0xff; 6],
        client_mac,
        ARP_OPER_REQUEST,
        client_mac,
        [0, 0, 0, 0],
        [0; 6],
        client_ip,
    );
    let pkt_probe = parse_arp_payload(
        3,
        1_000_010_000,
        &raw_probe[14..],
        Some("aa:bb:cc:11:22:33"),
        Some("ff:ff:ff:ff:ff:ff"),
    )
    .expect("Should parse ARP probe");
    assert_eq!(pkt_probe.subtype, ArpSubtype::ArpProbe);
    assert_eq!(pkt_probe.sender_ip, "0.0.0.0");
    assert_eq!(pkt_probe.target_ip, "192.168.1.50");

    // RFC 5227 ACD Announcement (sender IP == target IP, target MAC zeros)
    let raw_ann = build_raw_arp_frame(
        [0xff; 6],
        client_mac,
        ARP_OPER_REQUEST,
        client_mac,
        client_ip,
        [0; 6],
        client_ip,
    );
    let pkt_ann = parse_arp_payload(
        4,
        1_000_015_000,
        &raw_ann[14..],
        Some("aa:bb:cc:11:22:33"),
        Some("ff:ff:ff:ff:ff:ff"),
    )
    .expect("Should parse ARP announcement");
    assert_eq!(pkt_ann.subtype, ArpSubtype::ArpAnnouncement);
    assert!(pkt_ann.is_gratuitous);
}

#[test]
fn test_conflicting_ip_ownership_detection() {
    let pcap_bytes = build_synthetic_arp_pcap(ArpScenario::ConflictingBinding);
    let report = audit_arp_bytes(&pcap_bytes, "test_conflict.pcap", None)
        .expect("Audit should complete successfully");

    assert_eq!(report.total_arp_frames, 2);
    assert_eq!(report.replies, 2);
    assert!(
        matches!(
            report.overall_verdict,
            ArpVerdict::Suspicious | ArpVerdict::AttackDetected
        ),
        "Expected Suspicious or AttackDetected, got {:?}",
        report.overall_verdict
    );

    let host = report
        .bindings
        .iter()
        .find(|b| b.ip == "192.168.1.100")
        .expect("Host 192.168.1.100 should be tracked");
    assert_eq!(host.observed_macs.len(), 2);
    assert!(host.mac_transitions >= 1);
    assert!(!host.anomalies.is_empty());
}

#[test]
fn test_gateway_mac_flapping_and_mitm_verdict() {
    let pcap_bytes = build_synthetic_arp_pcap(ArpScenario::GatewayFlapping);
    let mut config = ArpAuditConfig::default();
    config.gateway_ips.push("192.168.1.1".to_string());

    let report = audit_arp_bytes(&pcap_bytes, "test_gateway_flapping.pcap", Some(config))
        .expect("Audit should complete successfully");

    assert_eq!(report.total_arp_frames, 4);
    assert_eq!(report.overall_verdict, ArpVerdict::AttackDetected);
    assert!(!report.detected_threats.is_empty());

    let gw = report
        .bindings
        .iter()
        .find(|b| b.ip == "192.168.1.1")
        .expect("Gateway 192.168.1.1 should be present");
    assert!(gw.is_gateway);
    assert!(gw.is_flapping);
    assert!(gw.mac_transitions >= 3);
    assert_eq!(gw.observed_macs.len(), 2);

    let has_gw_threat = report
        .detected_threats
        .iter()
        .any(|t| t.contains("Gateway MAC Flapping"));
    assert!(has_gw_threat, "Expected Gateway MAC Flapping threat");
}

#[test]
fn test_gratuitous_arp_flood_detection() {
    let pcap_bytes = build_synthetic_arp_pcap(ArpScenario::GratuitousFlood);
    let report = audit_arp_bytes(&pcap_bytes, "test_flood.pcap", None)
        .expect("Audit should complete successfully");

    assert_eq!(report.total_arp_frames, 15);
    assert_eq!(report.gratuitous_count, 15);
    assert_eq!(report.overall_verdict, ArpVerdict::AttackDetected);

    let has_flood_threat = report
        .detected_threats
        .iter()
        .any(|t| t.contains("Gratuitous ARP Flood"));
    assert!(has_flood_threat, "Expected Gratuitous ARP Flood threat");
}

#[test]
fn test_l2_mac_mismatch_and_broadcast_reply_violations() {
    // 1. Ethernet L2 MAC mismatch
    let pcap_mismatch = build_synthetic_arp_pcap(ArpScenario::EthernetMacMismatch);
    let rep_mismatch =
        audit_arp_bytes(&pcap_mismatch, "test_mismatch.pcap", None).expect("Audit should complete");
    assert_eq!(rep_mismatch.overall_verdict, ArpVerdict::AttackDetected);
    assert!(!rep_mismatch.anomalous_frames.is_empty());
    let has_mismatch_anomaly = rep_mismatch.anomalous_frames[0]
        .anomalies
        .iter()
        .any(|a| a.contains("does not match ARP sender MAC"));
    assert!(has_mismatch_anomaly);

    // 2. Broadcast Reply
    let pcap_bcast = build_synthetic_arp_pcap(ArpScenario::BroadcastReply);
    let rep_bcast =
        audit_arp_bytes(&pcap_bcast, "test_bcast.pcap", None).expect("Audit should complete");
    assert_eq!(rep_bcast.overall_verdict, ArpVerdict::AttackDetected);
    assert!(!rep_bcast.anomalous_frames.is_empty());
    let has_bcast_violation = rep_bcast.anomalous_frames[0]
        .anomalies
        .iter()
        .any(|a| a.contains("RFC 826 violation"));
    assert!(has_bcast_violation);
}

#[test]
fn test_adversarial_malformed_and_truncated_bounds() {
    // Truncated payload (< 28 bytes)
    let truncated = [0u8; 20];
    let res = parse_arp_payload(1, 0, &truncated, None, None);
    assert!(res.is_err());

    // Invalid hardware type
    let mut invalid_htype = [0u8; 28];
    invalid_htype[0] = 0x00;
    invalid_htype[1] = 0x02; // Non-Ethernet
    invalid_htype[2] = 0x08;
    invalid_htype[3] = 0x00;
    invalid_htype[4] = 6;
    invalid_htype[5] = 4;
    let res = parse_arp_payload(1, 0, &invalid_htype, None, None);
    assert!(res.is_err());

    // Multicast sender MAC and loopback IP anomaly
    let mut anomalous = [0u8; 28];
    anomalous[0] = 0x00;
    anomalous[1] = 0x01; // Ethernet
    anomalous[2] = 0x08;
    anomalous[3] = 0x00; // IPv4
    anomalous[4] = 6;
    anomalous[5] = 4;
    anomalous[6] = 0x00;
    anomalous[7] = 0x01; // Request
    anomalous[8] = 0x01; // Multicast bit set on sender MAC (01:00:5e:00:00:01)
    anomalous[14] = 127; // Loopback sender IP (127.0.0.1)
    anomalous[17] = 1;
    let pkt = parse_arp_payload(1, 0, &anomalous, None, None).expect("Should parse with anomalies");
    assert!(!pkt.anomalies.is_empty());
    let has_mc_flag = pkt
        .anomalies
        .iter()
        .any(|a| a.contains("multicast/broadcast bit set"));
    let has_loopback_flag = pkt
        .anomalies
        .iter()
        .any(|a| a.contains("Illegal loopback IP"));
    assert!(has_mc_flag);
    assert!(has_loopback_flag);
}

#[test]
fn test_cli_arp_audit_command() {
    let pcap_bytes = build_synthetic_arp_pcap(ArpScenario::CleanResolution);
    let tmp_path = std::env::temp_dir().join("test_arp_sample.pcap");
    fs::write(&tmp_path, &pcap_bytes).expect("Failed to write temporary test PCAP");

    let str_path = tmp_path.to_string_lossy().to_string();

    // Human readable output
    let res_human = handle_arp_audit(&str_path, None, false);
    assert!(res_human.is_ok());

    // JSON output with gateway override
    let res_json = handle_arp_audit(&str_path, Some("192.168.1.1"), true);
    assert!(res_json.is_ok());

    let _ = fs::remove_file(tmp_path);
}
