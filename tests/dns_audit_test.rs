// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use net_specter::dns::{build_dns_query_packet, decode_qname, parse_dns_packet, TunnelRisk};
use std::process::Command;

#[test]
fn test_benign_vs_covert_tunnel_dns_queries() {
    let normal_pkt = build_dns_query_packet(0x1111, "www.cloudflare.com", 1); // A
    let normal_rep = parse_dns_packet(&normal_pkt).expect("parse normal DNS packet");
    assert_eq!(normal_rep.transaction_id, 0x1111);
    assert_eq!(normal_rep.questions.len(), 1);
    let q_norm = &normal_rep.questions[0];
    assert_eq!(q_norm.qname, "www.cloudflare.com");
    assert_eq!(q_norm.qtype_name, "A");
    assert_eq!(q_norm.risk_level, TunnelRisk::Low);

    let covert_domain =
        "8f3a1c9e4b7d2f6a0c5e8b1d4f7a3c9e2b6d0f8a4c1e7b3d.exfil.c2-beacon.example.org";
    let covert_pkt = build_dns_query_packet(0x2222, covert_domain, 16); // TXT
    let covert_rep = parse_dns_packet(&covert_pkt).expect("parse covert DNS packet");
    let q_cov = &covert_rep.questions[0];
    assert_eq!(q_cov.qtype_name, "TXT");
    assert_eq!(q_cov.risk_level, TunnelRisk::High);
    assert!(q_cov.risk_score >= 60);
    assert!(q_cov.subdomain_entropy >= 3.8);
    assert!(!q_cov.reasons.is_empty());
}

#[test]
fn test_dns_compression_pointer_and_loop_defense() {
    // Packet with valid compression pointer at offset 20 pointing back to offset 12 ("example.com")
    let mut pkt = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // Offset 12: \x07example\x03com\x00
    pkt.extend_from_slice(b"\x07example\x03com\x00");
    // Offset 25: \x03api\xc0\x0c (api + pointer to offset 12)
    let ptr_offset = pkt.len();
    pkt.extend_from_slice(b"\x03api\xc0\x0c");

    let (decoded, next_off) = decode_qname(&pkt, ptr_offset).expect("valid compressed QNAME");
    assert_eq!(decoded, "api.example.com");
    assert_eq!(next_off, ptr_offset + 6);

    // Cyclic compression pointer loop: offset 12 jumps to offset 14, offset 14 jumps back to 12
    let cyclic_pkt = [
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0e, 0xc0,
        0x0c,
    ];
    assert!(
        decode_qname(&cyclic_pkt, 12).is_err(),
        "Cyclic compression pointer must be rejected"
    );
}

#[test]
fn test_cli_dns_audit_hex_json() {
    let exe = env!("CARGO_BIN_EXE_nspecter");
    let pkt = build_dns_query_packet(
        0x9999,
        "7e4a9c2f8b1d6e3a0c5f9b2d4e8a1c7f3b6d0e9a2c4f8b1d.data.example.com",
        16,
    );
    let hex_str = hex::encode(&pkt);

    let out = Command::new(exe)
        .args(["dns-audit", &hex_str, "--json"])
        .output()
        .expect("run dns-audit");
    assert!(out.status.success());

    let val: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(val["transaction_id"], 0x9999);
    assert_eq!(val["questions"][0]["risk_level"], "High");
}
