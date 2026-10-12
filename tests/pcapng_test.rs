// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use md5::{Digest as Md5Digest, Md5};
use net_specter::pcap::LINKTYPE_ETHERNET;
use net_specter::pcapng::{
    build_synthetic_pcapng, is_pcapng, parse_pcapng_bytes, reconstruct_nanos, BLOCK_TYPE_IDB,
    BLOCK_TYPE_ISB, BLOCK_TYPE_SHB, BLOCK_TYPE_SPB, BOM_LITTLE_ENDIAN,
};
use sha2::Sha256;
use std::process::Command;

#[test]
fn test_synthetic_pcapng_generation_and_decoding() {
    let pcapng_bytes = build_synthetic_pcapng();
    assert!(
        is_pcapng(&pcapng_bytes),
        "Synthetic buffer must be identified as PCAPNG"
    );

    let report = parse_pcapng_bytes(&pcapng_bytes).expect("synthetic PCAPNG must parse cleanly");

    // Section Header Block
    assert_eq!(report.section.version_major, 1);
    assert_eq!(report.section.version_minor, 0);
    assert_eq!(report.section.section_length, -1);
    assert!(!report.section.big_endian);
    assert_eq!(report.section.hardware.as_deref(), Some("x86_64"));
    assert_eq!(report.section.os.as_deref(), Some("Rust Forensics Engine"));
    assert_eq!(
        report.section.user_app.as_deref(),
        Some("net-specter 0.2.0")
    );
    assert_eq!(
        report.section.comment.as_deref(),
        Some("Synthetic PCAPNG capture with nanosecond precision")
    );

    // Interface Description Block
    assert_eq!(report.interfaces.len(), 1);
    let iface = &report.interfaces[0];
    assert_eq!(iface.linktype, LINKTYPE_ETHERNET);
    assert_eq!(iface.snaplen, 65535);
    assert_eq!(iface.ts_resol, 9);
    assert_eq!(iface.name.as_deref(), Some("eth0"));
    assert_eq!(
        iface.description.as_deref(),
        Some("Synthetic Gigabit Forensics Interface")
    );

    // Summary counts
    assert_eq!(report.total_packets, 3);
    assert_eq!(report.tcp_packets, 1);
    assert_eq!(report.udp_packets, 2);
    assert_eq!(report.frames.len(), 3);
}

#[test]
fn test_nanosecond_precision_timestamping() {
    // 1. Reconstruct nanos helper verification
    assert_eq!(reconstruct_nanos(0, 500, 9), 500);
    assert_eq!(reconstruct_nanos(0, 500, 6), 500_000);
    assert_eq!(reconstruct_nanos(0, 500, 3), 500_000_000);
    assert_eq!(reconstruct_nanos(0, 5, 0), 5_000_000_000);

    let high = (1_700_000_000_125_000_000u64 >> 32) as u32;
    let low = (1_700_000_000_125_000_000u64 & 0xFFFF_FFFF) as u32;
    assert_eq!(
        reconstruct_nanos(high, low, 9),
        1_700_000_000_125_000_000u64
    );

    // 2. Inspection of parsed synthetic EPB frames
    let pcapng_bytes = build_synthetic_pcapng();
    let report = parse_pcapng_bytes(&pcapng_bytes).expect("parse PCAPNG");

    assert_eq!(report.frames[0].ts_sec, 1_700_000_000);
    assert_eq!(report.frames[0].ts_subsec, 0);

    assert_eq!(report.frames[1].ts_sec, 1_700_000_001);
    assert_eq!(report.frames[1].ts_subsec, 125_000_000);

    assert_eq!(report.frames[2].ts_sec, 1_700_000_002);
    assert_eq!(report.frames[2].ts_subsec, 250_000_000);
}

#[test]
fn test_tls_ja3_and_dns_extraction_from_pcapng() {
    let pcapng_bytes = build_synthetic_pcapng();
    let report = parse_pcapng_bytes(&pcapng_bytes).expect("parse PCAPNG");

    // TLS extraction
    assert_eq!(report.tls_handshakes.len(), 1);
    let tls = &report.tls_handshakes[0];
    assert_eq!(tls.sni.as_deref(), Some("api.telemetry.example.org"));
    let expected_ja3 = "771,4865-4866-4867-49195,0-10-11-16-43,29-23,0";
    assert_eq!(tls.ja3_string, expected_ja3);

    let mut md5_hasher = Md5::new();
    md5_hasher.update(expected_ja3.as_bytes());
    assert_eq!(tls.ja3_md5, hex::encode(md5_hasher.finalize()));

    let mut sha_hasher = Sha256::new();
    sha_hasher.update(expected_ja3.as_bytes());
    assert_eq!(tls.ja3_sha256, hex::encode(sha_hasher.finalize()));

    // DNS extraction
    assert_eq!(report.dns_messages.len(), 2);
    let dns_benign = &report.dns_messages[0];
    assert_eq!(dns_benign.questions[0].qname, "api.telemetry.example.org");
    assert_eq!(dns_benign.questions[0].qtype_name, "A");

    let dns_covert = &report.dns_messages[1];
    assert_eq!(dns_covert.questions[0].qtype_name, "TXT");
    assert!(dns_covert.questions[0].subdomain_entropy > 3.5);
    assert!(dns_covert.questions[0].risk_score > 30);
}

#[test]
fn test_simple_packet_block_spb_decoding() {
    let mut data = Vec::new();

    // 1. SHB
    let mut shb_body = Vec::new();
    shb_body.extend_from_slice(&BOM_LITTLE_ENDIAN);
    shb_body.extend_from_slice(&1u16.to_le_bytes());
    shb_body.extend_from_slice(&0u16.to_le_bytes());
    shb_body.extend_from_slice(&(-1i64).to_le_bytes());
    let shb_len = (12 + shb_body.len()) as u32;
    data.extend_from_slice(&BLOCK_TYPE_SHB.to_le_bytes());
    data.extend_from_slice(&shb_len.to_le_bytes());
    data.extend_from_slice(&shb_body);
    data.extend_from_slice(&shb_len.to_le_bytes());

    // 2. IDB
    let mut idb_body = Vec::new();
    idb_body.extend_from_slice(&1u16.to_le_bytes()); // linktype Ethernet
    idb_body.extend_from_slice(&0u16.to_le_bytes());
    idb_body.extend_from_slice(&65535u32.to_le_bytes());
    let idb_len = (12 + idb_body.len()) as u32;
    data.extend_from_slice(&BLOCK_TYPE_IDB.to_le_bytes());
    data.extend_from_slice(&idb_len.to_le_bytes());
    data.extend_from_slice(&idb_body);
    data.extend_from_slice(&idb_len.to_le_bytes());

    // 3. SPB with synthetic DNS packet
    let packet = &net_specter::pcap::synthetic_test_packets()[1];
    let pad = (4 - (packet.len() % 4)) % 4;
    let spb_body_len = 4 + packet.len() + pad;
    let spb_total_len = (12 + spb_body_len) as u32;

    data.extend_from_slice(&BLOCK_TYPE_SPB.to_le_bytes());
    data.extend_from_slice(&spb_total_len.to_le_bytes());
    data.extend_from_slice(&(packet.len() as u32).to_le_bytes()); // orig_len
    data.extend_from_slice(packet);
    data.extend_from_slice(&vec![0u8; pad]);
    data.extend_from_slice(&spb_total_len.to_le_bytes());

    let report = parse_pcapng_bytes(&data).expect("parse PCAPNG with SPB");
    assert_eq!(report.total_packets, 1);
    assert_eq!(report.udp_packets, 1);
    assert_eq!(report.frames[0].ts_sec, 0);
    assert_eq!(report.frames[0].ts_subsec, 0);
    assert_eq!(report.dns_messages.len(), 1);
}

#[test]
fn test_graceful_unknown_block_skipping() {
    let mut data = Vec::new();

    // 1. SHB
    let mut shb_body = Vec::new();
    shb_body.extend_from_slice(&BOM_LITTLE_ENDIAN);
    shb_body.extend_from_slice(&1u16.to_le_bytes());
    shb_body.extend_from_slice(&0u16.to_le_bytes());
    shb_body.extend_from_slice(&(-1i64).to_le_bytes());
    let shb_len = (12 + shb_body.len()) as u32;
    data.extend_from_slice(&BLOCK_TYPE_SHB.to_le_bytes());
    data.extend_from_slice(&shb_len.to_le_bytes());
    data.extend_from_slice(&shb_body);
    data.extend_from_slice(&shb_len.to_le_bytes());

    // 2. IDB
    let mut idb_body = Vec::new();
    idb_body.extend_from_slice(&1u16.to_le_bytes());
    idb_body.extend_from_slice(&0u16.to_le_bytes());
    idb_body.extend_from_slice(&65535u32.to_le_bytes());
    let idb_len = (12 + idb_body.len()) as u32;
    data.extend_from_slice(&BLOCK_TYPE_IDB.to_le_bytes());
    data.extend_from_slice(&idb_len.to_le_bytes());
    data.extend_from_slice(&idb_body);
    data.extend_from_slice(&idb_len.to_le_bytes());

    // 3. ISB (Interface Statistics Block 0x00000005) - should be skipped
    let isb_total_len = 24u32;
    data.extend_from_slice(&BLOCK_TYPE_ISB.to_le_bytes());
    data.extend_from_slice(&isb_total_len.to_le_bytes());
    data.extend_from_slice(&[0u8; 12]); // isb body
    data.extend_from_slice(&isb_total_len.to_le_bytes());

    // 4. Custom block 0x00000BAD - should be skipped
    let custom_len = 16u32;
    data.extend_from_slice(&0x0000_0BADu32.to_le_bytes());
    data.extend_from_slice(&custom_len.to_le_bytes());
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    data.extend_from_slice(&custom_len.to_le_bytes());

    let report = parse_pcapng_bytes(&data).expect("skipped blocks successfully");
    assert_eq!(report.total_packets, 0);
    assert_eq!(report.interfaces.len(), 1);
}

#[test]
fn test_malformed_block_length_and_bounds_rejection() {
    // 1. Buffer too short
    assert!(parse_pcapng_bytes(&[]).is_err());
    assert!(parse_pcapng_bytes(&[0x0A, 0x0D, 0x0D, 0x0A]).is_err());
    assert!(!is_pcapng(&[0x01, 0x02]));

    // 2. Non-PCAPNG magic
    assert!(parse_pcapng_bytes(&[0xFF; 32]).is_err());

    // 3. Invalid Byte Order Magic
    let mut bad_bom = build_synthetic_pcapng();
    bad_bom[8..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    assert!(parse_pcapng_bytes(&bad_bom).is_err());

    // 4. Block length not multiple of 4
    let mut unaligned = build_synthetic_pcapng();
    unaligned[4..8].copy_from_slice(&29u32.to_le_bytes());
    assert!(parse_pcapng_bytes(&unaligned).is_err());

    // 5. Block length smaller than 12
    let mut too_short = build_synthetic_pcapng();
    too_short[4..8].copy_from_slice(&8u32.to_le_bytes());
    assert!(parse_pcapng_bytes(&too_short).is_err());

    // 6. Block length exceeds buffer
    let mut oversized = build_synthetic_pcapng();
    oversized[4..8].copy_from_slice(&999_999u32.to_le_bytes());
    assert!(parse_pcapng_bytes(&oversized).is_err());

    // 7. Trailing length mismatch
    let mut mismatch = build_synthetic_pcapng();
    let end_idx = mismatch.len() - 4;
    mismatch[end_idx..].copy_from_slice(&999u32.to_le_bytes());
    assert!(parse_pcapng_bytes(&mismatch).is_err());
}

#[test]
fn test_cli_commands_with_pcapng() {
    let exe = env!("CARGO_BIN_EXE_nspecter");
    let temp_pcapng = std::env::temp_dir().join("net_specter_test_capture.pcapng");

    // 1. synth-pcap --pcapng --json
    let synth_out = Command::new(exe)
        .args([
            "synth-pcap",
            temp_pcapng.to_str().unwrap(),
            "--pcapng",
            "--json",
        ])
        .output()
        .expect("run synth-pcap --pcapng");
    assert!(synth_out.status.success());
    let synth_json: serde_json::Value =
        serde_json::from_slice(&synth_out.stdout).expect("valid JSON from synth-pcap");
    assert_eq!(synth_json["format"], "pcapng");
    assert_eq!(synth_json["packets"], 3);

    // 2. inspect-pcap --json
    let inspect_out = Command::new(exe)
        .args(["inspect-pcap", temp_pcapng.to_str().unwrap(), "--json"])
        .output()
        .expect("run inspect-pcap");
    assert!(inspect_out.status.success());
    let inspect_json: serde_json::Value =
        serde_json::from_slice(&inspect_out.stdout).expect("valid JSON from inspect-pcap");
    assert_eq!(inspect_json["total_packets"], 3);
    assert_eq!(inspect_json["section"]["version_major"], 1);

    // 3. ja3 --json
    let ja3_out = Command::new(exe)
        .args(["ja3", temp_pcapng.to_str().unwrap(), "--json"])
        .output()
        .expect("run ja3");
    assert!(ja3_out.status.success());
    let ja3_json: serde_json::Value =
        serde_json::from_slice(&ja3_out.stdout).expect("valid JSON from ja3");
    assert_eq!(ja3_json["sni"], "api.telemetry.example.org");
    assert_eq!(
        ja3_json["ja3_string"],
        "771,4865-4866-4867-49195,0-10-11-16-43,29-23,0"
    );

    // 4. dns-audit --json
    let dns_out = Command::new(exe)
        .args(["dns-audit", temp_pcapng.to_str().unwrap(), "--json"])
        .output()
        .expect("run dns-audit");
    assert!(dns_out.status.success());
    let dns_json: serde_json::Value =
        serde_json::from_slice(&dns_out.stdout).expect("valid JSON from dns-audit");
    assert!(dns_json.as_array().map(|a| a.len()).unwrap_or(0) >= 2);

    let _ = std::fs::remove_file(&temp_pcapng);
}

#[test]
fn test_hardened_bounds_and_overflow_protection() {
    // 1. Extreme ts_resol values must not overflow or panic
    assert_eq!(reconstruct_nanos(0, 100, 20), 0);
    assert_eq!(reconstruct_nanos(0, 100, 50), 0);
    assert_eq!(reconstruct_nanos(0, 100, 127), 0);
    assert_eq!(reconstruct_nanos(0, 100, 255), 100_000); // 0x80 bit set fallback

    // 2. EPB with malicious oversized caplen exceeding block capacity must be cleanly rejected
    let mut bad_epb = build_synthetic_pcapng();
    // In synthetic PCAPNG, find the EPB (block type 0x00000006)
    // The EPB starts around offset 116 in synthetic_pcapng
    let mut epb_offset = None;
    for i in (0..bad_epb.len() - 12).step_by(4) {
        let btype =
            u32::from_le_bytes([bad_epb[i], bad_epb[i + 1], bad_epb[i + 2], bad_epb[i + 3]]);
        if btype == 0x0000_0006 {
            epb_offset = Some(i);
            break;
        }
    }
    let epb_pos = epb_offset.expect("must find EPB in synthetic capture");
    // Overwrite caplen (offset + 20 in EPB) with huge value
    bad_epb[epb_pos + 20..epb_pos + 24].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
    assert!(parse_pcapng_bytes(&bad_epb).is_err());
}
