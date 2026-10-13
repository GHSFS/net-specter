// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use net_specter::beacon::{
    audit_beacon_bytes, classify_beacon, compute_delta_ts, compute_mean, compute_median,
    compute_scores, compute_spectrogram, compute_variance, BeaconAuditConfig, BeaconVerdict,
};
use std::process::Command;

fn make_ipv4_tcp_frame(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(54);
    // Ethernet II header (14 bytes)
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    // IPv4 header (20 bytes)
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&40u16.to_be_bytes()); // total len = 40 (20 IP + 20 TCP)
    frame.extend_from_slice(&0xbeefu16.to_be_bytes());
    frame.extend_from_slice(&0x4000u16.to_be_bytes());
    frame.push(64);
    frame.push(6); // TCP
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);

    // TCP header (20 bytes)
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&100u32.to_be_bytes()); // seq
    frame.extend_from_slice(&0u32.to_be_bytes()); // ack
    frame.push(0x50); // data offset 5
    frame.push(0x02); // SYN
    frame.extend_from_slice(&8192u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame
}

fn build_test_pcap(packet_records: &[(&[u8], u32, u32)]) -> Vec<u8> {
    let mut pcap = Vec::new();
    // Global Header (24 bytes)
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // microsecond magic
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET

    for &(pkt, ts_sec, ts_usec) in packet_records {
        let len = pkt.len() as u32;
        pcap.extend_from_slice(&ts_sec.to_le_bytes());
        pcap.extend_from_slice(&ts_usec.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(pkt);
    }
    pcap
}

#[test]
fn test_delta_and_statistical_computations() {
    let empty: [f64; 0] = [];
    assert!(compute_delta_ts(&empty).is_empty());
    assert_eq!(compute_mean(&empty), 0.0);
    assert_eq!(compute_median(&empty), 0.0);
    assert_eq!(compute_variance(&empty, 0.0), 0.0);

    let single = [10.0];
    assert!(compute_delta_ts(&single).is_empty());
    assert_eq!(compute_mean(&single), 10.0);
    assert_eq!(compute_median(&single), 10.0);
    assert_eq!(compute_variance(&single, 10.0), 0.0);

    let timestamps = [10.0, 15.0, 20.0, 25.0, 30.0];
    let deltas = compute_delta_ts(&timestamps);
    assert_eq!(deltas, vec![5.0, 5.0, 5.0, 5.0]);

    let mean = compute_mean(&deltas);
    assert_eq!(mean, 5.0);
    assert_eq!(compute_median(&deltas), 5.0);
    assert_eq!(compute_variance(&deltas, mean), 0.0);

    // Unsorted timestamps must be ordered correctly
    let unsorted = [25.0, 10.0, 30.0, 15.0, 20.0];
    assert_eq!(compute_delta_ts(&unsorted), vec![5.0, 5.0, 5.0, 5.0]);
}

#[test]
fn test_spectrogram_dominant_frequency_and_bins() {
    let fixed_deltas = [10.0, 10.0, 10.0, 10.0];
    let spec = compute_spectrogram(&fixed_deltas);
    assert!((spec.dominant_interval - 10.0).abs() < 1e-4);
    assert!((spec.dominant_freq_hz - 0.1).abs() < 1e-4);
    assert!((spec.peak_power_ratio - 1.0).abs() < 1e-4);
    assert_eq!(spec.bins.len(), 1);

    // Multi-bin varied deltas
    let varied_deltas = [1.0, 1.1, 1.2, 5.0, 5.2, 10.0];
    let spec_var = compute_spectrogram(&varied_deltas);
    assert!(spec_var.dominant_interval > 0.0);
    assert!(spec_var.dominant_freq_hz > 0.0);
    assert!(!spec_var.bins.is_empty());
}

#[test]
fn test_beacon_verdict_classification() {
    let perfect_deltas = [15.0, 15.0, 15.0, 15.0, 15.0];
    let spec_perf = compute_spectrogram(&perfect_deltas);
    let (per_perf, reg_perf) = compute_scores(&perfect_deltas, 15.0, 0.0, &spec_perf);
    assert!(per_perf >= 0.90);
    assert!(reg_perf >= 0.90);

    let v_perf = classify_beacon(reg_perf, 0.0, 6, 4, 0.70);
    assert_eq!(v_perf, BeaconVerdict::HighConfidenceBeacon);

    // Jittered beacon (20% jitter)
    let v_jit = classify_beacon(0.65, 20.0, 6, 4, 0.70);
    assert_eq!(v_jit, BeaconVerdict::JitteredBeacon);

    // Suspect interval
    let v_susp = classify_beacon(0.40, 60.0, 6, 4, 0.70);
    assert_eq!(v_susp, BeaconVerdict::SuspectInterval);

    // Benign / Poisson traffic
    let v_ben = classify_beacon(0.15, 120.0, 6, 4, 0.70);
    assert_eq!(v_ben, BeaconVerdict::Benign);

    // Under minimum events threshold
    let v_under = classify_beacon(0.99, 0.0, 3, 4, 0.70);
    assert_eq!(v_under, BeaconVerdict::Benign);
}

#[test]
fn test_synthetic_pcap_multi_flow_beacon_audit() {
    let c2_pkt = make_ipv4_tcp_frame([192, 168, 1, 100], [45, 33, 32, 156], 49152, 443);
    let benign_pkt = make_ipv4_tcp_frame([192, 168, 1, 100], [142, 250, 190, 46], 49153, 80);

    let mut records = Vec::new();
    // Flow 1: High confidence beacon every 5.0 seconds (6 packets)
    for i in 0..6 {
        records.push((c2_pkt.as_slice(), 1_700_000_000 + i * 5, 0));
    }

    // Flow 2: Benign bursty traffic with irregular timing
    let irregular_offsets = [1, 2, 85, 90, 250];
    for &sec in &irregular_offsets {
        records.push((benign_pkt.as_slice(), 1_700_000_000 + sec, 500_000));
    }

    let pcap_bytes = build_test_pcap(&records);
    let config = BeaconAuditConfig {
        min_events: 4,
        threshold: 0.70,
    };
    let report = audit_beacon_bytes(&pcap_bytes, config).expect("audit synthetic PCAP");

    assert_eq!(report.total_flows, 2);
    assert_eq!(report.analyzed_flows, 2);
    assert_eq!(report.high_confidence_count, 1);
    assert_eq!(report.benign_count, 1);

    let c2_flow = &report.flows[0];
    assert_eq!(c2_flow.src_ip, "192.168.1.100");
    assert_eq!(c2_flow.dst_ip, "45.33.32.156");
    assert_eq!(c2_flow.dst_port, 443);
    assert_eq!(c2_flow.verdict, BeaconVerdict::HighConfidenceBeacon);
    assert!(c2_flow.regularity_score >= 0.85);
    assert!(c2_flow.jitter_percent <= 5.0);
    assert!((c2_flow.mean - 5.0).abs() < 1e-3);
}

#[test]
fn test_synthetic_pcapng_beacon_audit() {
    // Construct simple PCAPNG with SHB, IDB, and 5 EPB records (10.0s interval)
    let c2_pkt = make_ipv4_tcp_frame([10, 0, 0, 5], [198, 51, 100, 77], 52000, 8443);
    let mut pcapng = Vec::new();

    // SHB (28 bytes)
    pcapng.extend_from_slice(&0x0a0d0d0au32.to_le_bytes()); // SHB type
    pcapng.extend_from_slice(&28u32.to_le_bytes()); // total len
    pcapng.extend_from_slice(&0x1a2e3b4cu32.to_le_bytes()); // magic
    pcapng.extend_from_slice(&1u16.to_le_bytes()); // major
    pcapng.extend_from_slice(&0u16.to_le_bytes()); // minor
    pcapng.extend_from_slice(&0xFFFFFFFFFFFFFFFFu64.to_le_bytes()); // section len unknown
    pcapng.extend_from_slice(&28u32.to_le_bytes()); // total len

    // IDB (20 bytes)
    pcapng.extend_from_slice(&0x00000001u32.to_le_bytes()); // IDB type
    pcapng.extend_from_slice(&20u32.to_le_bytes()); // total len
    pcapng.extend_from_slice(&1u16.to_le_bytes()); // linktype Ethernet
    pcapng.extend_from_slice(&0u16.to_le_bytes()); // reserved
    pcapng.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    pcapng.extend_from_slice(&20u32.to_le_bytes()); // total len

    // EPBs (packet len 54 + 32 header/trailer = 88 rounded up)
    let pkt_len = c2_pkt.len() as u32;
    let pad_len = (4 - (pkt_len % 4)) % 4;
    let epb_total_len = 32 + pkt_len + pad_len;

    for i in 0..5 {
        let ts_micros = (1_700_000_000u64 + i as u64 * 10) * 1_000_000;
        let ts_high = (ts_micros >> 32) as u32;
        let ts_low = (ts_micros & 0xffffffff) as u32;

        pcapng.extend_from_slice(&0x00000006u32.to_le_bytes()); // EPB type
        pcapng.extend_from_slice(&epb_total_len.to_le_bytes());
        pcapng.extend_from_slice(&0u32.to_le_bytes()); // iface 0
        pcapng.extend_from_slice(&ts_high.to_le_bytes());
        pcapng.extend_from_slice(&ts_low.to_le_bytes());
        pcapng.extend_from_slice(&pkt_len.to_le_bytes());
        pcapng.extend_from_slice(&pkt_len.to_le_bytes());
        pcapng.extend_from_slice(&c2_pkt);
        if pad_len > 0 {
            pcapng.extend_from_slice(&[0u8; 4][..pad_len as usize]);
        }
        pcapng.extend_from_slice(&epb_total_len.to_le_bytes());
    }

    let config = BeaconAuditConfig {
        min_events: 4,
        threshold: 0.70,
    };
    let report = audit_beacon_bytes(&pcapng, config).expect("audit PCAPNG capture");
    assert_eq!(report.total_flows, 1);
    assert_eq!(report.high_confidence_count, 1);
    assert_eq!(report.flows[0].verdict, BeaconVerdict::HighConfidenceBeacon);
    assert!((report.flows[0].mean - 10.0).abs() < 1e-3);
}

#[test]
fn test_adversarial_and_empty_buffer_handling() {
    let empty: [u8; 0] = [];
    let config = BeaconAuditConfig::default();
    let rep = audit_beacon_bytes(&empty, config).expect("empty buffer returns empty report");
    assert_eq!(rep.total_flows, 0);
    assert!(rep.flows.is_empty());

    let malformed = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
    assert!(audit_beacon_bytes(&malformed, config).is_err());
}

#[test]
fn test_cli_beacon_audit_subcommand_execution() {
    let exe = env!("CARGO_BIN_EXE_nspecter");
    let c2_pkt = make_ipv4_tcp_frame([10, 10, 1, 2], [10, 10, 2, 99], 33333, 8080);
    let mut records = Vec::new();
    for i in 0..5 {
        records.push((c2_pkt.as_slice(), 1_700_000_100 + i * 2, 0));
    }
    let pcap = build_test_pcap(&records);
    let temp_file = std::env::temp_dir().join("nspecter_beacon_test.pcap");
    std::fs::write(&temp_file, &pcap).expect("write temp pcap");

    let out = Command::new(exe)
        .args([
            "beacon-audit",
            temp_file.to_str().unwrap(),
            "--min-events",
            "4",
            "--json",
        ])
        .output()
        .expect("run beacon-audit command");
    assert!(out.status.success());

    let val: serde_json::Value = serde_json::from_slice(&out.stdout).expect("parse json output");
    assert_eq!(val["total_flows"], 1);
    assert_eq!(val["high_confidence_count"], 1);
    assert_eq!(val["flows"][0]["verdict"], "HighConfidenceBeacon");
    assert_eq!(val["flows"][0]["event_count"], 5);

    let _ = std::fs::remove_file(&temp_file);
}
