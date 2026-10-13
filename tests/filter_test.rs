// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use net_specter::filter::{
    evaluate_filter_on_capture, Direction, FilterExpr, IpMatch, IpNetwork, PortMatch, Protocol,
};
use net_specter::pcap::{build_synthetic_pcap, parse_pcap_bytes, DecodedFrame, TcpFlags};
use net_specter::pcapng::{build_synthetic_pcapng, parse_pcapng_bytes};
use std::process::Command;

fn make_dummy_frame(
    protocol: &str,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    flags: Option<TcpFlags>,
    orig_len: u32,
) -> DecodedFrame {
    let ip_version = if src_ip.contains(':') { 6 } else { 4 };
    DecodedFrame {
        index: 1,
        ts_sec: 1700000000,
        ts_subsec: 0,
        orig_len,
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        ip_version,
        ttl: 64,
        protocol: protocol.to_string(),
        src_port,
        dst_port,
        tcp_seq: Some(1000),
        tcp_ack: Some(0),
        tcp_flags: flags,
        payload: vec![0xaa; 32],
    }
}

#[test]
fn test_bpf_filter_expression_parsing() {
    // Protocol primitives
    assert_eq!(
        FilterExpr::parse("tcp").unwrap(),
        FilterExpr::Protocol(Protocol::Tcp)
    );
    assert_eq!(
        FilterExpr::parse("udp").unwrap(),
        FilterExpr::Protocol(Protocol::Udp)
    );
    assert_eq!(
        FilterExpr::parse("icmp").unwrap(),
        FilterExpr::Protocol(Protocol::Icmp)
    );
    assert_eq!(
        FilterExpr::parse("ip").unwrap(),
        FilterExpr::Protocol(Protocol::Ipv4)
    );
    assert_eq!(
        FilterExpr::parse("ip6").unwrap(),
        FilterExpr::Protocol(Protocol::Ipv6)
    );

    // Port & port ranges
    let p80 = FilterExpr::parse("port 80").unwrap();
    assert_eq!(
        p80,
        FilterExpr::Port(PortMatch {
            direction: Direction::SrcOrDst,
            start: 80,
            end: 80,
        })
    );

    let src_pr = FilterExpr::parse("src portrange 1000-2000").unwrap();
    assert_eq!(
        src_pr,
        FilterExpr::Port(PortMatch {
            direction: Direction::Src,
            start: 1000,
            end: 2000,
        })
    );

    // Host & CIDR subnets
    let host_v4 = FilterExpr::parse("host 192.168.1.5").unwrap();
    assert_eq!(
        host_v4,
        FilterExpr::Ip(IpMatch {
            direction: Direction::SrcOrDst,
            network: IpNetwork::V4 {
                net: "192.168.1.5".parse().unwrap(),
                prefix: 32,
            },
        })
    );

    let dst_net_v4 = FilterExpr::parse("dst net 10.0.0.0/8").unwrap();
    assert_eq!(
        dst_net_v4,
        FilterExpr::Ip(IpMatch {
            direction: Direction::Dst,
            network: IpNetwork::V4 {
                net: "10.0.0.0".parse().unwrap(),
                prefix: 8,
            },
        })
    );

    let src_net_v6 = FilterExpr::parse("src net 2001:db8::/32").unwrap();
    assert_eq!(
        src_net_v6,
        FilterExpr::Ip(IpMatch {
            direction: Direction::Src,
            network: IpNetwork::V6 {
                net: "2001:db8::".parse().unwrap(),
                prefix: 32,
            },
        })
    );

    // Implicit AND: "tcp port 443"
    let implicit_and = FilterExpr::parse("tcp port 443").unwrap();
    assert_eq!(
        implicit_and,
        FilterExpr::And(vec![
            FilterExpr::Protocol(Protocol::Tcp),
            FilterExpr::Port(PortMatch {
                direction: Direction::SrcOrDst,
                start: 443,
                end: 443,
            }),
        ])
    );

    // Complex logical expressions
    let complex = FilterExpr::parse("tcp and (port 80 or port 443)").unwrap();
    assert_eq!(
        complex,
        FilterExpr::And(vec![
            FilterExpr::Protocol(Protocol::Tcp),
            FilterExpr::Or(vec![
                FilterExpr::Port(PortMatch {
                    direction: Direction::SrcOrDst,
                    start: 80,
                    end: 80,
                }),
                FilterExpr::Port(PortMatch {
                    direction: Direction::SrcOrDst,
                    start: 443,
                    end: 443,
                }),
            ]),
        ])
    );

    // Negation
    let not_udp = FilterExpr::parse("not udp").unwrap();
    assert_eq!(
        not_udp,
        FilterExpr::Not(Box::new(FilterExpr::Protocol(Protocol::Udp)))
    );
}

#[test]
fn test_ipv4_and_ipv6_cidr_matching() {
    let frame_v4_local = make_dummy_frame(
        "TCP",
        "192.168.1.50",
        51234,
        "10.0.0.1",
        443,
        Some(TcpFlags {
            fin: false,
            syn: true,
            rst: false,
            psh: false,
            ack: false,
        }),
        64,
    );

    let frame_v4_ext = make_dummy_frame("TCP", "8.8.8.8", 53, "172.16.5.99", 12345, None, 128);

    let net_filter = FilterExpr::parse("src net 192.168.0.0/16").unwrap();
    assert!(net_filter.matches(&frame_v4_local));
    assert!(!net_filter.matches(&frame_v4_ext));

    let dst_net_filter = FilterExpr::parse("dst net 10.0.0.0/8").unwrap();
    assert!(dst_net_filter.matches(&frame_v4_local));
    assert!(!dst_net_filter.matches(&frame_v4_ext));

    let host_filter = FilterExpr::parse("host 8.8.8.8").unwrap();
    assert!(host_filter.matches(&frame_v4_ext));
    assert!(!host_filter.matches(&frame_v4_local));

    // IPv6 matching
    let frame_v6 = make_dummy_frame("TCP", "2001:db8:acad::1", 54321, "fe80::2", 80, None, 80);
    let v6_net_filter = FilterExpr::parse("src net 2001:db8::/32").unwrap();
    assert!(v6_net_filter.matches(&frame_v6));

    let v6_other = FilterExpr::parse("src net 2606:4700::/32").unwrap();
    assert!(!v6_other.matches(&frame_v6));
}

#[test]
fn test_port_and_port_range_matching() {
    let frame = make_dummy_frame(
        "TCP",
        "192.168.1.10",
        49152,
        "93.184.216.34",
        443,
        None,
        500,
    );

    assert!(FilterExpr::parse("port 443").unwrap().matches(&frame));
    assert!(FilterExpr::parse("src port 49152").unwrap().matches(&frame));
    assert!(FilterExpr::parse("dst port 443").unwrap().matches(&frame));
    assert!(!FilterExpr::parse("dst port 80").unwrap().matches(&frame));

    // Range matching
    assert!(FilterExpr::parse("src portrange 40000-50000")
        .unwrap()
        .matches(&frame));
    assert!(!FilterExpr::parse("src portrange 1000-2000")
        .unwrap()
        .matches(&frame));
    assert!(FilterExpr::parse("portrange 440-445")
        .unwrap()
        .matches(&frame));
}

#[test]
fn test_tcp_flags_matching() {
    let syn_frame = make_dummy_frame(
        "TCP",
        "10.0.0.1",
        12345,
        "10.0.0.2",
        80,
        Some(TcpFlags {
            fin: false,
            syn: true,
            rst: false,
            psh: false,
            ack: false,
        }),
        60,
    );

    let syn_ack_frame = make_dummy_frame(
        "TCP",
        "10.0.0.2",
        80,
        "10.0.0.1",
        12345,
        Some(TcpFlags {
            fin: false,
            syn: true,
            rst: false,
            psh: false,
            ack: true,
        }),
        60,
    );

    let fin_frame = make_dummy_frame(
        "TCP",
        "10.0.0.1",
        12345,
        "10.0.0.2",
        80,
        Some(TcpFlags {
            fin: true,
            syn: false,
            rst: false,
            psh: false,
            ack: true,
        }),
        54,
    );

    // BPF syntax: tcp[tcpflags] & tcp-syn != 0
    let bpf_syn = FilterExpr::parse("tcp[tcpflags] & tcp-syn != 0").unwrap();
    assert!(bpf_syn.matches(&syn_frame));
    assert!(bpf_syn.matches(&syn_ack_frame));
    assert!(!bpf_syn.matches(&fin_frame));

    // SYN without ACK: "syn and not ack"
    let pure_syn = FilterExpr::parse("syn and not ack").unwrap();
    assert!(pure_syn.matches(&syn_frame));
    assert!(!pure_syn.matches(&syn_ack_frame));

    // tcpflags syn,ack (requires both SYN and ACK set)
    let syn_ack_filter = FilterExpr::parse("tcpflags syn,ack").unwrap();
    assert!(!syn_ack_filter.matches(&syn_frame));
    assert!(syn_ack_filter.matches(&syn_ack_frame));
    assert!(!syn_ack_filter.matches(&fin_frame));

    // Raw hex: tcp[13] & 0x02 != 0
    let bpf_13 = FilterExpr::parse("tcp[13] & 0x02 != 0").unwrap();
    assert!(bpf_13.matches(&syn_frame));
    assert!(bpf_13.matches(&syn_ack_frame));
    assert!(!bpf_13.matches(&fin_frame));
}

#[test]
fn test_packet_length_filters() {
    let frame_small = make_dummy_frame("UDP", "1.1.1.1", 53, "1.1.1.2", 53, None, 60);
    let frame_large = make_dummy_frame("TCP", "1.1.1.1", 80, "1.1.1.2", 80, None, 1500);

    assert!(FilterExpr::parse("len < 100")
        .unwrap()
        .matches(&frame_small));
    assert!(!FilterExpr::parse("len < 100")
        .unwrap()
        .matches(&frame_large));

    assert!(FilterExpr::parse("len >= 1500")
        .unwrap()
        .matches(&frame_large));
    assert!(FilterExpr::parse("len == 60")
        .unwrap()
        .matches(&frame_small));
    assert!(FilterExpr::parse("len != 60")
        .unwrap()
        .matches(&frame_large));
}

#[test]
fn test_filter_against_synthetic_pcap_capture() {
    let pcap_bytes = build_synthetic_pcap();
    let report = parse_pcap_bytes(&pcap_bytes).unwrap();
    assert!(report.total_packets >= 2);

    // Filter TCP port 443
    let tcp_report = evaluate_filter_on_capture(&pcap_bytes, "tcp port 443").unwrap();
    assert_eq!(tcp_report.matched_packets, 1);
    assert_eq!(tcp_report.tcp_matched, 1);
    assert_eq!(tcp_report.udp_matched, 0);
    assert_eq!(tcp_report.frames[0].protocol, "TCP");
    assert_eq!(tcp_report.frames[0].dst_port, 443);

    // Filter UDP port 53 (2 DNS queries in synthetic pcap)
    let udp_report = evaluate_filter_on_capture(&pcap_bytes, "udp port 53").unwrap();
    assert_eq!(udp_report.matched_packets, 2);
    assert_eq!(udp_report.tcp_matched, 0);
    assert_eq!(udp_report.udp_matched, 2);
    assert_eq!(udp_report.frames[0].protocol, "UDP");
    assert_eq!(udp_report.frames[0].dst_port, 53);

    // Filter ICMP (none present)
    let icmp_report = evaluate_filter_on_capture(&pcap_bytes, "icmp").unwrap();
    assert_eq!(icmp_report.matched_packets, 0);

    // Filter net 10.0.0.0/8 (all 3 synthetic packets originate from 10.0.0.15)
    let net_report = evaluate_filter_on_capture(&pcap_bytes, "src net 10.0.0.0/8").unwrap();
    assert_eq!(net_report.matched_packets, 3);

    let no_match = evaluate_filter_on_capture(&pcap_bytes, "src net 192.168.0.0/16").unwrap();
    assert_eq!(no_match.matched_packets, 0);
}

#[test]
fn test_filter_against_synthetic_pcapng_capture() {
    let pcapng_bytes = build_synthetic_pcapng();
    let pcapng = parse_pcapng_bytes(&pcapng_bytes).unwrap();
    assert!(pcapng.total_packets >= 2);

    let tcp_res = evaluate_filter_on_capture(&pcapng_bytes, "tcp").unwrap();
    assert!(tcp_res.tcp_matched >= 1);
    assert_eq!(tcp_res.udp_matched, 0);

    let udp_res = evaluate_filter_on_capture(&pcapng_bytes, "udp").unwrap();
    assert!(udp_res.udp_matched >= 1);
    assert_eq!(udp_res.tcp_matched, 0);
}

#[test]
fn test_adversarial_and_invalid_filters() {
    // Empty expression evaluates to True (all match)
    let empty = FilterExpr::parse("   ").unwrap();
    assert_eq!(empty, FilterExpr::True);

    // Unbalanced parentheses
    assert!(FilterExpr::parse("(tcp or udp").is_err());
    assert!(FilterExpr::parse("tcp and )").is_err());

    // Invalid CIDR prefix
    assert!(FilterExpr::parse("net 192.168.1.1/33").is_err());
    assert!(FilterExpr::parse("net 2001:db8::/129").is_err());

    // Incomplete directions
    assert!(FilterExpr::parse("src").is_err());
    assert!(FilterExpr::parse("dst").is_err());

    // Missing operator in length
    assert!(FilterExpr::parse("len 100").is_err());
}

#[test]
fn test_cli_filter_and_inspect_pcap_flag() {
    let temp_dir = std::env::temp_dir();
    let pcap_path = temp_dir.join("test_filter_cli.pcap");
    let pcap_bytes = build_synthetic_pcap();
    std::fs::write(&pcap_path, pcap_bytes).unwrap();

    let exe_path = env!("CARGO_BIN_EXE_nspecter");

    // Test 1: nspecter filter <file> "tcp port 443" --json
    let output1 = Command::new(exe_path)
        .arg("filter")
        .arg(&pcap_path)
        .arg("tcp port 443")
        .arg("--json")
        .output()
        .expect("Failed to execute nspecter filter");

    assert!(output1.status.success());
    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    let json1: serde_json::Value = serde_json::from_str(&stdout1).expect("Valid JSON output");
    assert_eq!(json1["matched_packets"], 1);
    assert_eq!(json1["tcp_matched"], 1);

    // Test 2: nspecter inspect-pcap <file> --filter "udp port 53" --json
    let output2 = Command::new(exe_path)
        .arg("inspect-pcap")
        .arg(&pcap_path)
        .arg("--filter")
        .arg("udp port 53")
        .arg("--json")
        .output()
        .expect("Failed to execute nspecter inspect-pcap");

    assert!(output2.status.success());
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    let json2: serde_json::Value = serde_json::from_str(&stdout2).expect("Valid JSON output");
    assert_eq!(json2["total_packets"], 2);
    assert_eq!(json2["udp_packets"], 2);
    assert_eq!(json2["tcp_packets"], 0);

    let _ = std::fs::remove_file(pcap_path);
}
