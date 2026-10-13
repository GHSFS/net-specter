// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use md5::Digest;
use net_specter::ssh_hassh::{
    audit_ssh_bytes, build_synthetic_ssh_kexinit, build_synthetic_ssh_pcap, compute_hassh,
    parse_ssh_banner, parse_ssh_kexinit, SshAuditReport, SshKexInit, SshRole,
};
use std::process::Command;

#[test]
fn test_rfc4253_banner_parsing_openssh() {
    let raw = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
    let (banner, consumed) = parse_ssh_banner(raw).expect("banner should parse");
    assert_eq!(consumed, raw.len());
    assert_eq!(banner.proto_version, "2.0");
    assert_eq!(banner.software_version, "OpenSSH_8.9p1");
    assert_eq!(banner.comments, Some("Ubuntu-3ubuntu0.1".to_string()));
    assert_eq!(banner.raw, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1");
}

#[test]
fn test_rfc4253_banner_parsing_putty_and_dropbear() {
    // PuTTY banner without comments
    let putty = b"SSH-2.0-PuTTY_Release_0.78\r\n";
    let (banner, consumed) = parse_ssh_banner(putty).expect("putty banner");
    assert_eq!(consumed, putty.len());
    assert_eq!(banner.proto_version, "2.0");
    assert_eq!(banner.software_version, "PuTTY_Release_0.78");
    assert_eq!(banner.comments, None);

    // Dropbear with newline only
    let dropbear = b"SSH-2.0-dropbear_2022.82\n";
    let (banner2, consumed2) = parse_ssh_banner(dropbear).expect("dropbear banner");
    assert_eq!(consumed2, dropbear.len());
    assert_eq!(banner2.software_version, "dropbear_2022.82");
    assert_eq!(banner2.comments, None);
}

#[test]
fn test_rfc4253_banner_preceding_lines() {
    let payload =
        b"Welcome to the secure gateway\r\nAuthorized personnel only\r\nSSH-2.0-OpenSSH_9.3p1\r\n";
    let (banner, consumed) = parse_ssh_banner(payload).expect("banner after headers");
    assert_eq!(consumed, payload.len());
    assert_eq!(banner.software_version, "OpenSSH_9.3p1");
    assert_eq!(banner.comments, None);
}

#[test]
fn test_exact_salesforce_hassh_client() {
    let kex = SshKexInit {
        packet_length: 100,
        padding_length: 8,
        cookie_hex: "0102030405060708090a0b0c0d0e0f10".to_string(),
        kex_algorithms: "curve25519-sha256,ecdh-sha2-nistp256".to_string(),
        server_host_key_algorithms: "ssh-ed25519,rsa-sha2-512".to_string(),
        encryption_algorithms_client_to_server: "aes128-ctr,aes256-ctr".to_string(),
        encryption_algorithms_server_to_client: "aes128-ctr,aes256-ctr".to_string(),
        mac_algorithms_client_to_server: "hmac-sha2-256,hmac-sha2-512".to_string(),
        mac_algorithms_server_to_client: "hmac-sha2-256,hmac-sha2-512".to_string(),
        compression_algorithms_client_to_server: "none,zlib".to_string(),
        compression_algorithms_server_to_client: "none,zlib".to_string(),
        languages_client_to_server: String::new(),
        languages_server_to_client: String::new(),
        first_kex_packet_follows: false,
    };

    let (raw, md5, sha256) = compute_hassh(&kex, SshRole::Client);
    let expected_raw = "curve25519-sha256,ecdh-sha2-nistp256;aes128-ctr,aes256-ctr;hmac-sha2-256,hmac-sha2-512;none,zlib";
    assert_eq!(raw, expected_raw);
    assert_eq!(md5.len(), 32);
    assert_eq!(sha256.len(), 64);

    // Verify deterministic MD5 & SHA-256 digests
    let expected_md5 = hex::encode(md5::Md5::digest(expected_raw.as_bytes()));
    assert_eq!(md5, expected_md5);
}

#[test]
fn test_exact_salesforce_hassh_server() {
    let kex = SshKexInit {
        packet_length: 100,
        padding_length: 8,
        cookie_hex: "0102030405060708090a0b0c0d0e0f10".to_string(),
        kex_algorithms: "curve25519-sha256".to_string(),
        server_host_key_algorithms: "ssh-ed25519".to_string(),
        encryption_algorithms_client_to_server: "aes128-ctr".to_string(),
        encryption_algorithms_server_to_client: "aes256-gcm@openssh.com".to_string(),
        mac_algorithms_client_to_server: "hmac-sha2-256".to_string(),
        mac_algorithms_server_to_client: "none".to_string(),
        compression_algorithms_client_to_server: "none".to_string(),
        compression_algorithms_server_to_client: "none".to_string(),
        languages_client_to_server: String::new(),
        languages_server_to_client: String::new(),
        first_kex_packet_follows: false,
    };

    let (raw, md5, sha256) = compute_hassh(&kex, SshRole::Server);
    let expected_raw = "curve25519-sha256;aes256-gcm@openssh.com;none;none";
    assert_eq!(raw, expected_raw);
    assert_eq!(md5.len(), 32);
    assert_eq!(sha256.len(), 64);
    let expected_md5 = hex::encode(md5::Md5::digest(expected_raw.as_bytes()));
    assert_eq!(md5, expected_md5);
}

#[test]
fn test_synthetic_kexinit_packets() {
    let client_pkt = build_synthetic_ssh_kexinit(SshRole::Client);
    assert!(client_pkt.len() > 100);

    let client_kex = parse_ssh_kexinit(&client_pkt).expect("client packet should parse");
    assert!(client_kex.kex_algorithms.contains("curve25519-sha256"));
    assert_eq!(client_kex.cookie_hex.len(), 32);

    let (c_raw, c_md5, c_sha256) = compute_hassh(&client_kex, SshRole::Client);
    assert_eq!(c_md5.len(), 32);
    assert_eq!(c_sha256.len(), 64);

    let server_pkt = build_synthetic_ssh_kexinit(SshRole::Server);
    let server_kex = parse_ssh_kexinit(&server_pkt).expect("server packet should parse");
    let (s_raw, s_md5, s_sha256) = compute_hassh(&server_kex, SshRole::Server);
    assert_eq!(s_md5.len(), 32);
    assert_eq!(s_sha256.len(), 64);

    // Client and Server have distinct algorithm sets
    assert_ne!(c_raw, s_raw);
    assert_ne!(c_md5, s_md5);
    assert_ne!(c_sha256, s_sha256);
}

#[test]
fn test_synthetic_ssh_pcap_audit() {
    let pcap_bytes = build_synthetic_ssh_pcap();
    assert!(pcap_bytes.len() > 500);

    let report = audit_ssh_bytes(&pcap_bytes, "synthetic_ssh.pcap").expect("audit should succeed");
    assert!(
        report.total_records >= 2,
        "expected at least 2 records, found {}",
        report.total_records
    );
    assert!(
        report.client_records >= 1,
        "expected at least 1 client record"
    );
    assert!(
        report.server_records >= 1,
        "expected at least 1 server record"
    );

    // Check banner associations
    let client_record = report
        .records
        .iter()
        .find(|r| r.role == SshRole::Client)
        .expect("client record");
    assert!(client_record.banner.is_some());
    let client_banner = client_record.banner.as_ref().unwrap();
    assert!(client_banner.software_version.contains("OpenSSH_8.9p1"));

    let server_record = report
        .records
        .iter()
        .find(|r| r.role == SshRole::Server)
        .expect("server record");
    assert!(server_record.banner.is_some());
    let server_banner = server_record.banner.as_ref().unwrap();
    assert!(server_banner.software_version.contains("OpenSSH_8.2p1"));
}

#[test]
fn test_adversarial_corrupted_packets() {
    // Empty payload
    assert!(parse_ssh_kexinit(&[]).is_err());

    // Truncated packet header
    assert!(parse_ssh_kexinit(&[0, 0, 0, 10]).is_err());

    // Packet length claiming 100 bytes but only 6 provided
    assert!(parse_ssh_kexinit(&[0, 0, 0, 100, 4, 20]).is_err());

    // Wrong message type (not 20)
    let wrong_type = [
        0, 0, 0, 20, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert!(parse_ssh_kexinit(&wrong_type).is_err());

    // Truncated name-list length field
    let mut malformed_namelist = Vec::new();
    malformed_namelist.push(20); // msg_type
    malformed_namelist.extend_from_slice(&[0u8; 16]); // cookie
    malformed_namelist.extend_from_slice(&[0, 0]); // truncated length (only 2 bytes instead of 4)
    assert!(parse_ssh_kexinit(&malformed_namelist).is_err());

    // Declared name-list length larger than available data
    let mut truncated_data = Vec::new();
    truncated_data.push(20);
    truncated_data.extend_from_slice(&[0u8; 16]);
    truncated_data.extend_from_slice(&100u32.to_be_bytes()); // length 100
    truncated_data.extend_from_slice(b"short"); // only 5 bytes
    assert!(parse_ssh_kexinit(&truncated_data).is_err());

    // Integer overflow attempt in name-list length (0xFFFFFFFF)
    let mut overflow_namelist = Vec::new();
    overflow_namelist.push(20);
    overflow_namelist.extend_from_slice(&[0u8; 16]);
    overflow_namelist.extend_from_slice(&u32::MAX.to_be_bytes());
    overflow_namelist.extend_from_slice(b"some-algorithms");
    assert!(parse_ssh_kexinit(&overflow_namelist).is_err());

    // Integer overflow attempt in binary packet length header (0xFFFFFFFF)
    let overflow_pkt = [0xff, 0xff, 0xff, 0xff, 0, 20, 1, 2, 3, 4, 5, 6, 7, 8];
    assert!(parse_ssh_kexinit(&overflow_pkt).is_err());
}

#[test]
fn test_scanner_spurious_byte_recovery_and_multiline_banner() {
    let valid_kex = build_synthetic_ssh_kexinit(SshRole::Client);

    // Multi-line banner preceding binary KEXINIT packet
    let mut stream_with_banner = Vec::new();
    stream_with_banner.extend_from_slice(b"Notice: Authorized use only.\r\n");
    stream_with_banner.extend_from_slice(b"SSH-2.0-OpenSSH_9.0\r\n");
    stream_with_banner.extend_from_slice(&valid_kex);
    let parsed =
        parse_ssh_kexinit(&stream_with_banner).expect("should parse after multiline banner");
    assert!(parsed.kex_algorithms.contains("curve25519-sha256"));

    // Spurious candidate (false positive byte 20) followed by valid KEXINIT
    let mut payload_with_noise = Vec::new();
    payload_with_noise.extend_from_slice(&[0x00, 0x00, 0x00, 0x14, 0x00, 0x14, 0xff, 0xee]); // noise
    payload_with_noise.extend_from_slice(&valid_kex);
    let recovered = parse_ssh_kexinit(&payload_with_noise).expect("scanner should recover");
    assert_eq!(recovered.packet_length, valid_kex.len() as u32 - 4);
}

#[test]
fn test_cli_hassh_command() {
    let pcap_bytes = build_synthetic_ssh_pcap();
    let temp_file =
        std::env::temp_dir().join(format!("test_ssh_hassh_{}.pcap", std::process::id()));
    std::fs::write(&temp_file, &pcap_bytes).expect("write temp pcap");

    let bin_path = env!("CARGO_BIN_EXE_nspecter");
    let output = Command::new(bin_path)
        .arg("hassh")
        .arg(temp_file.to_str().unwrap())
        .arg("--json")
        .output()
        .expect("execute nspecter hassh");

    let _ = std::fs::remove_file(&temp_file);

    assert!(
        output.status.success(),
        "CLI exit status failure: {:?}",
        output
    );
    let report: SshAuditReport = serde_json::from_slice(&output.stdout).expect("parse JSON output");
    assert!(report.total_records >= 2);
    assert_eq!(report.client_records, 1);
    assert_eq!(report.server_records, 1);
}
