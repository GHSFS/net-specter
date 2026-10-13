// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use net_specter::pcap::build_synthetic_pcap;
use net_specter::pcapng::build_synthetic_pcapng;
use net_specter::quic::{
    audit_quic_bytes, audit_quic_capture_bytes, audit_quic_packet, build_synthetic_quic_initial,
    decrypt_quic_initial_packet,
};
use net_specter::quic_crypto::{
    aes_128_gcm_decrypt, aes_128_gcm_encrypt, derive_quic_initial_keys, hkdf_expand_label,
    hkdf_extract, QUIC_V1_INITIAL_SALT,
};
use std::process::Command;

/// Helper to build a sample TLS 1.3 ClientHello handshake message.
fn make_tls13_client_hello(sni_host: &str, alpn_proto: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // Legacy Client Version TLS 1.2
    body.extend_from_slice(&[0x42; 32]); // 32-byte Random
    body.push(0); // Session ID len 0

    // Cipher suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_CHACHA20_POLY1305_SHA256 (0x1303)
    let ciphers = [0x1301u16, 0x1303u16];
    body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in ciphers {
        body.extend_from_slice(&c.to_be_bytes());
    }

    // Compression: 1 byte (0x00 null)
    body.push(1);
    body.push(0);

    // Extensions
    let mut exts = Vec::new();

    // 1. SNI extension (0x0000)
    let mut sni = Vec::new();
    sni.extend_from_slice(&((sni_host.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(sni_host.len() as u16).to_be_bytes());
    sni.extend_from_slice(sni_host.as_bytes());
    exts.extend_from_slice(&0x0000u16.to_be_bytes());
    exts.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni);

    // 2. Supported Versions extension (0x002b) with TLS 1.3 (0x0304)
    let mut s_vers = Vec::new();
    s_vers.push(2); // length of versions list
    s_vers.extend_from_slice(&0x0304u16.to_be_bytes());
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&(s_vers.len() as u16).to_be_bytes());
    exts.extend_from_slice(&s_vers);

    // 3. Supported Groups extension (0x000a) with X25519 (0x001d)
    let mut groups = Vec::new();
    groups.extend_from_slice(&2u16.to_be_bytes());
    groups.extend_from_slice(&0x001du16.to_be_bytes());
    exts.extend_from_slice(&0x000au16.to_be_bytes());
    exts.extend_from_slice(&(groups.len() as u16).to_be_bytes());
    exts.extend_from_slice(&groups);

    // 4. ALPN extension (0x0010)
    let mut alpn = Vec::new();
    alpn.extend_from_slice(&((alpn_proto.len() + 1) as u16).to_be_bytes());
    alpn.push(alpn_proto.len() as u8);
    alpn.extend_from_slice(alpn_proto.as_bytes());
    exts.extend_from_slice(&0x0010u16.to_be_bytes());
    exts.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
    exts.extend_from_slice(&alpn);

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    // Wrap in Handshake header (type 0x01 ClientHello + 3-byte length)
    let mut hs = Vec::new();
    hs.push(0x01);
    let len = body.len();
    hs.push((len >> 16) as u8);
    hs.push((len >> 8) as u8);
    hs.push((len & 0xff) as u8);
    hs.extend_from_slice(&body);
    hs
}

/// Helper to build a sample TLS 1.3 ServerHello handshake message.
fn make_tls13_server_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // Legacy TLS 1.2
    body.extend_from_slice(&[0x77; 32]); // Random
    body.push(0); // Session ID len 0
    body.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
    body.push(0); // Compression method null

    let mut exts = Vec::new();
    // Supported versions: selected TLS 1.3 (0x0304)
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&0x0304u16.to_be_bytes());

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = Vec::new();
    hs.push(0x02); // ServerHello
    let len = body.len();
    hs.push((len >> 16) as u8);
    hs.push((len >> 8) as u8);
    hs.push((len & 0xff) as u8);
    hs.extend_from_slice(&body);
    hs
}

#[test]
fn test_rfc9001_appendix_a_hkdf_key_derivation() {
    let dcid = hex::decode("8394c8f03e515708").unwrap();

    let initial_secret = hkdf_extract(&QUIC_V1_INITIAL_SALT, &dcid);
    assert_eq!(
        hex::encode(initial_secret),
        "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
    );

    let client_secret =
        hkdf_expand_label(&initial_secret, "client in", b"", 32).expect("client secret");
    assert_eq!(
        hex::encode(&client_secret),
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
    );

    let client_key = hkdf_expand_label(&client_secret, "quic key", b"", 16).expect("client key");
    assert_eq!(hex::encode(&client_key), "1f369613dd76d5467730efcbe3b1a22d");

    let client_iv = hkdf_expand_label(&client_secret, "quic iv", b"", 12).expect("client iv");
    assert_eq!(hex::encode(&client_iv), "fa044b2f42a3fd3b46fb255c");

    let client_hp = hkdf_expand_label(&client_secret, "quic hp", b"", 16).expect("client hp");
    assert_eq!(hex::encode(&client_hp), "9f50449e04a0e810283a1e9933adedd2");

    let server_secret =
        hkdf_expand_label(&initial_secret, "server in", b"", 32).expect("server secret");
    assert_eq!(
        hex::encode(&server_secret),
        "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
    );

    let server_key = hkdf_expand_label(&server_secret, "quic key", b"", 16).expect("server key");
    assert_eq!(hex::encode(&server_key), "cf3a5331653c364c88f0f379b6067e37");

    let server_iv = hkdf_expand_label(&server_secret, "quic iv", b"", 12).expect("server iv");
    assert_eq!(hex::encode(&server_iv), "0ac1493ca1905853b0bba03e");

    let server_hp = hkdf_expand_label(&server_secret, "quic hp", b"", 16).expect("server hp");
    assert_eq!(hex::encode(&server_hp), "c206b8d9b9f0f37644430b490eeaa314");

    // Also test derived helper:
    let keys = derive_quic_initial_keys(0x0000_0001, &dcid, false).unwrap();
    assert_eq!(hex::encode(keys.key), "1f369613dd76d5467730efcbe3b1a22d");
    assert_eq!(hex::encode(keys.iv), "fa044b2f42a3fd3b46fb255c");
    assert_eq!(hex::encode(keys.hp), "9f50449e04a0e810283a1e9933adedd2");
}

#[test]
fn test_aes_128_gcm_nist_sp800_38d_vectors() {
    // NIST SP 800-38D Test Case 1: Empty PT and AAD
    let key = [0u8; 16];
    let iv = [0u8; 12];
    let pt = [];
    let aad = [];
    let (ct, tag) = aes_128_gcm_encrypt(&key, &iv, &pt, &aad);
    assert!(ct.is_empty());
    assert_eq!(hex::encode(tag), "58e2fccefa7e3061367f1d57a4e7455a");

    let decrypted = aes_128_gcm_decrypt(&key, &iv, &ct, &aad, &tag).expect("decrypts TC1");
    assert!(decrypted.is_empty());

    // NIST SP 800-38D Test Case 2: 16-byte zero PT
    let pt2 = [0u8; 16];
    let (ct2, tag2) = aes_128_gcm_encrypt(&key, &iv, &pt2, &aad);
    assert_eq!(hex::encode(&ct2), "0388dace60b6a392f328c2b971b2fe78");
    assert_eq!(hex::encode(tag2), "ab6e47d42cec13bdf53a67b21257bddf");

    let dec2 = aes_128_gcm_decrypt(&key, &iv, &ct2, &aad, &tag2).expect("decrypts TC2");
    assert_eq!(dec2, pt2);
}

#[test]
fn test_synthetic_quic_client_initial_decryption_and_ja3_ja4() {
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let scid = hex::decode("01020304").unwrap();
    let client_hello = make_tls13_client_hello("specter.quic.cloud", "h3");

    let packet = build_synthetic_quic_initial(
        0x0000_0001,
        &dcid,
        &scid,
        2, // packet number 2
        &client_hello,
        false,
    )
    .expect("builds synthetic quic initial");

    let (header, pn, dec_payload) =
        decrypt_quic_initial_packet(&packet, false).expect("decrypts initial packet");
    assert_eq!(header.version, 0x0000_0001);
    assert_eq!(header.dcid, dcid);
    assert_eq!(header.scid, scid);
    assert_eq!(pn, 2);
    assert!(dec_payload.len() >= client_hello.len());

    let report = audit_quic_packet(&packet).expect("audits quic packet");
    assert_eq!(report.role, "client");
    assert_eq!(report.version, "QUICv1 (0x00000001)");
    assert_eq!(report.dcid, "8394c8f03e515708");
    assert_eq!(report.scid, "01020304");
    assert_eq!(report.packet_number, 2);
    assert_eq!(report.handshake_type, Some("ClientHello".to_string()));
    assert_eq!(report.sni, Some("specter.quic.cloud".to_string()));
    assert_eq!(report.alpn, vec!["h3"]);
    assert!(report.ja3.is_some());
    assert!(report.ja3_digest.is_some());
    assert!(report.ja4.is_some());

    let ja4 = report.ja4.unwrap();
    assert!(ja4.starts_with("q13d"));
}

#[test]
fn test_synthetic_quic_server_initial_decryption_and_ja3s_ja4s() {
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let scid = hex::decode("aabbccdd").unwrap();
    let server_hello = make_tls13_server_hello();

    let packet = build_synthetic_quic_initial(
        0x0000_0001,
        &dcid,
        &scid,
        1,
        &server_hello,
        true, // server Initial
    )
    .expect("builds server initial");

    let report = audit_quic_packet(&packet).expect("audits server packet");
    assert_eq!(report.role, "server");
    assert_eq!(report.handshake_type, Some("ServerHello".to_string()));
    assert!(report.ja3s.is_some());
    assert!(report.ja4s.is_some());

    let ja4s = report.ja4s.unwrap();
    assert!(ja4s.starts_with("q13"));
}

#[test]
fn test_quic_v2_rfc9369_packet_decryption() {
    let dcid = hex::decode("1122334455667788").unwrap();
    let scid = hex::decode("99aabbcc").unwrap();
    let client_hello = make_tls13_client_hello("v2.quic.corp", "h3");

    let packet = build_synthetic_quic_initial(
        0x6b33_43cf, // RFC 9369 QUIC v2
        &dcid,
        &scid,
        5,
        &client_hello,
        false,
    )
    .expect("builds v2 packet");

    let report = audit_quic_packet(&packet).expect("audits v2 initial");
    assert_eq!(report.version, "QUICv2 (0x6b3343cf)");
    assert_eq!(report.packet_number, 5);
    assert_eq!(report.sni, Some("v2.quic.corp".to_string()));
    assert!(report.ja4.is_some());
}

#[test]
fn test_pcap_and_pcapng_capture_quic_audit() {
    let pcap_bytes = build_synthetic_pcap();
    let audit_pcap = audit_quic_capture_bytes(&pcap_bytes).expect("audits pcap");
    assert!(audit_pcap.packets_inspected >= 1);

    let pcapng_bytes = build_synthetic_pcapng();
    let audit_pcapng = audit_quic_capture_bytes(&pcapng_bytes).expect("audits pcapng");
    assert!(audit_pcapng.packets_inspected >= 1);
}

#[test]
fn test_adversarial_malformed_and_truncated_quic_rejection() {
    // 1. Truncated header
    assert!(audit_quic_packet(&[0xc0, 0x00]).is_err());

    // 2. Corrupted ciphertext tag
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let scid = hex::decode("01020304").unwrap();
    let ch = make_tls13_client_hello("bad.quic", "h3");
    let mut packet =
        build_synthetic_quic_initial(0x0000_0001, &dcid, &scid, 1, &ch, false).unwrap();

    let last = packet.len() - 1;
    packet[last] ^= 0xff; // Tamper with tag byte
    let err = audit_quic_packet(&packet);
    assert!(err.is_err());

    // 3. Empty input
    assert!(audit_quic_bytes(&[]).is_err());
}

#[test]
fn test_cli_quic_audit_subcommand_and_json() {
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let scid = hex::decode("01020304").unwrap();
    let ch = make_tls13_client_hello("cli.quic.cloud", "h3");
    let packet = build_synthetic_quic_initial(0x0000_0001, &dcid, &scid, 7, &ch, false).unwrap();
    let hex_str = hex::encode(&packet);

    let output = Command::new(env!("CARGO_BIN_EXE_nspecter"))
        .args(["quic-audit", &hex_str, "--json"])
        .output()
        .expect("executes quic-audit");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("QUICv1 (0x00000001)"));
    assert!(stdout.contains("cli.quic.cloud"));
    assert!(stdout.contains("ClientHello"));
    assert!(stdout.contains("8394c8f03e515708"));
}
