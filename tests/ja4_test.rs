// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration tests for JA4 & JA4S Modern TLS & QUIC Fingerprint Engine.

use net_specter::ja4::{
    compute_ja4_client, compute_ja4_server, extract_ja4_from_capture_bytes,
    extract_quic_tls_payload, is_quic_packet, parse_ja4, Ja4Fingerprint, TransportProtocol,
};
use net_specter::pcap::build_synthetic_pcap;
use net_specter::pcapng::build_synthetic_pcapng;
use std::process::Command;

fn make_u16_be(val: u16) -> [u8; 2] {
    val.to_be_bytes()
}

fn make_u24_be(val: usize) -> [u8; 3] {
    [
        ((val >> 16) & 0xff) as u8,
        ((val >> 8) & 0xff) as u8,
        (val & 0xff) as u8,
    ]
}

/// Builds a deterministic TLS 1.3 ClientHello record for testing.
fn make_test_client_hello(
    sni_host: Option<&str>,
    alpn_list: &[&str],
    include_grease: bool,
) -> Vec<u8> {
    let mut body = Vec::new();
    // Client Version (0x0303)
    body.extend_from_slice(&make_u16_be(0x0303));
    // Random (32 bytes)
    body.extend_from_slice(&[0x42; 32]);
    // Session ID (32 bytes)
    body.push(32);
    body.extend_from_slice(&[0x11; 32]);

    // Cipher Suites
    let mut ciphers = vec![0x1301, 0x1302, 0x1303, 0xcca8];
    if include_grease {
        ciphers.push(0x0a0a); // RFC 8701 GREASE
    }
    body.extend_from_slice(&make_u16_be((ciphers.len() * 2) as u16));
    for c in ciphers {
        body.extend_from_slice(&make_u16_be(c));
    }

    // Compression Methods (1 byte: 0x00)
    body.push(1);
    body.push(0);

    // Extensions
    let mut exts_buf = Vec::new();

    // 1. SNI (0x0000)
    if let Some(host) = sni_host {
        let mut sni_ext = Vec::new();
        let h_bytes = host.as_bytes();
        let list_len = (h_bytes.len() + 3) as u16;
        sni_ext.extend_from_slice(&make_u16_be(list_len));
        sni_ext.push(0); // host_name type
        sni_ext.extend_from_slice(&make_u16_be(h_bytes.len() as u16));
        sni_ext.extend_from_slice(h_bytes);

        exts_buf.extend_from_slice(&make_u16_be(0x0000));
        exts_buf.extend_from_slice(&make_u16_be(sni_ext.len() as u16));
        exts_buf.extend_from_slice(&sni_ext);
    }

    // 2. Supported Groups (0x000a)
    {
        let mut grp_ext = Vec::new();
        grp_ext.extend_from_slice(&make_u16_be(4));
        grp_ext.extend_from_slice(&make_u16_be(0x001d)); // x25519
        grp_ext.extend_from_slice(&make_u16_be(0x0017)); // secp256r1

        exts_buf.extend_from_slice(&make_u16_be(0x000a));
        exts_buf.extend_from_slice(&make_u16_be(grp_ext.len() as u16));
        exts_buf.extend_from_slice(&grp_ext);
    }

    // 3. Signature Algorithms (0x000d)
    {
        let mut sigs = vec![0x0403, 0x0804];
        if include_grease {
            sigs.push(0x1a1a); // GREASE in sig algs
        }
        let mut sig_ext = Vec::new();
        sig_ext.extend_from_slice(&make_u16_be((sigs.len() * 2) as u16));
        for s in sigs {
            sig_ext.extend_from_slice(&make_u16_be(s));
        }

        exts_buf.extend_from_slice(&make_u16_be(0x000d));
        exts_buf.extend_from_slice(&make_u16_be(sig_ext.len() as u16));
        exts_buf.extend_from_slice(&sig_ext);
    }

    // 4. ALPN (0x0010)
    if !alpn_list.is_empty() {
        let mut alpn_ext = Vec::new();
        let mut proto_list = Vec::new();
        for proto in alpn_list {
            proto_list.push(proto.len() as u8);
            proto_list.extend_from_slice(proto.as_bytes());
        }
        alpn_ext.extend_from_slice(&make_u16_be(proto_list.len() as u16));
        alpn_ext.extend_from_slice(&proto_list);

        exts_buf.extend_from_slice(&make_u16_be(0x0010));
        exts_buf.extend_from_slice(&make_u16_be(alpn_ext.len() as u16));
        exts_buf.extend_from_slice(&alpn_ext);
    }

    // 5. Supported Versions (0x002b)
    {
        let mut vers = vec![0x0304, 0x0303];
        if include_grease {
            vers.push(0x2a2a); // GREASE in supported versions
        }
        let mut ver_ext = Vec::new();
        ver_ext.push((vers.len() * 2) as u8);
        for v in vers {
            ver_ext.extend_from_slice(&make_u16_be(v));
        }

        exts_buf.extend_from_slice(&make_u16_be(0x002b));
        exts_buf.extend_from_slice(&make_u16_be(ver_ext.len() as u16));
        exts_buf.extend_from_slice(&ver_ext);
    }

    // 6. GREASE Extension (0x3a3a)
    if include_grease {
        exts_buf.extend_from_slice(&make_u16_be(0x3a3a));
        exts_buf.extend_from_slice(&make_u16_be(0));
    }

    body.extend_from_slice(&make_u16_be(exts_buf.len() as u16));
    body.extend_from_slice(&exts_buf);

    // Handshake header: msg_type = 0x01, len = u24
    let mut hs = Vec::new();
    hs.push(0x01);
    hs.extend_from_slice(&make_u24_be(body.len()));
    hs.extend_from_slice(&body);

    // Record layer: content_type = 0x16, version = 0x0301, len = u16
    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&make_u16_be(0x0301));
    rec.extend_from_slice(&make_u16_be(hs.len() as u16));
    rec.extend_from_slice(&hs);
    rec
}

/// Builds a deterministic TLS 1.3 ServerHello record for testing.
fn make_test_server_hello(cipher: u16, alpn: Option<&str>, include_grease: bool) -> Vec<u8> {
    let mut body = Vec::new();
    // Server Version (0x0303)
    body.extend_from_slice(&make_u16_be(0x0303));
    // Random (32 bytes)
    body.extend_from_slice(&[0x77; 32]);
    // Session ID length (0)
    body.push(0);
    // Chosen Cipher Suite
    body.extend_from_slice(&make_u16_be(cipher));
    // Compression (0x00)
    body.push(0);

    // Extensions
    let mut exts_buf = Vec::new();

    // 1. ALPN (0x0010)
    if let Some(proto) = alpn {
        let mut alpn_ext = Vec::new();
        let mut proto_list = Vec::new();
        proto_list.push(proto.len() as u8);
        proto_list.extend_from_slice(proto.as_bytes());
        alpn_ext.extend_from_slice(&make_u16_be(proto_list.len() as u16));
        alpn_ext.extend_from_slice(&proto_list);

        exts_buf.extend_from_slice(&make_u16_be(0x0010));
        exts_buf.extend_from_slice(&make_u16_be(alpn_ext.len() as u16));
        exts_buf.extend_from_slice(&alpn_ext);
    }

    // 2. Supported Versions (0x002b) -> selected version 0x0304
    {
        exts_buf.extend_from_slice(&make_u16_be(0x002b));
        exts_buf.extend_from_slice(&make_u16_be(2));
        exts_buf.extend_from_slice(&make_u16_be(0x0304));
    }

    // 3. GREASE Extension (0x4a4a)
    if include_grease {
        exts_buf.extend_from_slice(&make_u16_be(0x4a4a));
        exts_buf.extend_from_slice(&make_u16_be(0));
    }

    body.extend_from_slice(&make_u16_be(exts_buf.len() as u16));
    body.extend_from_slice(&exts_buf);

    let mut hs = Vec::new();
    hs.push(0x02); // ServerHello
    hs.extend_from_slice(&make_u24_be(body.len()));
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&make_u16_be(0x0303));
    rec.extend_from_slice(&make_u16_be(hs.len() as u16));
    rec.extend_from_slice(&hs);
    rec
}

/// Builds a synthetic QUIC Initial packet wrapping naked ClientHello.
fn make_test_quic_initial(naked_client_hello: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    // Header byte: 0xc0 (Long Header Initial packet)
    pkt.push(0xc0);
    // Version: 0x00000001 (QUIC v1)
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    // DCID length + DCID
    pkt.push(4);
    pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    // SCID length + SCID
    pkt.push(4);
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    // Token length (varint 0)
    pkt.push(0x00);

    // Crypto Frame: Type 0x06, Offset 0x00, Length varint, Crypto Data
    let mut crypto_frame = vec![
        0x06,                                           // CRYPTO frame
        0x00,                                           // offset = 0
        0x40 | ((naked_client_hello.len() >> 8) as u8), // 2-byte varint len
        (naked_client_hello.len() & 0xff) as u8,
    ];
    crypto_frame.extend_from_slice(naked_client_hello);

    // Payload Length: 2-byte varint (1 byte packet number + frame len)
    let payload_len = 1 + crypto_frame.len();
    pkt.push(0x40 | ((payload_len >> 8) as u8));
    pkt.push((payload_len & 0xff) as u8);

    // Packet Number: 1 byte
    pkt.push(0x01);
    // Frame
    pkt.extend_from_slice(&crypto_frame);
    pkt
}

#[test]
fn test_ja4_client_fingerprint_calculation_and_grease_immunity() {
    let raw_normal = make_test_client_hello(Some("specter.local"), &["h2", "http/1.1"], false);
    let raw_grease = make_test_client_hello(Some("specter.local"), &["h2", "http/1.1"], true);

    let rep_normal = compute_ja4_client(&raw_normal, TransportProtocol::Tcp).unwrap();
    let rep_grease = compute_ja4_client(&raw_grease, TransportProtocol::Tcp).unwrap();

    // JA4_a verification: t (tcp) + 13 (tls 1.3) + d (domain) + 04 (ciphers) + 05 (exts) + h2 (alpn)
    assert_eq!(rep_normal.ja4_a, "t13d0405h2");
    // With grease, GREASE ciphers, exts, vers, and sigs are filtered out -> identical JA4!
    assert_eq!(rep_grease.ja4_a, "t13d0405h2");
    assert_eq!(rep_normal.ja4_b, rep_grease.ja4_b);
    assert_eq!(rep_normal.ja4_c, rep_grease.ja4_c);
    assert_eq!(rep_normal.ja4, rep_grease.ja4);

    assert_eq!(rep_normal.cipher_suites.len(), 4);
    assert_eq!(rep_normal.sni, Some("specter.local".to_string()));
    assert_eq!(rep_normal.alpn, vec!["h2", "http/1.1"]);
}

#[test]
fn test_ja4_sni_ip_vs_domain_and_alpn_variations() {
    // 1. IP address in SNI -> flag 'i'
    let raw_ip = make_test_client_hello(Some("192.168.1.100"), &["h2"], false);
    let rep_ip = compute_ja4_client(&raw_ip, TransportProtocol::Tcp).unwrap();
    assert!(rep_ip.ja4_a.starts_with("t13i"));

    // 2. Missing SNI -> flag 'i'
    let raw_no_sni = make_test_client_hello(None, &["h2"], false);
    let rep_no_sni = compute_ja4_client(&raw_no_sni, TransportProtocol::Tcp).unwrap();
    assert!(rep_no_sni.ja4_a.starts_with("t13i"));

    // 3. Single character ALPN -> duplicate char ("q" -> "qq")
    let raw_single_alpn = make_test_client_hello(Some("test.org"), &["q"], false);
    let rep_single_alpn = compute_ja4_client(&raw_single_alpn, TransportProtocol::Tcp).unwrap();
    assert!(rep_single_alpn.ja4_a.ends_with("qq"));

    // 4. Missing ALPN -> "00"
    let raw_no_alpn = make_test_client_hello(Some("test.org"), &[], false);
    let rep_no_alpn = compute_ja4_client(&raw_no_alpn, TransportProtocol::Tcp).unwrap();
    assert!(rep_no_alpn.ja4_a.ends_with("00"));
}

#[test]
fn test_ja4s_server_fingerprint_and_grease_immunity() {
    let raw_server = make_test_server_hello(0x1301, Some("h2"), false);
    let raw_server_grease = make_test_server_hello(0x1301, Some("h2"), true);

    let rep = compute_ja4_server(&raw_server, TransportProtocol::Tcp).unwrap();
    let rep_grease = compute_ja4_server(&raw_server_grease, TransportProtocol::Tcp).unwrap();

    // JA4S_a: t (tcp) + 13 (tls 1.3) + 02 (ext count) + h2 (alpn)
    assert_eq!(rep.ja4s_a, "t1302h2");
    assert_eq!(rep_grease.ja4s_a, "t1302h2");
    // JA4S_b: 1301 (chosen cipher)
    assert_eq!(rep.ja4s_b, "1301");
    assert_eq!(rep_grease.ja4s_b, "1301");
    // JA4S_c: extension hash matches
    assert_eq!(rep.ja4s_c, rep_grease.ja4s_c);
    assert_eq!(rep.ja4s, rep_grease.ja4s);
}

#[test]
fn test_quic_initial_detection_and_fingerprint_extraction() {
    // Extract naked ClientHello from record (skip 5-byte TLS record header)
    let raw_record = make_test_client_hello(Some("quic.target"), &["h3"], false);
    let naked_hello = &raw_record[5..];

    let quic_pkt = make_test_quic_initial(naked_hello);
    assert!(is_quic_packet(&quic_pkt));

    let extracted = extract_quic_tls_payload(&quic_pkt);
    assert!(extracted.is_some());
    assert_eq!(extracted.unwrap()[0], 0x01); // Handshake Type ClientHello

    let fp = parse_ja4(&quic_pkt, None).unwrap();
    match fp {
        Ja4Fingerprint::Client(c) => {
            assert_eq!(c.transport, TransportProtocol::Quic);
            assert!(c.ja4_a.starts_with("q13d"));
            assert!(c.ja4_a.ends_with("h3"));
            assert_eq!(c.sni, Some("quic.target".to_string()));
        }
        _ => panic!("Expected Client fingerprint"),
    }
}

#[test]
fn test_malformed_and_truncated_rejection() {
    // 1. Truncated record
    assert!(compute_ja4_client(
        &[0x16, 0x03, 0x01, 0x00, 0x10, 0x01],
        TransportProtocol::Tcp
    )
    .is_err());
    // 2. Invalid handshake type
    assert!(compute_ja4_client(
        &[0x16, 0x03, 0x01, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00],
        TransportProtocol::Tcp
    )
    .is_err());
    // 3. Random empty buffer
    assert!(parse_ja4(&[], None).is_err());
}

#[test]
fn test_capture_bytes_extraction_pcap_and_pcapng() {
    let pcap_bytes = build_synthetic_pcap();
    let pcap_fps = extract_ja4_from_capture_bytes(&pcap_bytes, false).unwrap();
    assert!(!pcap_fps.is_empty(), "Extracted JA4 from synthetic PCAP");

    let pcapng_bytes = build_synthetic_pcapng();
    let pcapng_fps = extract_ja4_from_capture_bytes(&pcapng_bytes, false).unwrap();
    assert!(
        !pcapng_fps.is_empty(),
        "Extracted JA4 from synthetic PCAPNG"
    );
}

#[test]
fn test_cli_ja4_subcommand_execution() {
    let raw = make_test_client_hello(Some("cli.example.com"), &["h2"], false);
    let hex_str = hex::encode(&raw);

    let output = Command::new(env!("CARGO_BIN_EXE_nspecter"))
        .args(["ja4", &hex_str, "--json"])
        .output()
        .expect("runs nspecter ja4");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("t13d0405h2"));
    assert!(stdout.contains("cli.example.com"));
}

/// Builds a synthetic DTLS 1.2 ClientHello record with 13-byte record header and 12-byte handshake header.
fn make_test_dtls_client_hello(epoch: u16, cookie: &[u8], include_grease: bool) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&make_u16_be(0xfefd)); // DTLS 1.2
    body.extend_from_slice(&[0x55; 32]); // Random
    body.push(0); // Session ID len 0
                  // DTLS Cookie (RFC 6347 Section 4.2.1)
    body.push(cookie.len() as u8);
    body.extend_from_slice(cookie);

    let mut ciphers = vec![0x1301, 0xc02f];
    if include_grease {
        ciphers.push(0x5a5a);
    }
    body.extend_from_slice(&make_u16_be((ciphers.len() * 2) as u16));
    for c in ciphers {
        body.extend_from_slice(&make_u16_be(c));
    }
    body.push(1);
    body.push(0);

    let mut exts = Vec::new();
    let host = b"specter.dtls";
    let mut sni = Vec::new();
    sni.extend_from_slice(&make_u16_be((host.len() + 3) as u16));
    sni.push(0);
    sni.extend_from_slice(&make_u16_be(host.len() as u16));
    sni.extend_from_slice(host);
    exts.extend_from_slice(&make_u16_be(0x0000));
    exts.extend_from_slice(&make_u16_be(sni.len() as u16));
    exts.extend_from_slice(&sni);

    // ALPN "dtls" -> first and last char "ds"
    let mut alpn = Vec::new();
    alpn.push(4);
    alpn.extend_from_slice(b"dtls");
    exts.extend_from_slice(&make_u16_be(0x0010));
    exts.extend_from_slice(&make_u16_be((alpn.len() + 2) as u16));
    exts.extend_from_slice(&make_u16_be(alpn.len() as u16));
    exts.extend_from_slice(&alpn);

    body.extend_from_slice(&make_u16_be(exts.len() as u16));
    body.extend_from_slice(&exts);

    let mut hs = Vec::new();
    hs.push(0x01); // ClientHello
    hs.extend_from_slice(&make_u24_be(body.len()));
    hs.extend_from_slice(&make_u16_be(0)); // message_seq
    hs.extend_from_slice(&make_u24_be(0)); // fragment_offset
    hs.extend_from_slice(&make_u24_be(body.len())); // fragment_length
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(0x16); // Handshake record
    rec.extend_from_slice(&make_u16_be(0xfefd)); // DTLS 1.2
    rec.extend_from_slice(&make_u16_be(epoch));
    rec.extend_from_slice(&[0, 0, 0, 0, 0, 1]); // 6-byte sequence
    rec.extend_from_slice(&make_u16_be(hs.len() as u16));
    rec.extend_from_slice(&hs);
    rec
}

#[test]
fn test_dtls_fingerprinting_and_cookie_epoch_handling() {
    let raw_dtls = make_test_dtls_client_hello(1, &[0xaa, 0xbb, 0xcc, 0xdd], false);
    let raw_dtls_grease = make_test_dtls_client_hello(2, &[0xaa, 0xbb, 0xcc, 0xdd], true);

    let fp = parse_ja4(&raw_dtls, None).unwrap();
    match fp {
        Ja4Fingerprint::Client(c) => {
            assert_eq!(c.transport, TransportProtocol::Dtls);
            // d (dtls) + d2 (dtls 1.2) + d (domain) + 02 (ciphers) + 02 (exts) + ds (alpn "dtls")
            assert_eq!(c.ja4_a, "dd2d0202ds");
            assert_eq!(c.sni, Some("specter.dtls".to_string()));
            assert_eq!(c.alpn, vec!["dtls"]);
            assert_eq!(c.version, "DTLS d2 (0xfefd)");

            let fp_grease = parse_ja4(&raw_dtls_grease, None).unwrap();
            if let Ja4Fingerprint::Client(cg) = fp_grease {
                assert_eq!(cg.ja4_a, c.ja4_a);
                assert_eq!(cg.ja4_b, c.ja4_b);
                assert_eq!(cg.ja4, c.ja4);
            }
        }
        _ => panic!("Expected DTLS Client fingerprint"),
    }
}
