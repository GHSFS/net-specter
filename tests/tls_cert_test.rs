// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration tests for TLS ServerHello JA3S & X.509 Certificate Chain Forensics.

use net_specter::tls_cert::{
    audit_cert_bytes, parse_der_time, parse_tls_certificates, parse_tls_server_hello,
    parse_x509_der, read_der_element,
};
use std::fs;
use std::process::Command;

fn make_der_tlv(tag: u8, val: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(tag);
    if val.len() < 128 {
        out.push(val.len() as u8);
    } else if val.len() < 256 {
        out.push(0x81);
        out.push(val.len() as u8);
    } else {
        out.push(0x82);
        out.push(((val.len() >> 8) & 0xff) as u8);
        out.push((val.len() & 0xff) as u8);
    }
    out.extend_from_slice(val);
    out
}

fn make_der_sequence(val: &[u8]) -> Vec<u8> {
    make_der_tlv(0x30, val)
}

fn make_der_set(val: &[u8]) -> Vec<u8> {
    make_der_tlv(0x31, val)
}

fn make_der_oid(components: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::new();
    if components.len() >= 2 {
        bytes.push((components[0] * 40 + components[1]) as u8);
        for &c in &components[2..] {
            let mut val = c;
            let mut stack = Vec::new();
            stack.push((val & 0x7f) as u8);
            val >>= 7;
            while val > 0 {
                stack.push(((val & 0x7f) | 0x80) as u8);
                val >>= 7;
            }
            stack.reverse();
            bytes.extend_from_slice(&stack);
        }
    }
    make_der_tlv(0x06, &bytes)
}

fn make_der_dn(cn: &str, o: Option<&str>, c: Option<&str>) -> Vec<u8> {
    let mut rdn_list = Vec::new();

    // CN: 2.5.4.3
    let cn_oid = make_der_oid(&[2, 5, 4, 3]);
    let cn_val = make_der_tlv(0x13, cn.as_bytes()); // PrintableString
    let mut cn_seq = Vec::new();
    cn_seq.extend_from_slice(&cn_oid);
    cn_seq.extend_from_slice(&cn_val);
    rdn_list.extend_from_slice(&make_der_set(&make_der_sequence(&cn_seq)));

    // O: 2.5.4.10
    if let Some(org) = o {
        let o_oid = make_der_oid(&[2, 5, 4, 10]);
        let o_val = make_der_tlv(0x13, org.as_bytes());
        let mut o_seq = Vec::new();
        o_seq.extend_from_slice(&o_oid);
        o_seq.extend_from_slice(&o_val);
        rdn_list.extend_from_slice(&make_der_set(&make_der_sequence(&o_seq)));
    }

    // C: 2.5.4.6
    if let Some(country) = c {
        let c_oid = make_der_oid(&[2, 5, 4, 6]);
        let c_val = make_der_tlv(0x13, country.as_bytes());
        let mut c_seq = Vec::new();
        c_seq.extend_from_slice(&c_oid);
        c_seq.extend_from_slice(&c_val);
        rdn_list.extend_from_slice(&make_der_set(&make_der_sequence(&c_seq)));
    }

    make_der_sequence(&rdn_list)
}

fn make_test_cert_der(
    subject_cn: &str,
    issuer_cn: &str,
    not_before: &str,
    not_after: &str,
    sig_oid_components: &[u64],
    sans_dns: &[&str],
    sans_ip: &[&str],
) -> Vec<u8> {
    let mut tbs = Vec::new();

    // Version v3: [0] EXPLICIT INTEGER 2
    let v_int = make_der_tlv(0x02, &[0x02]);
    tbs.extend_from_slice(&make_der_tlv(0xa0, &v_int));

    // Serial Number: 0x01020304
    tbs.extend_from_slice(&make_der_tlv(0x02, &[0x01, 0x02, 0x03, 0x04]));

    // Signature Algorithm in TBS
    let sig_oid = make_der_oid(sig_oid_components);
    let mut sig_alg = Vec::new();
    sig_alg.extend_from_slice(&sig_oid);
    sig_alg.extend_from_slice(&[0x05, 0x00]); // NULL parameters
    tbs.extend_from_slice(&make_der_sequence(&sig_alg));

    // Issuer DN
    tbs.extend_from_slice(&make_der_dn(issuer_cn, Some("NetSpecter Org"), Some("US")));

    // Validity
    let mut val_bytes = Vec::new();
    val_bytes.extend_from_slice(&make_der_tlv(0x17, not_before.as_bytes())); // UTCTime
    val_bytes.extend_from_slice(&make_der_tlv(0x17, not_after.as_bytes()));
    tbs.extend_from_slice(&make_der_sequence(&val_bytes));

    // Subject DN
    tbs.extend_from_slice(&make_der_dn(subject_cn, Some("NetSpecter Org"), Some("US")));

    // SubjectPublicKeyInfo (dummy RSA key)
    let rsa_oid = make_der_oid(&[1, 2, 840, 113549, 1, 1, 1]);
    let mut spki_alg = Vec::new();
    spki_alg.extend_from_slice(&rsa_oid);
    spki_alg.extend_from_slice(&[0x05, 0x00]);
    let mut spki = Vec::new();
    spki.extend_from_slice(&make_der_sequence(&spki_alg));
    spki.extend_from_slice(&make_der_tlv(
        0x03,
        &[0x00, 0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x03],
    )); // dummy bit string
    tbs.extend_from_slice(&make_der_sequence(&spki));

    // Extensions [3]
    if !sans_dns.is_empty() || !sans_ip.is_empty() {
        let mut gn_bytes = Vec::new();
        for d in sans_dns {
            gn_bytes.extend_from_slice(&make_der_tlv(0x82, d.as_bytes()));
        }
        for ip_str in sans_ip {
            if let Ok(addr) = ip_str.parse::<std::net::IpAddr>() {
                match addr {
                    std::net::IpAddr::V4(v4) => {
                        gn_bytes.extend_from_slice(&make_der_tlv(0x87, &v4.octets()))
                    }
                    std::net::IpAddr::V6(v6) => {
                        gn_bytes.extend_from_slice(&make_der_tlv(0x87, &v6.octets()))
                    }
                }
            }
        }
        let gn_seq = make_der_sequence(&gn_bytes);
        let san_octets = make_der_tlv(0x04, &gn_seq);

        let mut san_ext = Vec::new();
        san_ext.extend_from_slice(&make_der_oid(&[2, 5, 29, 17])); // id-ce-subjectAltName
        san_ext.extend_from_slice(&san_octets);

        let exts_seq = make_der_sequence(&make_der_sequence(&san_ext));
        tbs.extend_from_slice(&make_der_tlv(0xa3, &exts_seq));
    }

    let tbs_seq = make_der_sequence(&tbs);

    // Root Certificate SEQUENCE
    let mut cert_body = Vec::new();
    cert_body.extend_from_slice(&tbs_seq);
    cert_body.extend_from_slice(&make_der_sequence(&sig_alg));
    cert_body.extend_from_slice(&make_der_tlv(
        0x03,
        &[0x00, 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34],
    )); // dummy signature
    make_der_sequence(&cert_body)
}

fn make_test_server_hello(
    version: u16,
    cipher: u16,
    extensions: &[u16],
    include_grease: bool,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&version.to_be_bytes()); // ServerVersion
    body.extend_from_slice(&[0xaa; 32]); // Random
    body.push(32); // Session ID len
    body.extend_from_slice(&[0x55; 32]); // Session ID
    body.extend_from_slice(&cipher.to_be_bytes()); // CipherSuite
    body.push(0x00); // CompressionMethod null

    let mut ext_buf = Vec::new();
    if include_grease {
        ext_buf.extend_from_slice(&0x0a0au16.to_be_bytes()); // GREASE ext
        ext_buf.extend_from_slice(&0u16.to_be_bytes());
    }
    for &e in extensions {
        ext_buf.extend_from_slice(&e.to_be_bytes());
        if e == 0x0010 {
            // ALPN: "h2"
            let alpn_data = b"\x00\x03\x02h2";
            ext_buf.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
            ext_buf.extend_from_slice(alpn_data);
        } else if e == 0x002b {
            // supported_versions: TLS 1.3 (0x0304)
            ext_buf.extend_from_slice(&2u16.to_be_bytes());
            ext_buf.extend_from_slice(&0x0304u16.to_be_bytes());
        } else {
            ext_buf.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    if include_grease {
        ext_buf.extend_from_slice(&0x2a2au16.to_be_bytes()); // GREASE ext
        ext_buf.extend_from_slice(&0u16.to_be_bytes());
    }

    body.extend_from_slice(&(ext_buf.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_buf);

    // Handshake header 0x02 + u24 len
    let mut hs = Vec::new();
    hs.push(0x02);
    let hs_len = body.len();
    hs.push(((hs_len >> 16) & 0xff) as u8);
    hs.push(((hs_len >> 8) & 0xff) as u8);
    hs.push((hs_len & 0xff) as u8);
    hs.extend_from_slice(&body);

    // TLS Record header 0x16 + 0x0303 + u16 len
    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&0x0303u16.to_be_bytes());
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn wrap_tls12_certificate(certs: &[Vec<u8>]) -> Vec<u8> {
    let mut cert_list_bytes = Vec::new();
    for c in certs {
        let len = c.len();
        cert_list_bytes.push(((len >> 16) & 0xff) as u8);
        cert_list_bytes.push(((len >> 8) & 0xff) as u8);
        cert_list_bytes.push((len & 0xff) as u8);
        cert_list_bytes.extend_from_slice(c);
    }

    let mut body = Vec::new();
    let total_len = cert_list_bytes.len();
    body.push(((total_len >> 16) & 0xff) as u8);
    body.push(((total_len >> 8) & 0xff) as u8);
    body.push((total_len & 0xff) as u8);
    body.extend_from_slice(&cert_list_bytes);

    let mut hs = Vec::new();
    hs.push(0x0b); // Certificate handshake type
    let hs_len = body.len();
    hs.push(((hs_len >> 16) & 0xff) as u8);
    hs.push(((hs_len >> 8) & 0xff) as u8);
    hs.push((hs_len & 0xff) as u8);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&0x0303u16.to_be_bytes());
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn wrap_tls13_certificate(certs: &[Vec<u8>]) -> Vec<u8> {
    let mut cert_list_bytes = Vec::new();
    for c in certs {
        let len = c.len();
        cert_list_bytes.push(((len >> 16) & 0xff) as u8);
        cert_list_bytes.push(((len >> 8) & 0xff) as u8);
        cert_list_bytes.push((len & 0xff) as u8);
        cert_list_bytes.extend_from_slice(c);
        cert_list_bytes.extend_from_slice(&0x0000u16.to_be_bytes()); // 0 extensions
    }

    let mut body = Vec::new();
    body.push(0x00); // context_len = 0
    let total_len = cert_list_bytes.len();
    body.push(((total_len >> 16) & 0xff) as u8);
    body.push(((total_len >> 8) & 0xff) as u8);
    body.push((total_len & 0xff) as u8);
    body.extend_from_slice(&cert_list_bytes);

    let mut hs = Vec::new();
    hs.push(0x0b);
    let hs_len = body.len();
    hs.push(((hs_len >> 16) & 0xff) as u8);
    hs.push(((hs_len >> 8) & 0xff) as u8);
    hs.push((hs_len & 0xff) as u8);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&0x0303u16.to_be_bytes());
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn build_ipv4_tcp_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc]);
    frame.extend_from_slice(&[0x00, 0x0c, 0x29, 0x11, 0x22, 0x33]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    let total_len = (20 + 20 + payload.len()) as u16;
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&0x1234u16.to_be_bytes());
    frame.extend_from_slice(&0x4000u16.to_be_bytes());
    frame.push(64);
    frame.push(6); // TCP
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&[10, 0, 0, 1]); // src
    frame.extend_from_slice(&[10, 0, 0, 2]); // dst

    frame.extend_from_slice(&443u16.to_be_bytes()); // src port 443
    frame.extend_from_slice(&54321u16.to_be_bytes()); // dst port 54321
    frame.extend_from_slice(&100u32.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.push(0x50); // data offset 5 (20 bytes)
    frame.push(0x18); // ACK + PSH
    frame.extend_from_slice(&65535u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn wrap_in_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());

    for (idx, f) in frames.iter().enumerate() {
        let len = f.len() as u32;
        pcap.extend_from_slice(&(1_700_000_000u32 + idx as u32).to_le_bytes());
        pcap.extend_from_slice(&100_000u32.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(f);
    }
    pcap
}

fn wrap_in_pcapng(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut ng = Vec::new();
    // SHB (28 bytes)
    ng.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
    ng.extend_from_slice(&28u32.to_le_bytes());
    ng.extend_from_slice(&0x1A2E3B4Cu32.to_le_bytes());
    ng.extend_from_slice(&1u16.to_le_bytes());
    ng.extend_from_slice(&0u16.to_le_bytes());
    ng.extend_from_slice(&(-1i64).to_le_bytes());
    ng.extend_from_slice(&28u32.to_le_bytes());

    // IDB (20 bytes)
    ng.extend_from_slice(&0x00000001u32.to_le_bytes());
    ng.extend_from_slice(&20u32.to_le_bytes());
    ng.extend_from_slice(&1u16.to_le_bytes()); // linktype Ethernet
    ng.extend_from_slice(&0u16.to_le_bytes());
    ng.extend_from_slice(&65535u32.to_le_bytes());
    ng.extend_from_slice(&20u32.to_le_bytes());

    for f in frames {
        let pad = (4 - (f.len() % 4)) % 4;
        let block_len = (32 + f.len() + pad) as u32;
        ng.extend_from_slice(&0x00000006u32.to_le_bytes()); // EPB
        ng.extend_from_slice(&block_len.to_le_bytes());
        ng.extend_from_slice(&0u32.to_le_bytes()); // iface 0
        ng.extend_from_slice(&0u32.to_le_bytes()); // ts high
        ng.extend_from_slice(&1_700_000_000u32.to_le_bytes()); // ts low
        ng.extend_from_slice(&(f.len() as u32).to_le_bytes());
        ng.extend_from_slice(&(f.len() as u32).to_le_bytes());
        ng.extend_from_slice(f);
        ng.extend_from_slice(&vec![0u8; pad]);
        ng.extend_from_slice(&block_len.to_le_bytes());
    }
    ng
}

#[test]
fn test_ja3s_string_and_grease_immunity() {
    let sh_clean = make_test_server_hello(0x0303, 0xc02f, &[0x0010, 0x002b], false);
    let sh_grease = make_test_server_hello(0x0303, 0xc02f, &[0x0010, 0x002b], true);

    let rep_clean = parse_tls_server_hello(&sh_clean).expect("Parse clean ServerHello");
    let rep_grease = parse_tls_server_hello(&sh_grease).expect("Parse GREASE ServerHello");

    assert_eq!(rep_clean.server_version, 771);
    assert_eq!(rep_clean.cipher_suite, 49199);
    assert_eq!(rep_clean.ja3s_string, "771,49199,16-43");
    assert_eq!(rep_clean.grease_filtered_count, 0);
    assert_eq!(rep_clean.alpn.as_deref(), Some("h2"));
    assert_eq!(rep_clean.selected_version, Some(0x0304));

    assert_eq!(rep_grease.ja3s_string, rep_clean.ja3s_string);
    assert_eq!(rep_grease.ja3s_md5, rep_clean.ja3s_md5);
    assert_eq!(rep_grease.ja3s_sha256, rep_clean.ja3s_sha256);
    assert_eq!(rep_grease.grease_filtered_count, 2);
}

#[test]
fn test_x509_asn1_der_parsing_valid() {
    let cert_der = make_test_cert_der(
        "specter.local",
        "NetSpecter CA",
        "240101000000Z",
        "300101000000Z",
        &[1, 2, 840, 113549, 1, 1, 11], // sha256WithRSAEncryption
        &["specter.local", "*.specter.local"],
        &["192.168.1.100"],
    );

    let report = parse_x509_der(&cert_der).expect("Parse valid DER certificate");
    assert!(report.subject.contains("CN=specter.local"));
    assert!(report.issuer.contains("CN=NetSpecter CA"));
    assert_eq!(report.serial_number, "01020304");
    assert_eq!(report.signature_algorithm, "sha256WithRSAEncryption");
    assert_eq!(report.not_before, "2024-01-01T00:00:00Z");
    assert_eq!(report.not_after, "2030-01-01T00:00:00Z");
    assert_eq!(
        report.sans_dns,
        vec!["specter.local".to_string(), "*.specter.local".to_string()]
    );
    assert_eq!(report.sans_ip, vec!["192.168.1.100".to_string()]);
    assert!(!report.is_self_signed);
    assert!(
        report.anomalies.is_empty(),
        "Expected no anomalies, got: {:?}",
        report.anomalies
    );
}

#[test]
fn test_tls12_and_tls13_certificate_extraction() {
    let leaf_der = make_test_cert_der(
        "leaf.net",
        "Intermediate CA",
        "240101000000Z",
        "290101000000Z",
        &[1, 2, 840, 113549, 1, 1, 11],
        &["leaf.net"],
        &[],
    );
    let ca_der = make_test_cert_der(
        "Intermediate CA",
        "Root CA",
        "200101000000Z",
        "350101000000Z",
        &[1, 2, 840, 113549, 1, 1, 11],
        &[],
        &[],
    );

    // TLS 1.2
    let tls12_rec = wrap_tls12_certificate(&[leaf_der.clone(), ca_der.clone()]);
    let certs12 = parse_tls_certificates(&tls12_rec).expect("Extract TLS 1.2 certs");
    assert_eq!(certs12.len(), 2);
    assert!(certs12[0].subject.contains("CN=leaf.net"));
    assert!(certs12[1].subject.contains("CN=Intermediate CA"));

    // TLS 1.3
    let tls13_rec = wrap_tls13_certificate(&[leaf_der, ca_der]);
    let certs13 = parse_tls_certificates(&tls13_rec).expect("Extract TLS 1.3 certs");
    assert_eq!(certs13.len(), 2);
    assert!(certs13[0].subject.contains("CN=leaf.net"));
    assert!(certs13[1].subject.contains("CN=Intermediate CA"));
}

#[test]
fn test_anomaly_detection_expired_weak_and_self_signed() {
    // 1. Expired
    let expired_der = make_test_cert_der(
        "expired.net",
        "CA",
        "150101000000Z",
        "160101000000Z",
        &[1, 2, 840, 113549, 1, 1, 11],
        &[],
        &[],
    );
    let rep_expired = parse_x509_der(&expired_der).unwrap();
    assert!(
        rep_expired.anomalies.iter().any(|a| a == "expired"),
        "Expected expired anomaly, got: {:?}",
        rep_expired.anomalies
    );

    // 2. Weak crypto (md5WithRSAEncryption = 1.2.840.113549.1.1.4)
    let weak_der = make_test_cert_der(
        "weak.net",
        "CA",
        "240101000000Z",
        "300101000000Z",
        &[1, 2, 840, 113549, 1, 1, 4],
        &[],
        &[],
    );
    let rep_weak = parse_x509_der(&weak_der).unwrap();
    assert!(
        rep_weak.anomalies.iter().any(|a| a == "weak_algorithm"),
        "Expected weak_algorithm anomaly, got: {:?}",
        rep_weak.anomalies
    );

    // 3. Self-signed
    let self_signed_der = make_test_cert_der(
        "Root Authority",
        "Root Authority",
        "240101000000Z",
        "300101000000Z",
        &[1, 2, 840, 113549, 1, 1, 11],
        &[],
        &[],
    );
    let rep_self = parse_x509_der(&self_signed_der).unwrap();
    assert!(rep_self.is_self_signed);
    assert!(
        rep_self.anomalies.iter().any(|a| a == "self_signed"),
        "Expected self_signed anomaly, got: {:?}",
        rep_self.anomalies
    );

    // 4. Inverted validity (notAfter precedes notBefore)
    let inverted_der = make_test_cert_der(
        "inverted.net",
        "CA",
        "280101000000Z",
        "250101000000Z",
        &[1, 2, 840, 113549, 1, 1, 11],
        &[],
        &[],
    );
    let rep_inv = parse_x509_der(&inverted_der).unwrap();
    assert!(
        rep_inv.anomalies.iter().any(|a| a == "inverted_validity"),
        "Expected inverted_validity anomaly, got: {:?}",
        rep_inv.anomalies
    );
}

#[test]
fn test_pcap_and_pcapng_capture_extraction() {
    let sh_rec = make_test_server_hello(0x0303, 0xc02f, &[0x0010], false);
    let cert_der = make_test_cert_der(
        "capture.specter",
        "Capture CA",
        "240101000000Z",
        "290101000000Z",
        &[1, 2, 840, 113549, 1, 1, 11],
        &["capture.specter"],
        &[],
    );
    let cert_rec = wrap_tls13_certificate(&[cert_der]);

    let f1 = build_ipv4_tcp_frame(&sh_rec);
    let f2 = build_ipv4_tcp_frame(&cert_rec);

    // Classic PCAP
    let pcap_bytes = wrap_in_pcap(&[f1.clone(), f2.clone()]);
    let pcap_rep = audit_cert_bytes(&pcap_bytes).expect("Audit classic PCAP");
    assert_eq!(pcap_rep.server_hellos.len(), 1);
    assert_eq!(pcap_rep.certificates.len(), 1);
    assert_eq!(pcap_rep.server_hellos[0].ja3s_string, "771,49199,16");
    assert!(pcap_rep.certificates[0]
        .subject
        .contains("CN=capture.specter"));

    // Next-Gen PCAPNG
    let pcapng_bytes = wrap_in_pcapng(&[f1, f2]);
    let pcapng_rep = audit_cert_bytes(&pcapng_bytes).expect("Audit PCAPNG");
    assert_eq!(pcapng_rep.server_hellos.len(), 1);
    assert_eq!(pcapng_rep.certificates.len(), 1);
    assert_eq!(pcapng_rep.server_hellos[0].ja3s_string, "771,49199,16");
}

#[test]
fn test_cli_cert_audit_subcommand_and_json() {
    let sh_rec = make_test_server_hello(0x0303, 0xc02f, &[0x0010], false);
    let hex_input = hex::encode(&sh_rec);

    let output = Command::new(env!("CARGO_BIN_EXE_nspecter"))
        .args(["cert-audit", &hex_input, "--json"])
        .output()
        .expect("Failed to execute nspecter cert-audit");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Valid JSON");
    assert_eq!(json["server_hellos"][0]["server_version"], 771);
    assert_eq!(json["server_hellos"][0]["ja3s_string"], "771,49199,16");

    // Test with temp PCAP file
    let cert_der = make_test_cert_der(
        "cli.specter",
        "CLI CA",
        "240101000000Z",
        "300101000000Z",
        &[1, 2, 840, 113549, 1, 1, 11],
        &["cli.specter"],
        &[],
    );
    let cert_rec = wrap_tls12_certificate(&[cert_der]);
    let f = build_ipv4_tcp_frame(&cert_rec);
    let pcap_data = wrap_in_pcap(&[f]);

    let temp_path = std::env::temp_dir().join("nspecter_cert_audit_test.pcap");
    fs::write(&temp_path, &pcap_data).expect("Write temp pcap");

    let file_out = Command::new(env!("CARGO_BIN_EXE_nspecter"))
        .args(["cert-audit", temp_path.to_str().unwrap(), "--json"])
        .output()
        .expect("Failed to execute nspecter cert-audit file");
    let _ = fs::remove_file(&temp_path);

    assert!(file_out.status.success());
    let file_json: serde_json::Value =
        serde_json::from_slice(&file_out.stdout).expect("Valid JSON");
    assert_eq!(file_json["certificates"].as_array().unwrap().len(), 1);
    assert!(file_json["certificates"][0]["subject"]
        .as_str()
        .unwrap()
        .contains("CN=cli.specter"));
}

#[test]
fn test_adversarial_asn1_der_and_tls_bounds_attacks() {
    // 1. DER Element boundaries and length overflows
    assert!(read_der_element(&[0x30]).is_err());
    assert!(read_der_element(&[0x30, 0x80]).is_err()); // Indefinite length forbidden in DER
    assert!(read_der_element(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err()); // Huge length overflow
    assert!(read_der_element(&[0x30, 0x05, 0x01, 0x02]).is_err()); // Truncated body

    // 2. Non-ASCII time data must not panic on char boundary slicing
    assert!(parse_der_time(0x17, b"2\xc3\xa90101000000Z").is_err());
    assert!(parse_der_time(0x18, b"202\xc3\xa90101000000Z").is_err());
    assert!(parse_der_time(0x02, b"240101000000Z").is_err());

    // 3. Pre-1970 UTCTime and GeneralizedTime civil epoch calculation
    let (t_str, ep) = parse_der_time(0x17, b"500101000000Z").expect("Parse 1950 UTCTime");
    assert_eq!(t_str, "1950-01-01T00:00:00Z");
    assert!(ep < 0, "1950 must be negative epoch seconds, got {ep}");

    // Inverted validity pre-1970: notBefore 1960, notAfter 1950
    let inv_pre1970 = make_test_cert_der(
        "old.specter",
        "CA",
        "600101000000Z",
        "500101000000Z",
        &[1, 2, 840, 113549, 1, 1, 11],
        &[],
        &[],
    );
    let rep_inv = parse_x509_der(&inv_pre1970).expect("Parse pre-1970 inverted cert");
    assert!(
        rep_inv.anomalies.contains(&"inverted_validity".to_string()),
        "Must flag inverted_validity for 1960 -> 1950"
    );

    // 4. Non-ServerHello payloads must be rejected, not parsed as dummy ServerHello
    assert!(parse_tls_server_hello(&[0u8; 50]).is_err());
    assert!(parse_tls_server_hello(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").is_err());

    // 5. Non-Certificate framing must be rejected
    assert!(parse_tls_certificates(&[0u8; 50]).is_err());
    assert!(parse_tls_certificates(b"arbitrary-non-tls-bytes").is_err());

    // 6. Resilient scan_tls_payload past false-positive 0x16 noise
    let sh_rec = make_test_server_hello(0x0303, 0xc02f, &[0x0010], false);
    let cert_der = make_test_cert_der(
        "resilient.specter",
        "CA",
        "240101000000Z",
        "300101000000Z",
        &[1, 2, 840, 113549, 1, 1, 11],
        &["resilient.specter"],
        &["2001:db8::1"], // IPv6 SAN test
    );
    let cert_rec = wrap_tls13_certificate(&[cert_der]);

    let mut noisy_payload = Vec::new();
    // False positive 0x16 with out-of-bounds length
    noisy_payload.extend_from_slice(&[0x16, 0x03, 0x01, 0xff, 0xff, 0x00, 0x01]);
    noisy_payload.extend_from_slice(&sh_rec);
    noisy_payload.extend_from_slice(&cert_rec);

    let report = audit_cert_bytes(&noisy_payload).expect("Resilient audit past noise");
    assert_eq!(report.server_hellos.len(), 1);
    assert_eq!(report.certificates.len(), 1);
    assert_eq!(report.server_hellos[0].ja3s_string, "771,49199,16");
    assert_eq!(
        report.certificates[0].sans_ip,
        vec!["2001:db8::1".to_string()]
    );
}
