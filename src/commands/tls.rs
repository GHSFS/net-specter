// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::commands::load_bytes_or_hex;
use crate::error::{Result, SpecterError};
use crate::ja4::{extract_ja4_from_capture_bytes, Ja4Fingerprint};
use crate::pcap::parse_pcap_bytes;
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use crate::tls_ja3::parse_tls_client_hello;

pub fn handle_ja3(file_or_hex: &str, json: bool) -> Result<()> {
    let raw = load_bytes_or_hex(file_or_hex)?;
    let reports = if is_pcapng(&raw) {
        let pcapng_rep = parse_pcapng_bytes(&raw)?;
        if pcapng_rep.tls_handshakes.is_empty() {
            return Err(SpecterError::MalformedTls(
                "No TLS ClientHello handshakes found in PCAPNG capture".into(),
            ));
        }
        pcapng_rep.tls_handshakes
    } else if let Ok(pcap_rep) = parse_pcap_bytes(&raw) {
        if pcap_rep.tls_handshakes.is_empty() {
            return Err(SpecterError::MalformedTls(
                "No TLS ClientHello handshakes found in PCAP capture".into(),
            ));
        }
        pcap_rep.tls_handshakes
    } else {
        vec![parse_tls_client_hello(&raw)?]
    };

    if json {
        let out = if reports.len() == 1 {
            serde_json::to_string_pretty(&reports[0])
        } else {
            serde_json::to_string_pretty(&reports)
        }
        .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?;
        println!("{out}");
    } else {
        for rep in &reports {
            println!("SNI        : {}", rep.sni.as_deref().unwrap_or("(none)"));
            println!("ALPN       : {}", rep.alpn.join(", "));
            println!("JA3 String : {}", rep.ja3_string);
            println!("JA3 MD5    : {}", rep.ja3_md5);
            println!("JA3 SHA256 : {}", rep.ja3_sha256);
        }
    }
    Ok(())
}

pub fn handle_ja4(file_or_hex: &str, quic: bool, json: bool) -> Result<()> {
    let raw = load_bytes_or_hex(file_or_hex)?;
    let fingerprints = extract_ja4_from_capture_bytes(&raw, quic)?;
    if fingerprints.is_empty() {
        return Err(SpecterError::MalformedTls(
            "No TLS/QUIC ClientHello or ServerHello handshakes found".into(),
        ));
    }

    if json {
        let out = if fingerprints.len() == 1 {
            serde_json::to_string_pretty(&fingerprints[0])
        } else {
            serde_json::to_string_pretty(&fingerprints)
        }
        .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?;
        println!("{out}");
    } else {
        for fp in &fingerprints {
            match fp {
                Ja4Fingerprint::Client(c) => {
                    println!("[JA4 Client]");
                    println!("  Transport   : {:?}", c.transport);
                    println!("  JA4         : {}", c.ja4);
                    println!("  JA4_a       : {}", c.ja4_a);
                    println!("  JA4_b       : {}", c.ja4_b);
                    println!("  JA4_c       : {}", c.ja4_c);
                    println!("  SNI         : {}", c.sni.as_deref().unwrap_or("(none)"));
                    println!("  ALPN        : {}", c.alpn.join(", "));
                    println!("  Version     : {}", c.version);
                    println!("  Ciphers     : {}", c.cipher_suites.len());
                    println!("  Extensions  : {}", c.extensions.len());
                }
                Ja4Fingerprint::Server(s) => {
                    println!("[JA4S Server]");
                    println!("  Transport   : {:?}", s.transport);
                    println!("  JA4S        : {}", s.ja4s);
                    println!("  JA4S_a      : {}", s.ja4s_a);
                    println!("  JA4S_b      : {}", s.ja4s_b);
                    println!("  JA4S_c      : {}", s.ja4s_c);
                    println!("  Cipher      : 0x{:04x}", s.cipher_suite);
                    println!("  ALPN        : {}", s.alpn.as_deref().unwrap_or("(none)"));
                    println!("  Version     : {}", s.version);
                    println!("  Extensions  : {}", s.extensions.len());
                }
            }
        }
    }
    Ok(())
}
