// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! `net-specter` (`nspecter`) — Zero-dependency network packet forensics,
//! PCAP/PCAPNG frame decoder, TLS ClientHello JA3 fingerprinting engine, and DNS
//! covert-channel anomaly detector.

#![forbid(unsafe_code)]

pub mod beacon;
pub mod cli;
pub mod commands;
pub mod dns;
pub mod error;
pub mod filter;
pub mod http_inspect;
pub mod icmp_tunnel;
pub mod ja4;
pub mod p0f;
pub mod pcap;
pub mod pcapng;
pub mod quic;
pub mod quic_crypto;
pub mod ssh_hassh;
pub mod tcp_stream;
pub mod tls_cert;
pub mod tls_ja3;
