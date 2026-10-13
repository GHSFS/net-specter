// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! `net-specter` (`nspecter`) — Zero-dependency network packet forensics,
//! PCAP/PCAPNG frame decoder, TLS ClientHello JA3 fingerprinting engine, and DNS
//! covert-channel anomaly detector.

#![forbid(unsafe_code)]

pub mod cli;
pub mod dns;
pub mod error;
pub mod http_inspect;
pub mod ja4;
pub mod pcap;
pub mod pcapng;
pub mod tcp_stream;
pub mod tls_cert;
pub mod tls_ja3;
