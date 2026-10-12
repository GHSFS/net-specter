// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! `net-specter` (`nspecter`) — Zero-dependency network packet forensics,
//! PCAP frame decoder, TLS ClientHello JA3 fingerprinting engine, and DNS
//! covert-channel anomaly detector.

pub mod cli;
pub mod dns;
pub mod error;
pub mod pcap;
pub mod tls_ja3;
