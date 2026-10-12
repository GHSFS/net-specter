// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fmt;

/// Unified error type for packet capture decoding, TLS handshake inspection,
/// and DNS wire-format auditing.
#[derive(Debug)]
pub enum SpecterError {
    Io(std::io::Error),
    InvalidPcap(String),
    InvalidPacket(String),
    MalformedTls(String),
    MalformedDns(String),
    InvalidArgument(String),
}

impl fmt::Display for SpecterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::InvalidPcap(msg) => write!(f, "Invalid PCAP capture: {msg}"),
            Self::InvalidPacket(msg) => write!(f, "Invalid network frame: {msg}"),
            Self::MalformedTls(msg) => write!(f, "Malformed TLS record: {msg}"),
            Self::MalformedDns(msg) => write!(f, "Malformed DNS message: {msg}"),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {msg}"),
        }
    }
}

impl std::error::Error for SpecterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SpecterError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, SpecterError>;
