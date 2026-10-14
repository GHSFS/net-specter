// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Operating system classification profiles and signature matching for p0f / JA4T.

use serde::{Deserialize, Serialize};

/// Operating system classification verdict with confidence rating.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsClassification {
    pub family: String,
    pub flavor: String,
    pub confidence: f64,
    pub match_reason: String,
}

/// Matches fingerprint parameters against operating system TCP/IP stack profiles.
pub fn classify_os(
    ittl: u8,
    options_kinds: &[u8],
    wscale: Option<u8>,
    _mss: Option<u16>,
    window_size: u16,
    _has_ts: bool,
    _ip_df: bool,
) -> OsClassification {
    // 1. Windows 10 / 11 / Server (kinds: MSS, NOP, WS, NOP, NOP, SACK)
    if options_kinds == [2, 1, 3, 1, 1, 4] && ittl == 128 {
        if wscale == Some(8) {
            return OsClassification {
                family: "Windows".into(),
                flavor: "Windows 10/11 / Server 2016-2022".into(),
                confidence: 0.95,
                match_reason: "Canonical Windows 10/11 SYN options layout and WSCALE 8".into(),
            };
        } else if window_size == 8192 || wscale == Some(2) {
            return OsClassification {
                family: "Windows".into(),
                flavor: "Windows 7/8 / Server 2008-2012".into(),
                confidence: 0.90,
                match_reason: "Windows 7/8 initial window/scale signature".into(),
            };
        }
        return OsClassification {
            family: "Windows".into(),
            flavor: "Windows NT/Desktop (Generic)".into(),
            confidence: 0.85,
            match_reason: "Standard Windows TCP options sequence".into(),
        };
    }

    // 2. Linux kernel 3.x - 6.x (kinds: MSS, SACK, TS, NOP, WS)
    if options_kinds == [2, 4, 8, 1, 3] {
        if ittl == 64 {
            return OsClassification {
                family: "Linux".into(),
                flavor: "Linux 3.x-6.x (Ubuntu/Debian/RHEL/Android)".into(),
                confidence: 0.95,
                match_reason: "Standard Linux kernel TCP options order (MSS, SACK, TS, NOP, WS)"
                    .into(),
            };
        }
        return OsClassification {
            family: "Linux".into(),
            flavor: "Linux (modified TTL)".into(),
            confidence: 0.80,
            match_reason: "Linux options sequence with non-standard TTL".into(),
        };
    }

    // 3. Apple macOS / iOS Darwin (kinds: MSS, NOP, WS, NOP, NOP, TS, SACK, EOL)
    if options_kinds == [2, 1, 3, 1, 1, 8, 4, 0] && ittl == 64 {
        return OsClassification {
            family: "Apple".into(),
            flavor: "macOS 12+ / iOS 15+ (Darwin)".into(),
            confidence: 0.95,
            match_reason: "Canonical Apple Darwin TCP options layout with trailing EOL".into(),
        };
    }

    // 4. FreeBSD / OpenBSD / macOS legacy (kinds: MSS, NOP, WS, NOP, NOP, TS, SACK)
    if options_kinds == [2, 1, 3, 1, 1, 8, 4] && ittl == 64 {
        return OsClassification {
            family: "BSD".into(),
            flavor: "FreeBSD / OpenBSD / macOS (BSD)".into(),
            confidence: 0.90,
            match_reason: "Standard BSD options sequence".into(),
        };
    }

    // 5. Port Scanners
    if options_kinds == [2] && window_size == 1024 {
        return OsClassification {
            family: "Scanner".into(),
            flavor: "Nmap SYN Scan".into(),
            confidence: 0.95,
            match_reason: "Nmap default SYN scan probe (Win: 1024, MSS only)".into(),
        };
    }
    if options_kinds.is_empty() {
        if window_size == 1024 {
            return OsClassification {
                family: "Scanner".into(),
                flavor: "Masscan SYN Probe".into(),
                confidence: 0.90,
                match_reason: "Masscan raw SYN probe (no TCP options, Win 1024)".into(),
            };
        }
        if window_size == 65535 {
            return OsClassification {
                family: "Scanner".into(),
                flavor: "ZMap SYN Probe".into(),
                confidence: 0.85,
                match_reason: "ZMap static window probe (no TCP options, Win 65535)".into(),
            };
        }
    }

    // 6. Network Equipment
    if ittl == 255 {
        return OsClassification {
            family: "Network Device".into(),
            flavor: "Cisco IOS / Solaris / Network Appliance".into(),
            confidence: 0.85,
            match_reason: "Initial TTL 255 network equipment signature".into(),
        };
    }

    // 7. General Fallbacks
    if ittl == 128 {
        OsClassification {
            family: "Windows".into(),
            flavor: "Windows (Generic Stack)".into(),
            confidence: 0.70,
            match_reason: "Initial TTL 128 heuristic".into(),
        }
    } else if ittl == 64 {
        OsClassification {
            family: "Unix".into(),
            flavor: "Unix / Linux / macOS (Generic)".into(),
            confidence: 0.65,
            match_reason: "Initial TTL 64 heuristic".into(),
        }
    } else {
        OsClassification {
            family: "Unknown".into(),
            flavor: "Generic TCP/IP stack".into(),
            confidence: 0.50,
            match_reason: "Unrecognized option layout and TTL".into(),
        }
    }
}
