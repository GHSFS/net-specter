// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::commands::load_bytes_or_hex;
use crate::dns::parse_dns_packet;
use crate::error::{Result, SpecterError};
use crate::pcap::parse_pcap_bytes;
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};

pub fn handle_dns_audit(file_or_hex: &str, json: bool) -> Result<()> {
    let raw = load_bytes_or_hex(file_or_hex)?;
    let reports = if is_pcapng(&raw) {
        let pcapng_rep = parse_pcapng_bytes(&raw)?;
        if pcapng_rep.dns_messages.is_empty() {
            return Err(SpecterError::MalformedDns(
                "No DNS packets found in PCAPNG capture".into(),
            ));
        }
        pcapng_rep.dns_messages
    } else if let Ok(pcap_rep) = parse_pcap_bytes(&raw) {
        if pcap_rep.dns_messages.is_empty() {
            return Err(SpecterError::MalformedDns(
                "No DNS packets found in PCAP capture".into(),
            ));
        }
        pcap_rep.dns_messages
    } else {
        vec![parse_dns_packet(&raw)?]
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
            for q in &rep.questions {
                println!(
                    "QNAME={} QTYPE={} Entropy={:.3} LongestLabel={} Risk={:?} ({}/100)",
                    q.qname,
                    q.qtype_name,
                    q.subdomain_entropy,
                    q.longest_label_len,
                    q.risk_level,
                    q.risk_score
                );
            }
        }
    }
    Ok(())
}
