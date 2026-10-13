// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::commands::load_bytes_or_hex;
use crate::error::{Result, SpecterError};
use crate::tls_cert::audit_cert_bytes;

pub fn handle_cert_audit(file_or_hex: &str, json: bool) -> Result<()> {
    let bytes = load_bytes_or_hex(file_or_hex)?;
    let report = audit_cert_bytes(&bytes)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?
        );
    } else {
        println!(
            "TLS Forensic Audit: {} ServerHello(s), {} Certificate(s) ({} anomalies)",
            report.server_hellos.len(),
            report.certificates.len(),
            report.total_anomalies
        );
        for sh in &report.server_hellos {
            println!(
                "  [ServerHello JA3S] Ver=0x{:04x} Cipher=0x{:04x} JA3S={} MD5={} SHA256={}",
                sh.server_version, sh.cipher_suite, sh.ja3s_string, sh.ja3s_md5, sh.ja3s_sha256
            );
        }
        for (i, c) in report.certificates.iter().enumerate() {
            println!(
                "  [Cert #{}] Subject=\"{}\" Issuer=\"{}\" Serial={} Algo={}",
                i + 1,
                c.subject,
                c.issuer,
                c.serial_number,
                c.signature_algorithm
            );
            println!("    Validity: {} to {}", c.not_before, c.not_after);
            if !c.sans_dns.is_empty() {
                println!("    SANs DNS: {}", c.sans_dns.join(", "));
            }
            if !c.sans_ip.is_empty() {
                println!("    SANs IP: {}", c.sans_ip.join(", "));
            }
            if c.is_self_signed {
                println!("    Self-Signed: true");
            }
            if !c.anomalies.is_empty() {
                println!("    Anomalies: {}", c.anomalies.join(", "));
            }
        }
    }
    Ok(())
}
