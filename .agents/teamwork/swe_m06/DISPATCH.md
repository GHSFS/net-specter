## 2026-10-13T01:35:59Z
You are the SWE Light orchestrator for the net-specter project.

Working directory: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\net-specter\.agents\teamwork\swe_m06
Project root: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\net-specter
Original request file: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\net-specter\.agents\teamwork\ORIGINAL_REQUEST.md

Task Requirements:
Milestone Focus: M06 — TLS ServerHello JA3S & X.509 Certificate Chain Forensics (v0.6.0)
[R1] Core Implementation:
- Parse TLS ServerHello (0x02) handshakes for TLS version, cipher suite, extensions, GREASE filtering, and compute JA3S string, MD5, and SHA-256 digests.
- Parse TLS Certificate messages (0x0b) supporting both TLS 1.2 and TLS 1.3 formats.
- Implement zero-dependency ASN.1 DER parser for X.509 certificates in src/tls_cert.rs extracting Subject DN, Issuer DN, validity timestamps (notBefore, notAfter), SANs (DNS and IP), serial number, signature algorithm, self-signed detection, and certificate anomalies (expired, not yet valid, inverted validity, weak algorithm).
- Implement PCAP / PCAPNG capture file extraction across raw frames and TCP streams.
- Add CLI subcommand `cert-audit` in src/cli.rs and src/main.rs.
- Maintain soft ceiling 300-500 lines for src/tls_cert.rs.

[R2] Dedicated Integration Test Suite:
- Create tests/tls_cert_test.rs with tests for:
  - JA3S string and hash computation with GREASE immunity.
  - TLS 1.2 and TLS 1.3 Certificate message extraction.
  - ASN.1 DER X.509 certificate parsing (Subject, Issuer, SANs, validity, self-signed).
  - Anomaly detection (expired, weak crypto, self-signed).
  - PCAP / PCAPNG capture extraction.
  - CLI `cert-audit` command and `--json` flag.

[R3] Architecture Map & Backlog Sync:
- Update scripts/ARCHITECTURE_MAP.md with src/tls_cert.rs and tests/tls_cert_test.rs.
- Mark M06 [x] in TASK_BACKLOG.md and expand queue if needed.
- Update public ROADMAP.md, README.md, and CHANGELOG.md in natural senior engineer style with zero AI attribution.

[R4] Acceptance Criteria:
- node scripts/check.mjs and node scripts/verify_assets.mjs pass with exit code 0.

Maintain your progress in progress.md and BRIEFING.md inside your working directory.
When finished and all checks pass, report completion and handoff.md back to the sentinel.
