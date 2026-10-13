# Original User Request

## 2026-10-13T09:35:00Z

This is a single self-contained fix; keep it small and focused.

Working directory: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\net-specter
Integrity mode: development

Requirements:
R1: Implement HTTP/1.1 & HTTP/2 Frame Inspector & JA4H Header Fingerprinting in src/http_inspect.rs (< 500 lines).
R2: Wire CLI subcommand nspecter http-audit in src/cli.rs and src/main.rs. Export in src/lib.rs.
R3: Write integration tests in tests/http_inspect_test.rs (< 450 lines).
R4: Update scripts/ARCHITECTURE_MAP.md, TASK_BACKLOG.md, ROADMAP.md, README.md, CHANGELOG.md.

Acceptance Criteria:
- All checks pass via node scripts/check.mjs and node scripts/verify_assets.mjs with exit code 0.
- All files modular (< 500-700 lines).
- 100% safe Rust, zero secrets, zeroize memory hygiene.


## 2026-10-13T01:35:59Z

This is a single self-contained fix; keep it small and focused.
Working directory: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\net-specter
Integrity mode: development

Teamwork Specification:
[R1] Milestone Focus: M06 — TLS ServerHello JA3S & X.509 Certificate Chain Forensics (v0.6.0)
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


## 2026-10-13T03:36:34Z

This is a single self-contained fix; keep it small and focused.

Working directory: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\net-specter
Integrity mode: development

Requirements:
R1: Implement C2 Beacon Jitter & Periodic Interval Spectrogram Detector in `src/beacon.rs` (< 500 lines) and register it in `src/lib.rs`, `src/cli.rs`, and `src/main.rs`.
R2: Support analyzing flow inter-arrival timestamps (delta t), mean, median, variance, std dev, coefficient of variation (jitter %), periodicity/regularity scores, and beacon classification verdicts (HighConfidenceBeacon, JitteredBeacon, SuspectInterval, Benign) across PCAP and PCAPNG captures.
R3: Add CLI subcommand `nspecter beacon-audit <file> [--min-events <n>] [--threshold <float>] [--json]`.
R4: Author comprehensive integration tests in `tests/beacon_test.rs` (< 500 lines) verifying strict beacons, jittered beacons, irregular/benign traffic, PCAP and PCAPNG captures, adversarial/empty captures, and CLI execution.

Acceptance Criteria:
- All source files remain under 500–700 lines.
- `node scripts/check.mjs` and `node scripts/verify_assets.mjs` exit with 0.
