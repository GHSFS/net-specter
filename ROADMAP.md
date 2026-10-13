# NetSpecter Roadmap

This document tracks shipped capabilities and planned packet forensics, protocol fingerprinting, and network anomaly detection features for `nspecter`.

---

## Shipped Capabilities

- [x] **Core PCAP Capture Decoder, TLS `ClientHello` JA3 Fingerprinting & DNS Covert Tunneling Auditor (`v0.1.0`)** — Zero-dependency libpcap `.pcap` L2/L3/L4 frame decoder (Ethernet II, 802.1Q VLAN, Raw IP, IPv4/IPv6, TCP/UDP), RFC 8701 GREASE-filtered TLS `ClientHello` JA3 (MD5 + SHA-256) extractor with SNI/ALPN inspection, RFC 1035 DNS wire parser with pointer loop protection and Shannon entropy covert-channel scoring, and deterministic `.pcap` synthesis (`nspecter inspect-pcap`, `ja3`, `dns-audit`, `synth-pcap`).
- [x] **PCAPNG Next-Generation Capture Format & Multi-Interface Block Parser (`v0.2.0`)** — Native parsing of PCAPNG Section Header Blocks (`0x0A0D0D0A`), Interface Description Blocks, Enhanced Packet Blocks, and Simple Packet Blocks with nanosecond resolution, TLV options, and seamless CLI integration (`nspecter synth-pcap --pcapng`, `nspecter inspect-pcap`).
- [x] **JA4 & JA4S Modern TLS / QUIC Client & Server Fingerprinting Engine (`v0.3.0`)** — Compute FoxIO-compatible sorted JA4 client fingerprints (`t13d1516h2_<cipher_hash>_<ext_hash>`) and JA4S server response fingerprints resilient to TLS extension order randomization across TCP, QUIC Initial, and DTLS transports with zeroize hygiene (`nspecter ja4 <file_or_hex> [--json]`).
- [x] **TCP Stream Reassembly & Out-of-Order Segment Tracker (`v0.4.0`)** — Reconstruct bidirectional TCP byte streams across fragmented, retransmitted, and out-of-order segments with RFC 793 32-bit sequence wrap-around, buffer memory DoS limits, and multi-segment TLS ClientHello (JA3/JA4) and HTTP inspection (`nspecter tcp-stream <file> [--dump-payload] [--json]`).
- [x] **HTTP/1.1 & HTTP/2 Frame Inspector & JA4H Header Fingerprinting (`v0.5.0`)** — Parse HTTP/1.1 request and response headers, cookies, referer, and body previews, decode RFC 7540 HTTP/2 connection prefaces, frame streams (`DATA`, `HEADERS`, `SETTINGS`, `WINDOW_UPDATE`, `PING`, `GOAWAY`), and `SETTINGS` parameters, and compute FoxIO-compliant `JA4H` client fingerprints across PCAP, PCAPNG, and raw streams (`nspecter http-audit <file_or_hex> [--json]`).
- [x] **TLS ServerHello JA3S & X.509 Certificate Chain Forensics (`v0.6.0`)** — Extract JA3S server fingerprints (MD5 and SHA-256 with RFC 8701 GREASE immunity), decode TLS 1.2 and TLS 1.3 `Certificate` (`0x0b`) handshake messages, zero-dependency ASN.1 DER parser for X.509 certificates (Subject/Issuer DN, validity windows, DNS/IP SANs, serial numbers, signature algorithms), and anomaly detection for expired, not yet valid, inverted validity, weak signature algorithms, and self-signed certificates across PCAP, PCAPNG, and reassembled TCP streams (`nspecter cert-audit <file_or_hex> [--json]`).
- [x] **QUIC Initial Packet & RFC 9001 Header Protection Decryptor (`v0.7.0`)** — Derive initial keys from RFC 9001 / RFC 9369 version salts and Destination Connection ID (`DCID`) using HKDF-SHA256, pure Rust AES-128 block cipher and AES-128-GCM authenticated decryption with $GF(2^{128})$ GHASH, strip header protection, reassemble CRYPTO frame byte streams, and extract TLS 1.3 ClientHello JA3 (MD5/SHA-256) and FoxIO JA4 / JA4S fingerprints over UDP/443 (`nspecter quic-audit <file_or_hex> [--json]`).
- [x] **C2 Beacon Jitter & Periodic Interval Spectrogram Detector (`v0.8.0`)** — Analyze flow inter-arrival timestamps ($\Delta t$), mean/variance/median jitter, coefficient of variation ($CV$), interval frequency spectrograms, and periodicity scores across PCAP/PCAPNG captures to detect automated C2 heartbeats and covert beaconing (`nspecter beacon-audit <file> [--json]`).
- [x] **BPF-Style Packet Filter Expression Engine (`v0.9.0`)** — Recursive-descent AST evaluator supporting IPv4/IPv6 CIDR matching, port and port-range filters, protocol tests, TCP flag masks, packet length comparisons, and boolean combinators across PCAP and PCAPNG captures (`nspecter filter <file> <expr> [--json]`, `inspect-pcap --filter`).
- [x] **SSH HASSH Client & Server Key-Exchange Fingerprinting (`v0.10.0`)** — Zero-dependency RFC 4253 SSH banner parser and `SSH_MSG_KEXINIT` (Type 20) decoder with packet header extraction and all 10 algorithm name-lists; computes Salesforce `HASSH` (client) and `HASSHServer` (server) raw strings, MD5 fingerprints, and SHA-256 extended digests across PCAP, PCAPNG, and raw byte streams (`nspecter hassh <file_or_hex> [--json]`).

---

## Planned Milestones

### Capture Formats & Transport Reassembly
- [ ] **IPv6 Extension Header & Fragmentation Chain Inspector (`src/ipv6_ext.rs`)** — Walk Hop-by-Hop, Routing, Fragment, and encapsulating security headers to detect evasion and overlapping fragment anomalies.
- [ ] **PCAP Sanitizer & PII Anonymizer (`src/anonymize.rs`)** — Prefix-preserving IPv4/IPv6 address pseudonymization, MAC scrubbing, and payload truncation for safe capture sharing (`nspecter scrub`).

### Cryptographic Protocol Fingerprinting
- [ ] **Encrypted Client Hello (ECH / ESNI) & DoH Bootstrap Detector (`src/ech.rs`)** — Identify TLS `encrypted_client_hello` (`0xfe0d`) extensions and DNS `HTTPS`/`SVCB` (`TYPE65`) bootstrap records.
- [ ] **TCP SYN Passive OS Fingerprinting (`src/p0f.rs`)** — Fingerprint client operating systems from initial TTL, TCP window size, MSS, SACK permitted, and TCP option ordering (`JA4T`).
- [ ] **TLS 1.3 Key Log (`SSLKEYLOGFILE`) Session Decryptor (`src/tls_decrypt.rs`)** — Parse NSS key log files to decrypt captured TLS sessions for offline deep inspection.
- [ ] **SNI Proxy & Transparent TLS Downgrade Detector (`src/sni_proxy.rs`)** — Detect mismatched SNI vs HTTP Host headers, TLS fallback signaling (`TLS_FALLBACK_SCSV`), and transparent proxy MITM anomalies.

### Covert Channel & Threat Hunting Analytics
- [ ] **ICMP Echo Payload & Timing Covert Tunnel Detector (`src/icmp_tunnel.rs`)** — Audit ICMP Echo Request/Reply payloads for non-standard byte patterns, asymmetric sizes, and high-entropy data exfiltration.
- [ ] **DNS-over-HTTPS (DoH) & DNS-over-TLS (DoT) Traffic Profiler (`src/doh_dot.rs`)** — Profile port 853 DoT sessions and identify wire-format DNS queries tunneled inside HTTP/2 / HTTP/3 DoH streams.
- [ ] **SMB2/3 & DCE/RPC Lateral Movement Inspector (`src/smb.rs`)** — Decode SMB2 negotiation headers, tree connects (`IPC$`, `ADMIN$`, `C$`), and named pipe RPC bindings indicative of lateral movement.
- [ ] **ARP Spoofing & Layer-2 MITM Anomaly Detector (`src/arp_audit.rs`)** — Detect gratuitous ARP storms, duplicate IP-to-MAC bindings, and gateway MAC flapping inside Ethernet captures.
- [ ] **SOCKS5 & Shadowsocks High-Entropy Stream Classifier (`src/proxy_detect.rs`)** — Identify unauthenticated/authenticated SOCKS5 handshakes and uniform-entropy encrypted proxy streams on non-standard ports.
- [ ] **YARA-Style Hex & Regex Payload Signature Scanner (`src/sig_scan.rs`)** — Scan reassembled L4/L7 payloads against custom hex wildcards and byte-offset signature rules (`nspecter scan`).
- [ ] **Flow NetFlow v5/v9 & IPFIX Summary Exporter (`src/flow_export.rs`)** — Aggregate 5-tuple conversations with byte/packet counters, duration, TCP flag unions, and directional entropy metrics (`nspecter flows`).
- [ ] **SARIF & STIX 2.1 Threat Intelligence Report Exporter (`src/report_export.rs`)** — Export detected JA3/JA4 fingerprints, high-entropy DNS domains, and C2 beacon flows as structured SARIF or STIX 2.1 JSON bundles.
