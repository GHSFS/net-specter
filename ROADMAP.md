# NetSpecter Roadmap

This document tracks shipped capabilities and planned packet forensics, protocol fingerprinting, and network anomaly detection features for `nspecter`.

---

## Shipped Capabilities

- [x] **Core PCAP Capture Decoder, TLS `ClientHello` JA3 Fingerprinting & DNS Covert Tunneling Auditor (`v0.1.0`)** — Zero-dependency libpcap `.pcap` L2/L3/L4 frame decoder (Ethernet II, 802.1Q VLAN, Raw IP, IPv4/IPv6, TCP/UDP), RFC 8701 GREASE-filtered TLS `ClientHello` JA3 (MD5 + SHA-256) extractor with SNI/ALPN inspection, RFC 1035 DNS wire parser with pointer loop protection and Shannon entropy covert-channel scoring, and deterministic `.pcap` synthesis (`nspecter inspect-pcap`, `ja3`, `dns-audit`, `synth-pcap`).
- [x] **PCAPNG Next-Generation Capture Format & Multi-Interface Block Parser (`v0.2.0`)** — Native parsing of PCAPNG Section Header Blocks (`0x0A0D0D0A`), Interface Description Blocks, Enhanced Packet Blocks, and Simple Packet Blocks with nanosecond resolution, TLV options, and seamless CLI integration (`nspecter synth-pcap --pcapng`, `nspecter inspect-pcap`).
- [x] **JA4 & JA4S Modern TLS / QUIC Client & Server Fingerprinting Engine (`v0.3.0`)** — Compute FoxIO-compatible sorted JA4 client fingerprints (`t13d1516h2_<cipher_hash>_<ext_hash>`) and JA4S server response fingerprints resilient to TLS extension order randomization across TCP, QUIC Initial, and DTLS transports with zeroize hygiene (`nspecter ja4 <file_or_hex> [--json]`).

---

## Planned Milestones

### Capture Formats & Transport Reassembly
- [ ] **TCP Stream Reassembly & Out-of-Order Segment Tracker (`src/tcp_stream.rs`)** — Reconstruct bidirectional TCP byte streams across fragmented and out-of-order segments, tracking sequence numbers, retransmissions, and window scaling.
- [ ] **BPF-Style Packet Filter Expression Engine (`src/filter.rs`)** — Filter captures by IP CIDR, port ranges, transport protocol, TCP flag masks, and payload byte signatures (`--filter "tcp port 443 and syn"`).
- [ ] **IPv6 Extension Header & Fragmentation Chain Inspector (`src/ipv6_ext.rs`)** — Walk Hop-by-Hop, Routing, Fragment, and encapsulating security headers to detect evasion and overlapping fragment anomalies.
- [ ] **PCAP Sanitizer & PII Anonymizer (`src/anonymize.rs`)** — Prefix-preserving IPv4/IPv6 address pseudonymization, MAC scrubbing, and payload truncation for safe capture sharing (`nspecter scrub`).

### Cryptographic Protocol Fingerprinting
- [ ] **TLS `ServerHello` & X.509 Certificate Chain Forensics (`src/tls_cert.rs`)** — Extract JA3S server fingerprints, ASN.1 DER X.509 leaf/intermediate certificates, validity windows, subject alternative names, and self-signed/expired certificate alerts.
- [ ] **QUIC Initial Packet & RFC 9001 Header Protection Decryptor (`src/quic.rs`)** — Derive initial secrets from the QUIC version salt and Destination Connection ID (`DCID`) using HKDF-SHA256 to remove header protection and inspect embedded TLS 1.3 `ClientHello` frames over UDP/443.
- [ ] **Encrypted Client Hello (ECH / ESNI) & DoH Bootstrap Detector (`src/ech.rs`)** — Identify TLS `encrypted_client_hello` (`0xfe0d`) extensions and DNS `HTTPS`/`SVCB` (`TYPE65`) bootstrap records.
- [ ] **SSH Hassh Client & Server Key-Exchange Fingerprinting (`src/ssh_hassh.rs`)** — Parse `SSH_MSG_KEXINIT` packets and compute `HASSH` / `HASSHServer` MD5 and SHA-256 algorithm negotiation fingerprints.
- [ ] **TCP SYN Passive OS Fingerprinting (`src/p0f.rs`)** — Fingerprint client operating systems from initial TTL, TCP window size, MSS, SACK permitted, and TCP option ordering (`JA4T`).

### Covert Channel & Threat Hunting Analytics
- [ ] **C2 Beacon Jitter & Periodic Interval Spectrogram Detector (`src/beacon.rs`)** — Analyze inter-arrival timestamp deltas ($\Delta t$), coefficient of variation, and discrete Fourier periodicity across flow pairs to detect automated command-and-control heartbeats.
- [ ] **HTTP/1.1 & HTTP/2 Frame Inspector (`src/http_inspect.rs`)** — Parse HTTP request/response headers, HTTP/2 preface and `SETTINGS` frames (`JA4H`), and suspect user-agent or header ordering anomalies.
- [ ] **ICMP Echo Payload & Timing Covert Tunnel Detector (`src/icmp_tunnel.rs`)** — Audit ICMP Echo Request/Reply payloads for non-standard byte patterns, asymmetric sizes, and high-entropy data exfiltration.
- [ ] **SMB2/3 & DCE/RPC Lateral Movement Inspector (`src/smb.rs`)** — Decode SMB2 negotiation headers, tree connects (`IPC$`, `ADMIN$`, `C$`), and named pipe RPC bindings indicative of lateral movement.
- [ ] **ARP Spoofing & Layer-2 MITM Anomaly Detector (`src/arp_audit.rs`)** — Detect gratuitous ARP storms, duplicate IP-to-MAC bindings, and gateway MAC flapping inside Ethernet captures.
- [ ] **SOCKS5 & Shadowsocks High-Entropy Stream Classifier (`src/proxy_detect.rs`)** — Identify unauthenticated/authenticated SOCKS5 handshakes and uniform-entropy encrypted proxy streams on non-standard ports.
- [ ] **YARA-Style Hex & Regex Payload Signature Scanner (`src/sig_scan.rs`)** — Scan reassembled L4/L7 payloads against custom hex wildcards and byte-offset signature rules (`nspecter scan`).
- [ ] **Flow NetFlow v5/v9 & IPFIX Summary Exporter (`src/flow_export.rs`)** — Aggregate 5-tuple conversations with byte/packet counters, duration, TCP flag unions, and directional entropy metrics (`nspecter flows`).
- [ ] **SARIF & STIX 2.1 Threat Intelligence Report Exporter (`src/report_export.rs`)** — Export detected JA3/JA4 fingerprints, high-entropy DNS domains, and C2 beacon flows as structured SARIF or STIX 2.1 JSON bundles.
