# Changelog

All notable changes to `net-specter` (`nspecter`) are documented in this file.

## [0.10.0] - 2026-10-13

### Added
- **SSH HASSH Client & Server Key-Exchange Fingerprinting (`src/ssh_hassh.rs`)**:
  - Implemented zero-dependency RFC 4253 Section 4.2 identification banner parser extracting protocol version, software identification string, and optional comments, with support for line feeds and server preamble lines.
  - Implemented RFC 4253 Section 7.1 `SSH_MSG_KEXINIT` (message type 20 / 0x14) parser decoding packet header length, padding length, 16-byte random cookie, and all 10 name-lists (`kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms_client_to_server`, `encryption_algorithms_server_to_client`, `mac_algorithms_client_to_server`, `mac_algorithms_server_to_client`, `compression_algorithms_client_to_server`, `compression_algorithms_server_to_client`, `languages_client_to_server`, `languages_server_to_client`), plus `first_kex_packet_follows`.
  - Added Salesforce `HASSH` (client) and `HASSHServer` (server) fingerprint calculation producing raw delimiter-separated algorithm strings, 32-character lowercase MD5 digests, and 64-character lowercase SHA-256 extended hashes.
  - Added capture auditing (`audit_ssh_bytes`) supporting classic PCAP, PCAPNG, and raw byte/hex payloads with bidirectional TCP stream reassembly endpoint tracking.
  - Added deterministic synthetic SSH packet generator (`build_synthetic_ssh_kexinit`) and multi-frame PCAP generator (`build_synthetic_ssh_pcap`).
- **CLI Command Modularization (`src/commands/` & `src/main.rs`)**:
  - Decomposed monolithic 708-line CLI handler in `src/main.rs` into isolated domain submodules under `src/commands/` (`inspect`, `tls`, `dns`, `tcp`, `http`, `cert`, `quic`, `synth`, `beacon`, `filter`, `hassh`), reducing `src/main.rs` to under 25 lines in compliance with `docs/VIBE_CODING_MODULAR_GUIDE.md` Pattern B.
  - Added CLI subcommand `nspecter hassh <file_or_hex> [--json]`.
- **Integration Test Suite (`tests/ssh_hassh_test.rs`)**:
  - Added 9 isolated integration tests covering RFC 4253 banner parsing (OpenSSH, PuTTY, Dropbear, preamble headers), exact Salesforce HASSH/HASSHServer raw string and MD5/SHA-256 calculation, synthetic client/server KEXINIT parsing, synthetic PCAP capture auditing, adversarial truncated/corrupted packet bounds testing, and CLI subprocess execution.

## [0.9.0] - 2026-10-13

### Added
- **BPF-Style Packet Filter Expression Engine (`src/filter/`)**:
  - Implemented recursive-descent tokenizer and AST evaluator supporting protocol predicates (`tcp`, `udp`, `icmp`, `ip`, `ip6`), directional qualifiers (`src`, `dst`), IPv4/IPv6 host and CIDR subnet matching (`net 192.168.0.0/16`, `2001:db8::/32`), port and port-range filters (`port 443`, `portrange 1024-2048`), TCP flag expressions (`tcp[tcpflags] & (tcp-syn|tcp-ack) != 0`, `tcpflags syn,ack`, `syn and not ack`), packet length comparisons (`len >= 1500`), and boolean combinators (`and`, `or`, `not`, parenthesized grouping).
- **CLI Subcommand (`nspecter filter` & `inspect-pcap --filter`)**:
  - Added `nspecter filter <file> <expr> [--json]` and `--filter` option on `inspect-pcap`.
- **Integration Test Suite (`tests/filter_test.rs`)**:
  - Added 9 integration tests covering BPF expression parsing, IPv4/IPv6 CIDR matching, port ranges, TCP flag bitmasks, packet length filters, PCAP/PCAPNG capture filtering, adversarial input rejection, and CLI execution.

## [0.8.0] - 2026-10-13

### Added
- **C2 Beacon Jitter & Periodic Interval Spectrogram Detector (`src/beacon.rs`)**:
  - Implemented 5-tuple flow grouping across IPv4/IPv6 TCP and UDP frames extracted from PCAP and PCAPNG captures.
  - Computed flow inter-arrival deltas ($\Delta t = t_{i+1} - t_i$), arithmetic mean, median, sample variance, standard deviation, and coefficient of variation ($CV$ / jitter %).
  - Constructed interval frequency spectrograms with automatic binning, identifying dominant heartbeat intervals, fundamental frequencies ($f = 1/\tau$), and peak power energy ratios.
  - Calculated periodicity and regularity scores evaluating closeness to median, delta clustering, and coefficient of variation.
  - Implemented automated verdict classification: `HighConfidenceBeacon` (strict periodic heartbeats, $\le 8\%$ jitter), `JitteredBeacon` ($\le 45\%$ jitter), `SuspectInterval` ($\le 70\%$ jitter), and `Benign` (bursty/irregular traffic or insufficient events).
- **CLI Subcommand (`nspecter beacon-audit`)**:
  - Added `nspecter beacon-audit <file> [--min-events <n>] [--threshold <val>] [--json]` supporting `.pcap` and `.pcapng` capture files with formatted tabular and JSON outputs.
- **Integration Test Suite (`tests/beacon_test.rs`)**:
  - Added 7 integration tests covering statistical deltas, spectrogram binning, beacon classification verdicts, multi-flow synthetic PCAP and PCAPNG captures, adversarial and empty buffer handling, and CLI execution.

## [0.7.0] - 2026-10-13

### Added
- **QUIC Initial Packet & RFC 9001 Header Protection Decryptor (`src/quic.rs`, `src/quic_crypto.rs`)**:
  - Implemented RFC 9001 key schedule derivation using HKDF-SHA256 from the Initial Salt and Destination Connection ID (`DCID`).
  - Added support for QUIC v1 (`0x00000001`), QUIC v2 (`0x6b3343cf`, RFC 9369), and draft-29 (`0xff00001d`) initial salt constants.
  - Implemented pure Rust AES-128 block cipher (NIST FIPS 197) for header protection sampling and mask unmasking.
  - Implemented pure Rust AES-128-GCM authenticated decryption (NIST SP 800-38D) with $GF(2^{128})$ GHASH and constant-time authentication tag validation.
  - Added zeroize memory wiping for all intermediate cryptographic keys, initialization vectors, and decrypted buffers on drop.
- **QUIC Frame & CRYPTO Stream Reassembly**:
  - Parsed QUIC variable-length integers (RFC 9000 Section 16) and frame sequences across PADDING, PING, ACK, and CRYPTO frames.
  - Reassembled fragmented or ordered CRYPTO chunks by stream offset.
  - Extracted embedded TLS 1.3 `ClientHello` and `ServerHello` handshake messages.
  - Computed full JA3 strings, MD5 fingerprints, SHA-256 digests, and FoxIO `JA4` / `JA4S` fingerprints (`q13d...`, `q1301...`) over QUIC UDP transport.
- **Capture File Auditing & CLI Integration**:
  - Added `audit_quic_bytes` and `audit_quic_capture_bytes` scanning classic `.pcap` and `.pcapng` capture files for UDP port 443 QUIC Initial packets.
  - Added CLI subcommand `nspecter quic-audit <file_or_hex> [--json]`.
- **Integration Test Suite (`tests/quic_test.rs`)**:
  - Added 8 integration tests covering RFC 9001 Appendix A HKDF key derivation test vectors, NIST SP 800-38D GCM test vectors, synthetic Client Initial and Server Initial packet decryption, QUIC v2 packet handling, PCAP/PCAPNG capture extraction, adversarial truncated/corrupted packet rejection, and CLI execution.

## [0.6.0] - 2026-10-13

### Added
- **TLS ServerHello JA3S Fingerprinting Engine (`src/tls_cert.rs`)**:
  - Parses TLS Handshake (`0x16`) `ServerHello` (`0x02`) records across TLS 1.2 and TLS 1.3 negotiated sessions.
  - Extracts server version, negotiated cipher suite, extension vectors, ALPN protocol selections, and TLS 1.3 `supported_versions` (`0x002b`).
  - Implements RFC 8701 GREASE filtering (`0x?a?a`) for server extensions to compute canonical JA3S strings, MD5 digests, and SHA-256 extended hashes.
- **TLS 1.2 & TLS 1.3 Certificate Message Extraction**:
  - Decodes TLS `Certificate` (`0x0b`) handshake messages supporting both TLS 1.2 (`certificates_length` + sequence of certificates) and RFC 8446 TLS 1.3 (`certificate_request_context` + `CertificateEntry` list with per-entry extensions).
- **Zero-Dependency ASN.1 DER Parser for X.509 Certificates**:
  - Implemented lightweight, memory-safe ASN.1 DER parser in `src/tls_cert.rs` without external cryptographic or ASN.1 dependencies.
  - Extracts X.509 Subject DN and Issuer DN attributes (`CN`, `O`, `OU`, `C`, `L`, `ST`, `emailAddress`).
  - Decodes validity intervals (`notBefore`, `notAfter`) across both `UTCTime` (`0x17`) and `GeneralizedTime` (`0x18`) into ISO 8601 timestamps and Unix epoch seconds.
  - Decodes Subject Alternative Names (SANs) for DNS names (`[2]` IA5String) and IP addresses (`[7]` IPv4/IPv6).
  - Extracts serial numbers (hexadecimal representation) and signature algorithm identifiers (`sha256WithRSAEncryption`, `ecdsa-with-SHA256`, etc.).
  - Detects certificate anomalies including expiration (`expired`), pre-validity (`not_yet_valid`), inverted validity intervals (`inverted_validity`), legacy/weak algorithms (`weak_algorithm` for MD2/MD5/SHA-1), and self-signed certificates (`self_signed`).
- **PCAP & PCAPNG Forensic Capture Auditing**:
  - Implemented `audit_cert_bytes` to extract ServerHello handshakes and X.509 certificate chains across raw capture frames and reassembled TCP streams with automatic deduplication.
- **CLI Subcommand (`nspecter cert-audit`)**:
  - Added `nspecter cert-audit <file_or_hex> [--json]` in `src/cli.rs` and `src/main.rs`.
- **Integration Test Suite (`tests/tls_cert_test.rs`)**:
  - Added 7 integration tests covering JA3S computation with GREASE immunity, X.509 DER parsing, TLS 1.2 / TLS 1.3 certificate message extraction, anomaly detection (expired, weak crypto, self-signed), PCAP / PCAPNG capture extraction, CLI `cert-audit --json` execution, and adversarial bounds / length overflow attacks.

## [0.5.0] - 2026-10-13

### Added
- **HTTP/1.1 & HTTP/2 Frame Inspector (`src/http_inspect.rs`)**:
  - Parses HTTP/1.1 client requests (method, URI, version, headers, cookies, `Referer`, and body previews) and server responses (version, status code, reason phrase, `Set-Cookie`, headers, and body previews).
  - Decodes RFC 7540 / RFC 9113 HTTP/2 connection prefaces (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) and 9-byte binary frame headers across `DATA`, `HEADERS`, `PRIORITY`, `RST_STREAM`, `SETTINGS`, `PUSH_PROMISE`, `PING`, `GOAWAY`, `WINDOW_UPDATE`, and `CONTINUATION` frame types.
  - Extracts and validates HTTP/2 `SETTINGS` parameters (`HEADER_TABLE_SIZE`, `ENABLE_PUSH`, `MAX_CONCURRENT_STREAMS`, `INITIAL_WINDOW_SIZE`, `MAX_FRAME_SIZE`, `MAX_HEADER_LIST_SIZE`, `ENABLE_CONNECT_PROTOCOL`) with strict stream-ID and frame-length verification.
  - Wipes transient request/response buffers on drop via `zeroize`.
- **FoxIO JA4H HTTP Client Fingerprinting Engine**:
  - Computes 4-segment `JA4H` client fingerprints (`<method><version><cookie><referer><header_count><lang>_<headers_hash>_<cookie_names_hash>_<cookie_values_hash>`) and raw `ja4h_r` representations.
  - Filters HTTP/2 pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`), normalizes `Accept-Language` tags, and sorts cookie key-value pairs alphabetically for cookie-order invariance.
- **CLI Subcommand (`nspecter http-audit`)**:
  - Added `nspecter http-audit <file_or_hex> [--json]` supporting classic `.pcap`, next-generation `.pcapng` (via automatic TCP stream reassembly), raw HTTP files, and hex-encoded payloads.
- **Integration Test Suite (`tests/http_inspect_test.rs`)**:
  - Added 6 integration tests covering HTTP/1.1 request/response parsing, JA4H fingerprint calculation and cookie-order invariance, HTTP/2 preface and `SETTINGS` frame decoding, PCAP/PCAPNG capture extraction, malformed frame rejection, and CLI `--json` execution.

## [0.4.0] - 2026-10-13

### Added
- **TCP Stream Reassembly & Out-of-Order Segment Tracker (`src/tcp_stream.rs`)**:
  - Implemented bidirectional TCP stream reassembly and state tracking (SYN, FIN, RST, sequence numbers) across client and server directions.
  - Added RFC 793 sequence arithmetic modulo $2^{32}$ handling 32-bit sequence wrap-around without data loss.
  - Implemented out-of-order segment buffering with deterministic gap draining and overlapping retransmission deduplication.
  - Added bounded memory management per stream (`DEFAULT_MAX_OUT_OF_ORDER_BUFFER`) to prevent denial-of-service memory exhaustion from fragmented or sparse segment floods.
  - Integrated zeroize memory hygiene on reassembled stream buffers upon teardown.
- **Application-Layer Inspection over Reassembled Streams**:
  - Transparently decodes fragmented multi-segment TLS `ClientHello` handshakes and extracts JA3 (MD5/SHA-256) and JA4 client fingerprints across TCP segment boundaries.
  - Detects HTTP/1.1 request/response flows, HTTP/2 connection prefaces, and SSH protocol banners from reassembled byte streams.
- **CLI Subcommand Integration (`nspecter tcp-stream`)**:
  - Added `nspecter tcp-stream <file> [--dump-payload] [--json]` supporting both classic `.pcap` and next-generation `.pcapng` capture formats.
  - Emits per-stream metrics (packet counts, retransmitted bytes, out-of-order counts, handshake status, duration) and optional hexadecimal payload dumps.
- **Dedicated Integration Test Suite (`tests/tcp_stream_test.rs`)**:
  - Added 8 comprehensive integration tests covering in-order HTTP flows, out-of-order gap draining, overlapping retransmissions, multi-segment fragmented TLS ClientHello inspection, 32-bit sequence wrap-around, buffer memory limit protections, and CLI command execution.

## [0.3.0] - 2026-10-13

### Added
- **JA4 & JA4S Modern TLS & QUIC Fingerprint Engine (`src/ja4.rs`)**:
  - Implemented FoxIO-compatible sorted JA4 client fingerprinting (`t13d1516h2_<cipher_hash>_<ext_hash>`) and JA4S server response fingerprinting (`t1302h2_1301_<ext_hash>`).
  - Added support for TCP (`t`), QUIC (`q`), and DTLS (`d`) transport protocols with RFC 8701 GREASE filtering (`0x?a?a`) across cipher suites, extensions, supported versions, and signature algorithms, with RFC 6347 DTLS 13-byte record and 12-byte handshake fragment parsing.
  - Implemented QUIC Initial packet inspection with RFC 9000 variable-length integer parsing and unencrypted/CRYPTO frame extraction over UDP.
  - Added zeroize memory hygiene to automatically scrub transient TLS/DTLS random bytes, session ID buffers, and handshake cookies on drop.
  - Implemented PCAP/PCAPNG capture bytes extraction (`extract_ja4_from_capture_bytes`) for offline batch fingerprinting.
- **CLI Subcommand Integration (`nspecter ja4`)**:
  - Added `nspecter ja4 <file_or_hex> [--quic] [--json]` supporting `.pcap`, `.pcapng`, or raw hexadecimal TLS ClientHello/ServerHello payloads.
  - Structured output provides human-readable formatted summary or full JSON telemetry for SIEM and threat intelligence correlation.
- **Comprehensive Integration Test Suite (`tests/ja4_test.rs`)**:
  - Validated JA4 client and JA4S server fingerprint calculation and GREASE immunity.
  - Verified SNI IP (`i`) versus domain (`d`) classification and ALPN edge cases (e.g., `h2`, `00`).
  - Tested QUIC Initial packet decoding, DTLS record header and cookie/epoch handling, malformed/truncated record rejection, PCAP/PCAPNG capture extraction, and CLI execution.

## [0.2.0] - 2026-10-13

### Added
- **PCAPNG Next-Generation Capture Format & Multi-Interface Block Parser (`src/pcapng.rs`)**:
  - Implemented Section Header Block (`0x0A0D0D0A` SHB) parser with Byte Order Magic detection for both little-endian (`0x4D3C2E1A`) and big-endian architectures, decoding hardware, OS, and user application metadata.
  - Implemented Interface Description Block (`0x00000001` IDB) parser supporting link types, snap lengths, interface names, descriptions, and arbitrary timestamp resolution (`if_tsresol`).
  - Implemented Enhanced Packet Block (`0x00000006` EPB) and Simple Packet Block (`0x00000003` SPB) frame decoders with nanosecond timestamp reconstruction and automatic alignment padding.
  - Added TLV block option parser with bounds verification and memory exhaustion limits.
  - Added deterministic multi-packet PCAPNG capture generation (`nspecter synth-pcap <output> --pcapng`).
- **CLI & Forensics Pipeline Integration**:
  - Enabled automatic capture format detection (`is_pcapng`) across `inspect-pcap`, `ja3`, and `dns-audit` subcommands, inspecting flows, TLS handshakes, and DNS messages from PCAPNG captures transparently.
  - Added dedicated integration test suite (`tests/pcapng_test.rs`) covering synthetic capture decoding, nanosecond timestamp accuracy, graceful unknown block skipping, and malformed header rejection.

## [0.1.0] - 2026-10-13

### Added
- **Zero-Dependency PCAP Capture Engine (`src/pcap.rs`)**:
  - Parses classic libpcap `.pcap` captures across little-endian and big-endian microsecond/nanosecond magic headers (`0xA1B2C3D4`, `0xA1B23C4D`) and link-layer encapsulations (`LINKTYPE_ETHERNET = 1` with IEEE 802.1Q VLAN tag unwrapping and `LINKTYPE_RAW_IP = 101`).
  - Decodes IPv4 and IPv6 L3 headers and TCP/UDP L4 transport headers with strict length and snaplen bounds verification.
  - Provides deterministic multi-packet `.pcap` synthesis (`nspecter synth-pcap <output>`) containing TLS 1.3 `ClientHello` and DNS wire frames for offline verification.
- **TLS `ClientHello` Inspector & JA3 Fingerprint Engine (`src/tls_ja3.rs`)**:
  - Inspects TLS Handshake (`0x16`) `ClientHello` (`0x01`) records and extracts TLS versions, cipher suites, extensions, Server Name Indication (`0x0000` SNI), Supported Groups (`0x000a`), EC Point Formats (`0x000b`), ALPN protocols (`0x0010`), and Supported Versions (`0x002b`).
  - Filters RFC 8701 GREASE identifiers (`0x?a?a`) before constructing canonical JA3 strings and computing both **MD5 JA3** and **SHA-256** digests (`nspecter ja3 <file_or_hex> [--json]`).
  - Wipes transient random and session ID byte buffers on drop via `zeroize`.
- **DNS Wire-Format Parser & Covert Tunneling Auditor (`src/dns.rs`)**:
  - Parses 12-byte DNS headers and RFC 1035 compressed/uncompressed QNAME labels with a 32-hop pointer limit to defend against cyclic compression pointer denial-of-service payloads.
  - Computes subdomain Shannon entropy, longest label length, and hexadecimal/Base32 encoding ratios to classify covert tunneling risk (`Low`, `Elevated`, `High`) via `nspecter dns-audit <file_or_hex> [--json]`.
