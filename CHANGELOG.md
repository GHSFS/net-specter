# Changelog

All notable changes to `net-specter` (`nspecter`) are documented in this file.

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
