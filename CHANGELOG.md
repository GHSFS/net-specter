# Changelog

All notable changes to `net-specter` (`nspecter`) are documented in this file.

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
