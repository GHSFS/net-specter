# Changelog

All notable changes to `net-specter` (`nspecter`) are documented in this file.

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
