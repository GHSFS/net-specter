# Security Policy

## Supported Versions

Security updates are applied to the latest release series on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| Latest (`0.x`) | :white_check_mark: |
| `< 0.1.0` | :x:                |

## Memory Safety & Packet Parser Invariants

1. **Zero Unsafe Code**: All L2/L3/L4 frame decoders, TLS record inspectors, and DNS wire parsers are implemented in 100% safe Rust without `unsafe` pointer arithmetic.
2. **Strict Bounds & Pointer Hop Protection**: Untrusted network captures enforce explicit slice length bounds and RFC 1035 DNS compression pointer hop limits (`<= 32` hops) to prevent infinite decompression loops and out-of-bounds reads.
3. **Ephemeral Buffer Hygiene**: Sensitive session identifiers, TLS random values, and extracted payload buffers implement `zeroize` wiping on drop where applicable.
4. **Deterministic Resource Limits**: Capture readers reject malformed packet headers whose captured length (`incl_len`) exceeds snaplen or remaining file capacity, preventing allocation exhaustion attacks.

## Reporting a Vulnerability

If you discover a potential parser bug, denial-of-service vector, or security issue:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal `.pcap` or hex reproduction case.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
