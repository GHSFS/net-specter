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
5. **Bounded Out-of-Order TCP Stream Buffering**: Stateful TCP reassembly enforces strict per-stream memory buffer limits (`DEFAULT_MAX_OUT_OF_ORDER_BUFFER`) to prevent denial-of-service memory exhaustion when processing adversarial sparse-sequence packet floods.
6. **Constant-Time Cryptographic Verification & Secret Buffer Wiping**: QUIC Initial decryption enforces constant-time comparison of AEAD authentication tags, strict 16-byte sample bounds checking for header protection, and automatic `zeroize` wiping on drop for all derived symmetric keys, IVs, and decrypted payload buffers.
7. **Safe Statistical Aggregation & Flow Tracking**: C2 beacon jitter and spectrogram analysis enforce minimum flow event thresholds and bounded binning intervals, with zero-division safeguards against timestamp collisions and zero-variance distributions.
8. **SSH-2.0 Protocol & Salesforce HASSH Bounds Verification**: SSH banner and `SSH_MSG_KEXINIT` parsers enforce strict RFC 4253 bounds checks across packet lengths, padding lengths, and binary payload boundaries. Name-list parsing mandates checked slice offsets and safe bounds subtraction (`saturating_sub` / `checked_add`) to prevent integer overflows and memory exhaustion when processing adversarial, truncated, or cyclic packet sequences.

## Reporting a Vulnerability

If you discover a potential parser bug, denial-of-service vector, or security issue:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal `.pcap` or hex reproduction case.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
