# Adversarial Reviewer Handoff: Milestone M06 (TLS ServerHello JA3S & X.509 Certificate Forensics)

## Review Verdict
- **Status**: Defects Identified, Hardened, and Successfully Re-verified.
- **Milestone**: M06 (v0.6.0)
- **Component**: `src/tls_cert.rs` (488 lines), `tests/tls_cert_test.rs` (715 lines, 7 integration tests).

## Defects Found in Prior Attempt
1. **UTF-8 Char Boundary Slicing Panic in `parse_der_time`**:
   - *Input*: UTCTime / GeneralizedTime ASN.1 octets containing valid multi-byte UTF-8 bytes (e.g. `b"2\xc3\xa90101000000Z"`).
   - *Expected*: Graceful rejection with `Err(SpecterError::MalformedCert(...))` without panicking.
   - *Actual*: Panicked with `byte index 2 is not a char boundary; it is inside '\u{e9}' (bytes 1..3)` because `std::str::from_utf8` accepts multi-byte UTF-8, and direct byte indexing `s[0..2]` / `s[2..4]` cut across code points.
   - *Root Cause*: In ASN.1 DER, time types (`UTCTime` 0x17 and `GeneralizedTime` 0x18) are restricted to ASCII digits and trailing ASCII `'Z'`. Added `if !data.is_ascii()` guard preventing char boundary panics.

2. **Pre-1970 Epoch Conversion Failure and False Negative Inverted Validity**:
   - *Input*: Certificates with UTCTime years in the range 1950..1969 (e.g. `500101000000Z` or `600101000000Z`, where two-digit years >= 50 represent 1950-1999 per RFC 5280).
   - *Expected*: Pre-1970 dates computed as negative epoch seconds, with inverted validity `1960 -> 1950` detected via `na_ep < nb_ep`.
   - *Actual*: `(1970..y)` in `to_epoch_seconds` evaluated to an empty range for `y < 1970`, resulting in `days = 0`. Both 1950 and 1960 returned epoch timestamp 0, causing `na_ep < nb_ep` to evaluate as `0 < 0` (false), missing inverted validity anomalies.
   - *Root Cause*: Looping year range `(1970..y)` failed for pre-epoch dates. Replaced with constant-time civil calendar arithmetic (`days_from_civil`) supporting any year with exact negative/positive day offsets.

3. **Arbitrary / Zero-filled Payloads Falsely Accepted as ServerHello**:
   - *Input*: Slices of non-TLS data >= 38 bytes (e.g. `[0u8; 50]`) passed to `parse_tls_server_hello`.
   - *Expected*: Return `Err(SpecterError::MalformedTls(...))`.
   - *Actual*: Fallback `else { payload }` treated arbitrary buffers as ServerHello bodies, returning fake `Ok(TlsServerHelloReport)` with version 0, cipher 0, and JA3S `"0,0,"`.
   - *Root Cause*: Missing handshake framing validation. Enforced explicit TLS record (`0x16`) or handshake (`0x02`) headers.

4. **Arbitrary Payloads Accepted into Certificate Parser Fallback**:
   - *Input*: Arbitrary non-TLS data passed to `parse_tls_certificates`.
   - *Expected*: Reject non-certificate framing with `Err(SpecterError::MalformedCert(...))`.
   - *Actual*: Fallback `else { payload }` attempted TLS 1.3/1.2 framing heuristics on arbitrary bytes.
   - *Root Cause*: Enforced explicit DER (`0x30`), TLS Record (`0x16`), or handshake (`0x0b`) framing.

5. **TLS Stream Scanner Aborting on False-Positive Record Header**:
   - *Input*: Payload with a false-positive byte `0x16` whose subsequent length field exceeds remaining bytes, followed by legitimate TLS ServerHello and Certificate records.
   - *Expected*: Scanner skips the false-positive byte (`r_off += 1`) and continues scanning, finding legitimate subsequent records.
   - *Actual*: `if r_end > payload.len() { break; }` aborted the entire outer loop, silently dropping all subsequent TLS handshakes in the stream.
   - *Root Cause*: Replaced premature `break` with `r_off += 1; continue;`.

6. **Unchecked DER Element Length Integer Overflow**:
   - *Input*: 4-byte length in DER element (e.g. `[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]`).
   - *Expected*: Return `Err(SpecterError::MalformedCert(...))` safely.
   - *Actual*: Potential integer overflow in `h_len + len`.
   - *Root Cause*: Hardened with `h_len.checked_add(len).filter(|&tot| tot <= buf.len())`.

7. **Untested IPv6 SANs and Missing SPKI Guard**:
   - *Hardening*: Supported canonical `std::net::Ipv6Addr` formatting in `parse_sans` and added missing `subjectPublicKeyInfo` check in `parse_x509_der`.

## Verification Record
- `cargo fmt --all`: Clean.
- `cargo clippy --all-targets -- -D warnings`: 0 warnings, 0 errors.
- `cargo test --all-targets`: 46/46 tests passing across all 7 integration test suites (`tls_cert_test` [7/7], `tcp_stream_test` [8/8], `ja4_test` [8/8], `pcapng_test` [8/8], `http_inspect_test` [6/6], `pcap_tls_test` [6/6], `dns_audit_test` [3/3]).
- `node scripts/verify_assets.mjs`: Clean (0 leaks, 21 valid SVGs).
- `node scripts/check.mjs`: Exit code 0.
- Soft ceiling: `src/tls_cert.rs` is 488 lines (strictly under 500 lines).
