// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use net_specter::http_inspect::{
    audit_http_bytes, compute_ja4h, compute_sha256_12, parse_http1_request, parse_http1_response,
    parse_http2_frames, HTTP2_PREFACE,
};
use std::fs;
use std::process::Command;

#[allow(clippy::too_many_arguments)]
fn build_ipv4_tcp_ethernet_frame(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(0x50); // data offset 5 (20 bytes)
    tcp.push(flags);
    tcp.extend_from_slice(&65535u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(payload);

    let total_ip_len = (20 + tcp.len()) as u16;
    let mut frame = Vec::with_capacity(14 + total_ip_len as usize);
    frame.extend_from_slice(&[0x00, 0x16, 0x3e, 0x10, 0x20, 0x30]);
    frame.extend_from_slice(&[0x00, 0x16, 0x3e, 0xaa, 0xbb, 0xcc]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());

    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&total_ip_len.to_be_bytes());
    frame.extend_from_slice(&0x1234u16.to_be_bytes());
    frame.extend_from_slice(&0x4000u16.to_be_bytes());
    frame.push(64);
    frame.push(6); // TCP
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);
    frame.extend_from_slice(&tcp);
    frame
}

fn wrap_packets_in_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());

    for (idx, f) in frames.iter().enumerate() {
        let len = f.len() as u32;
        pcap.extend_from_slice(&(1_700_000_000u32 + idx as u32).to_le_bytes());
        pcap.extend_from_slice(&100_000u32.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(f);
    }
    pcap
}

fn wrap_packets_in_pcapng(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut ng = Vec::new();
    // Section Header Block (28 bytes)
    ng.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
    ng.extend_from_slice(&28u32.to_le_bytes());
    ng.extend_from_slice(&0x1A2E3B4Cu32.to_le_bytes());
    ng.extend_from_slice(&1u16.to_le_bytes());
    ng.extend_from_slice(&0u16.to_le_bytes());
    ng.extend_from_slice(&(-1i64).to_le_bytes());
    ng.extend_from_slice(&28u32.to_le_bytes());

    // Interface Description Block (20 bytes)
    ng.extend_from_slice(&0x00000001u32.to_le_bytes());
    ng.extend_from_slice(&20u32.to_le_bytes());
    ng.extend_from_slice(&1u16.to_le_bytes()); // Ethernet
    ng.extend_from_slice(&0u16.to_le_bytes());
    ng.extend_from_slice(&65535u32.to_le_bytes());
    ng.extend_from_slice(&20u32.to_le_bytes());

    for f in frames {
        let orig_len = f.len();
        let pad = (4 - (orig_len % 4)) % 4;
        let total_len = (32 + orig_len + pad) as u32;
        ng.extend_from_slice(&0x00000006u32.to_le_bytes());
        ng.extend_from_slice(&total_len.to_le_bytes());
        ng.extend_from_slice(&0u32.to_le_bytes()); // interface_id
        ng.extend_from_slice(&0u32.to_le_bytes()); // ts_high
        ng.extend_from_slice(&1_000_000u32.to_le_bytes()); // ts_low
        ng.extend_from_slice(&(orig_len as u32).to_le_bytes());
        ng.extend_from_slice(&(orig_len as u32).to_le_bytes());
        ng.extend_from_slice(f);
        ng.extend(std::iter::repeat(0u8).take(pad));
        ng.extend_from_slice(&total_len.to_le_bytes());
    }
    ng
}

#[test]
fn test_http1_request_and_response_parsing() {
    let raw_req = b"POST /api/v1/telemetry HTTP/1.1\r\n\
Host: collector.example.org\r\n\
User-Agent: Mozilla/5.0\r\n\
Accept-Language: en-US,en;q=0.9\r\n\
Referer: https://portal.example.org/dashboard\r\n\
Cookie: z_token=xyz987; a_session=abc123\r\n\
Content-Type: application/json\r\n\
\r\n\
{\"event\":\"ping\"}";

    let req = parse_http1_request(raw_req).expect("Valid HTTP/1.1 POST request should parse");
    assert_eq!(req.method, "POST");
    assert_eq!(req.uri, "/api/v1/telemetry");
    assert_eq!(req.version, "HTTP/1.1");
    assert_eq!(
        req.referer.as_deref(),
        Some("https://portal.example.org/dashboard")
    );
    assert_eq!(req.cookies.len(), 2);
    assert_eq!(req.body_peek.as_deref(), Some("{\"event\":\"ping\"}"));
    assert_eq!(req.ja4h.ja4h_a, "po11cr04enus");
    assert!(req.ja4h.has_cookie);
    assert!(req.ja4h.has_referer);
    assert_eq!(req.ja4h.header_count, 4);

    let raw_resp = b"HTTP/1.1 201 Created\r\n\
Server: NetSpecter-Edge/1.0\r\n\
Set-Cookie: sid=deadbeef; HttpOnly; Secure\r\n\
Content-Type: application/json\r\n\
\r\n\
{\"status\":\"created\"}";

    let resp = parse_http1_response(raw_resp).expect("Valid HTTP/1.1 response should parse");
    assert_eq!(resp.version, "HTTP/1.1");
    assert_eq!(resp.status_code, 201);
    assert_eq!(resp.reason, "Created");
    assert_eq!(resp.cookies.len(), 1);
    assert_eq!(resp.body_peek.as_deref(), Some("{\"status\":\"created\"}"));
}

#[test]
fn test_ja4h_fingerprint_calculation_and_cookie_order_invariance() {
    let headers_no_cookie = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("User-Agent".to_string(), "curl/8.5.0".to_string()),
        ("Accept".to_string(), "*/*".to_string()),
    ];
    let fp = compute_ja4h("GET", "HTTP/1.1", &headers_no_cookie);
    assert_eq!(fp.ja4h_a, "ge11nn030000");
    assert_eq!(fp.ja4h_b, compute_sha256_12("Host,User-Agent,Accept"));
    assert_eq!(fp.ja4h_c, "000000000000");
    assert_eq!(fp.ja4h_d, "000000000000");
    assert_eq!(
        fp.ja4h,
        format!("ge11nn030000_{}_000000000000_000000000000", fp.ja4h_b)
    );

    // Cookie sorting invariance: "b=2; a=1" vs "a=1; b=2" must produce identical JA4H
    let headers_order_1 = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("Accept-Language".to_string(), "ko-KR,ko;q=0.8".to_string()),
        ("Cookie".to_string(), "zeta=999; alpha=111".to_string()),
    ];
    let headers_order_2 = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("Accept-Language".to_string(), "ko-KR,ko;q=0.8".to_string()),
        ("Cookie".to_string(), "alpha=111; zeta=999".to_string()),
    ];
    let fp1 = compute_ja4h("GET", "HTTP/1.1", &headers_order_1);
    let fp2 = compute_ja4h("GET", "HTTP/1.1", &headers_order_2);
    assert_eq!(fp1.ja4h_a, "ge11cn02kokr");
    assert_eq!(fp1.ja4h, fp2.ja4h);
    assert_eq!(fp1.ja4h_c, compute_sha256_12("alpha,zeta"));
    assert_eq!(fp1.ja4h_d, compute_sha256_12("111,999"));

    // HTTP/2 pseudo-header filtering (:method, :path, :authority ignored in header count)
    let h2_headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":path".to_string(), "/index.html".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        ("user-agent".to_string(), "h2client/1.0".to_string()),
        ("accept-language".to_string(), "en".to_string()),
    ];
    let fp_h2 = compute_ja4h("GET", "HTTP/2.0", &h2_headers);
    assert_eq!(fp_h2.ja4h_a, "ge20nn02en00");
    assert_eq!(fp_h2.header_count, 2);
}

#[test]
fn test_http2_preface_and_settings_frame_decoding() {
    let mut buf = Vec::new();
    buf.extend_from_slice(HTTP2_PREFACE);

    // Frame 1: SETTINGS (type=0x04, flags=0x00, stream_id=0, length=18 -> 3 params)
    buf.extend_from_slice(&[0x00, 0x00, 18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Param 1: HEADER_TABLE_SIZE (0x0001) = 4096
    buf.extend_from_slice(&0x0001u16.to_be_bytes());
    buf.extend_from_slice(&4096u32.to_be_bytes());
    // Param 2: MAX_CONCURRENT_STREAMS (0x0003) = 100
    buf.extend_from_slice(&0x0003u16.to_be_bytes());
    buf.extend_from_slice(&100u32.to_be_bytes());
    // Param 3: INITIAL_WINDOW_SIZE (0x0004) = 65535
    buf.extend_from_slice(&0x0004u16.to_be_bytes());
    buf.extend_from_slice(&65535u32.to_be_bytes());

    // Frame 2: WINDOW_UPDATE (type=0x08, flags=0x00, stream_id=0, length=4)
    buf.extend_from_slice(&[0x00, 0x00, 4, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&1048576u32.to_be_bytes());

    // Frame 3: HEADERS (type=0x01, flags=0x05 END_STREAM|END_HEADERS, stream_id=1, length=4)
    buf.extend_from_slice(&[0x00, 0x00, 4, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01]);
    buf.extend_from_slice(&[0x82, 0x84, 0x86, 0x41]);

    // Frame 4: PING (type=0x06, flags=0x00, stream_id=0, length=8)
    buf.extend_from_slice(&[0x00, 0x00, 8, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

    let h2 = parse_http2_frames(&buf).expect("Valid HTTP/2 stream should decode");
    assert!(h2.preface_valid);
    assert_eq!(h2.frames.len(), 4);
    assert_eq!(h2.settings.len(), 3);
    assert_eq!(h2.settings[0].name, "HEADER_TABLE_SIZE");
    assert_eq!(h2.settings[0].value, 4096);
    assert_eq!(h2.settings[1].name, "MAX_CONCURRENT_STREAMS");
    assert_eq!(h2.settings[1].value, 100);
    assert_eq!(h2.settings[2].name, "INITIAL_WINDOW_SIZE");
    assert_eq!(h2.settings[2].value, 65535);
    assert_eq!(h2.frames[1].frame_type_name, "WINDOW_UPDATE");
    assert_eq!(h2.frames[2].frame_type_name, "HEADERS");
    assert_eq!(h2.frames[2].stream_id, 1);
    assert_eq!(h2.frames[3].frame_type_name, "PING");
}

#[test]
fn test_pcap_and_pcapng_capture_http_audit() {
    let req_bytes =
        b"GET /status HTTP/1.1\r\nHost: internal.corp\r\nAccept-Language: en-GB\r\n\r\n";
    let resp_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";

    let mut h2_bytes = Vec::from(&HTTP2_PREFACE[..]);
    h2_bytes.extend_from_slice(&[0x00, 0x00, 6, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
    h2_bytes.extend_from_slice(&0x0002u16.to_be_bytes()); // ENABLE_PUSH
    h2_bytes.extend_from_slice(&0u32.to_be_bytes());

    let pkt1 = build_ipv4_tcp_ethernet_frame(
        [10, 1, 1, 5],
        50100,
        [10, 1, 1, 80],
        80,
        100,
        200,
        0x18,
        req_bytes,
    );
    let pkt2 = build_ipv4_tcp_ethernet_frame(
        [10, 1, 1, 80],
        80,
        [10, 1, 1, 5],
        50100,
        200,
        100 + req_bytes.len() as u32,
        0x18,
        resp_bytes,
    );
    let pkt3 = build_ipv4_tcp_ethernet_frame(
        [10, 1, 1, 5],
        50101,
        [10, 1, 1, 80],
        8080,
        500,
        600,
        0x18,
        &h2_bytes,
    );

    let frames = vec![pkt1, pkt2, pkt3];
    let pcap_bytes = wrap_packets_in_pcap(&frames);
    let pcapng_bytes = wrap_packets_in_pcapng(&frames);

    for capture in [&pcap_bytes, &pcapng_bytes] {
        let audit = audit_http_bytes(capture).expect("Capture HTTP audit should succeed");
        assert_eq!(audit.http1_requests.len(), 1);
        assert_eq!(audit.http1_responses.len(), 1);
        assert_eq!(audit.http2_connections.len(), 1);
        assert_eq!(audit.ja4h_fingerprints.len(), 1);
        assert_eq!(audit.ja4h_fingerprints[0].ja4h_a, "ge11nn02engb");
        assert_eq!(audit.http1_responses[0].status_code, 200);
        assert_eq!(audit.http2_connections[0].settings[0].name, "ENABLE_PUSH");
    }
}

#[test]
fn test_malformed_and_truncated_http_rejection() {
    assert!(audit_http_bytes(&[]).is_err());
    assert!(parse_http1_request(b"INVALID_LINE\r\n\r\n").is_err());
    assert!(parse_http1_response(b"HTTP/1.1 NOT_A_CODE OK\r\n\r\n").is_err());

    // Truncated HTTP/2 frame payload
    let mut bad_h2 = Vec::from(&HTTP2_PREFACE[..]);
    bad_h2.extend_from_slice(&[
        0x00, 0x00, 12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
    ]);
    assert!(parse_http2_frames(&bad_h2).is_err());

    // SETTINGS frame length not multiple of 6
    let mut bad_settings_len = Vec::from(&HTTP2_PREFACE[..]);
    bad_settings_len.extend_from_slice(&[
        0x00, 0x00, 5, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 1, 2, 3, 4, 5,
    ]);
    assert!(parse_http2_frames(&bad_settings_len).is_err());

    // SETTINGS frame on non-zero stream ID
    let mut bad_settings_stream = Vec::from(&HTTP2_PREFACE[..]);
    bad_settings_stream.extend_from_slice(&[0x00, 0x00, 0, 0x04, 0x01, 0x00, 0x00, 0x00, 0x01]);
    assert!(parse_http2_frames(&bad_settings_stream).is_err());
}

#[test]
fn test_cli_http_audit_subcommand_execution() {
    let raw_req = b"GET /healthz HTTP/1.1\r\nHost: edge.example.com\r\nUser-Agent: Probe/1.0\r\nAccept-Language: en-US\r\n\r\n";
    let hex_input = hex::encode(raw_req);

    let output = Command::new(env!("CARGO_BIN_EXE_nspecter"))
        .args(["http-audit", &hex_input, "--json"])
        .output()
        .expect("Failed to execute nspecter binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("CLI output must be valid JSON");
    assert_eq!(json["total_messages"], 1);
    assert_eq!(json["http1_requests"][0]["uri"], "/healthz");
    assert_eq!(json["ja4h_fingerprints"][0]["ja4h_a"], "ge11nn03enus");

    // Also test file-based PCAP input via temp file
    let pkt = build_ipv4_tcp_ethernet_frame(
        [192, 168, 1, 10],
        40000,
        [192, 168, 1, 1],
        80,
        1,
        1,
        0x18,
        raw_req,
    );
    let pcap_data = wrap_packets_in_pcap(&[pkt]);
    let temp_path = std::env::temp_dir().join("nspecter_http_audit_test.pcap");
    fs::write(&temp_path, &pcap_data).expect("Write temp pcap");

    let file_out = Command::new(env!("CARGO_BIN_EXE_nspecter"))
        .args(["http-audit", temp_path.to_str().unwrap(), "--json"])
        .output()
        .expect("Failed to execute nspecter on pcap file");
    let _ = fs::remove_file(&temp_path);

    assert!(file_out.status.success());
    let file_json: serde_json::Value =
        serde_json::from_slice(&file_out.stdout).expect("Valid JSON from file audit");
    assert_eq!(file_json["http1_requests"][0]["method"], "GET");
}
