// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Deterministic synthetic PCAP generator for TCP SYN passive OS fingerprinting test cases.

/// Builds a deterministic synthetic `.pcap` capture containing Windows, Linux, macOS, and scanner SYN packets.
pub fn build_synthetic_syn_pcap() -> Vec<u8> {
    let mut pcap = Vec::with_capacity(2048);
    // 24-byte PCAP header: magic (0xA1B2C3D4), v2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype Ethernet (1)
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&[0u8; 8]);
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());

    type SynthPacketSpec = ([u8; 4], [u8; 4], u16, u16, u8, u16, Vec<u8>, u8);
    let packets: Vec<SynthPacketSpec> = vec![
        // 1. Windows 10/11 client SYN (TTL 128, Win 64240, MSS 1460, WS 8, SACK)
        (
            [192, 168, 1, 50],
            [10, 0, 0, 1],
            49152,
            443,
            128,
            64240,
            vec![2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2], // MSS 1460, NOP, WS 8, NOP, NOP, SACK
            0x02,
        ),
        // 2. Linux 6.x client SYN (TTL 64, Win 64240, MSS 1460, SACK, TS, WS 7)
        (
            [192, 168, 1, 60],
            [10, 0, 0, 1],
            52410,
            443,
            64,
            64240,
            vec![
                2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 1, 0x30, 0x39, 0, 0, 0, 0, 1, 3, 3, 7,
            ], // MSS 1460, SACK, TS, NOP, WS 7
            0x02,
        ),
        // 3. Apple macOS 14.x client SYN (TTL 64, Win 65535, MSS 1460, WS 6, TS, SACK, EOL)
        (
            [192, 168, 1, 70],
            [10, 0, 0, 1],
            58920,
            443,
            64,
            65535,
            vec![
                2, 4, 0x05, 0xb4, 1, 3, 3, 6, 1, 1, 8, 10, 0, 2, 0x49, 0xf0, 0, 0, 0, 0, 4, 2, 0, 0,
            ], // MSS 1460, NOP, WS 6, NOP, NOP, TS, SACK, EOL, NOP
            0x02,
        ),
        // 4. Nmap SYN scanner probe (TTL 64, Win 1024, MSS 1460 only)
        (
            [10, 10, 10, 99],
            [10, 0, 0, 1],
            38472,
            80,
            64,
            1024,
            vec![2, 4, 0x05, 0xb4], // MSS 1460
            0x02,
        ),
        // 5. Anomalous SYN+FIN probe (TTL 5, Win 0, zero window and invalid flag)
        (
            [10, 10, 10, 99],
            [10, 0, 0, 1],
            38473,
            8080,
            5,
            0,
            vec![],
            0x03, // SYN | FIN
        ),
    ];

    for (i, (src, dst, sport, dport, ttl, win, opts, flags)) in packets.into_iter().enumerate() {
        let opt_len = opts.len();
        let data_offset = ((20 + opt_len) / 4) as u8;
        let mut tcp_hdr = Vec::with_capacity(20 + opt_len);
        tcp_hdr.extend_from_slice(&sport.to_be_bytes());
        tcp_hdr.extend_from_slice(&dport.to_be_bytes());
        tcp_hdr.extend_from_slice(&((1000 * (i as u32 + 1)).to_be_bytes())); // seq
        tcp_hdr.extend_from_slice(&0u32.to_be_bytes()); // ack
        tcp_hdr.push(data_offset << 4);
        tcp_hdr.push(flags);
        tcp_hdr.extend_from_slice(&win.to_be_bytes());
        tcp_hdr.extend_from_slice(&[0u8; 2]); // checksum
        tcp_hdr.extend_from_slice(&[0u8; 2]); // urgent ptr
        tcp_hdr.extend_from_slice(&opts);

        let ip_len = (20 + tcp_hdr.len()) as u16;
        let mut ip_hdr = Vec::with_capacity(20);
        ip_hdr.push(0x45); // IPv4, IHL 5
        ip_hdr.push(0x00);
        ip_hdr.extend_from_slice(&ip_len.to_be_bytes());
        ip_hdr.extend_from_slice(&((i as u16 + 100).to_be_bytes()));
        ip_hdr.extend_from_slice(&[0x40, 0x00]); // DF bit set
        ip_hdr.push(ttl);
        ip_hdr.push(6); // TCP
        ip_hdr.extend_from_slice(&[0u8; 2]); // checksum
        ip_hdr.extend_from_slice(&src);
        ip_hdr.extend_from_slice(&dst);

        let mut eth = Vec::with_capacity(14 + ip_hdr.len() + tcp_hdr.len());
        eth.extend_from_slice(&[0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef]);
        eth.extend_from_slice(&[0x00, 0x50, 0x56, 0x12, 0x34, 0x56]);
        eth.extend_from_slice(&[0x08, 0x00]); // IPv4
        eth.extend_from_slice(&ip_hdr);
        eth.extend_from_slice(&tcp_hdr);

        let incl_len = eth.len() as u32;
        pcap.extend_from_slice(&(1700000000u32 + i as u32).to_le_bytes());
        pcap.extend_from_slice(&(i as u32 * 100_000).to_le_bytes());
        pcap.extend_from_slice(&incl_len.to_le_bytes());
        pcap.extend_from_slice(&incl_len.to_le_bytes());
        pcap.extend_from_slice(&eth);
    }

    pcap
}
