<div align="center">

[🇺🇸 English](../../README.md) · [🇰🇷 한국어](./ko.md) · **🇨🇳 中文** · [🇪🇸 Español](./es.md) · [🇮🇳 हिन्दी](./hi.md) · [🇸🇦 العربية](./ar.md) · [🇧🇷 Português](./pt-BR.md) · [🇷🇺 Русский](./ru.md) · [🇫🇷 Français](./fr.md) · [🇮🇩 Bahasa Indonesia](./id.md)

</div>
<br>

<p align="center">
  <img src="../assets/locales/zh-CN/banner.svg" alt="NetSpecter (nspecter) banner" width="100%" />
</p>

# NetSpecter (nspecter)

**零依赖纯 Rust 网络数据包取证、TLS JA3/JA4 指纹识别与隐蔽信道检测引擎**

[![CI](https://github.com/GHSFS/net-specter/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/net-specter/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](./Cargo.toml)
[![Zero Unsafe](https://img.shields.io/badge/Memory_Safety-100%25_Safe_Rust-10b981.svg)](../../SECURITY.md)

---

## 🛡️ 项目概述与核心能力

<details open>
<summary><b>🛡️ 项目概述与核心能力</b></summary>
<br>

net-specter (nspecter) 是一款基于纯 Rust 构建的高速、内存安全离线数据包取证工具，无需依赖 libpcap 即可完成 L2-L7 协议解码、TLS JA3 指纹提取与 DNS 隐蔽隧道检测。

1. **Zero-Dependency PCAP Capture Engine (`src/pcap.rs`)** — Decodes classic libpcap `.pcap` files across both little-endian and big-endian microsecond/nanosecond headers (`0xA1B2C3D4`, `0xA1B23C4D`), Ethernet II frames (with IEEE 802.1Q VLAN tag unwrapping), Raw IP captures (`linktype 101`), IPv4/IPv6 headers, and TCP/UDP transport segments.
2. **TLS `ClientHello` Deep Inspector & JA3 Engine (`src/tls_ja3.rs`)** — Parses TLS Handshake (`0x16`) `ClientHello` (`0x01`) records, extracts SNI hostnames (`0x0000`), Supported Groups (`0x000a`), EC Point Formats (`0x000b`), ALPN protocols (`0x0010`), and Supported Versions (`0x002b`), filters RFC 8701 GREASE values (`0x?a?a`), and computes both **JA3 MD5** and **SHA-256** fingerprints.
3. **DNS Wire-Format Parser & Covert Tunneling Auditor (`src/dns.rs`)** — Decodes RFC 1035 DNS packets with strict compression pointer loop protection (`<= 32` hops) and scores subdomain Shannon entropy, label lengths, and hexadecimal/Base32 payload density to flag covert C2 or data exfiltration channels (`Low`, `Elevated`, `High`).
4. **Deterministic Capture Synthesis (`nspecter synth-pcap`)** — Generates self-contained multi-packet `.pcap` captures containing TLS 1.3 `ClientHello` and benign/covert DNS queries for reproducible CI testing and analyst validation.

</details>

---

## 🏛️ 数据包取证与指纹识别架构

<details open>
<summary><b>🏛️ 数据包取证与指纹识别架构</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/zh-CN/architecture.svg" alt="数据包取证与指纹识别架构" width="100%" />
</p>

| # | Component | Module | Responsibility |
|---|---|---|---|
| **01** | **01 · PCAP 捕获解码器** | `src/pcap.rs` | 支持大小端微秒/纳秒 PCAP 头与 Ethernet/VLAN/IPv4/IPv6/TCP/UDP 解码 |
| **02** | **02 · TLS 握手深度检查** | `src/tls_ja3.rs` | 提取 SNI 域名、ALPN 协议列表、椭圆曲线组与支持版本扩展 |
| **03** | **03 · JA3 密码学指纹** | `MD5 + SHA-256` | RFC 8701 GREASE 过滤与标准 JA3 MD5 及 SHA-256 双重摘要计算 |
| **04** | **04 · DNS 隐蔽隧道审计** | `src/dns.rs` | RFC 1035 压缩指针环路防护（32 跳上限）与子域名香农熵风险评分 |
| **05** | **05 · 确定性样本合成** | `synth-pcap & --json` | 一键生成包含 TLS 1.3 与 DNS 样本的 PCAP 文件并输出结构化 JSON |

</details>

---

## 🚀 快速开始与命令行指南

<details open>
<summary><b>🚀 快速开始与命令行指南</b></summary>
<br>

```bash
# 1. Build the release binary
cargo build --release

# 2. Generate a deterministic sample .pcap capture (TLS 1.3 ClientHello + DNS packets)
./target/release/nspecter synth-pcap sample.pcap

# 3. Inspect all L2/L3/L4 flows, TLS JA3 handshakes, and DNS queries in a capture
./target/release/nspecter inspect-pcap sample.pcap
./target/release/nspecter inspect-pcap sample.pcap --json

# 4. Extract TLS ClientHello details and JA3 MD5 / SHA-256 digests from a .pcap or hex string
./target/release/nspecter ja3 sample.pcap --json

# 5. Audit DNS packets for high-entropy covert tunneling / C2 exfiltration
./target/release/nspecter dns-audit sample.pcap --json
```

</details>

---

## 📦 核心模块与子命令参考

<details open>
<summary><b>📦 核心模块与子命令参考</b></summary>
<br>

```text
net-specter/
├── Cargo.toml                     # Crate manifest (net-specter / nspecter binary)
├── README.md                      # Primary English documentation
├── ROADMAP.md                     # Shipped capabilities & upcoming milestones
├── CHANGELOG.md                   # Release history
├── SECURITY.md                    # Memory safety & parser security policy
├── LICENSE                        # Apache-2.0 License
├── NOTICE                         # Attribution notice (GHSFS)
├── src/
│   ├── lib.rs                     # Public library exports
│   ├── main.rs                    # CLI entrypoint & output formatter
│   ├── cli.rs                     # Clap subcommand definitions
│   ├── error.rs                   # Unified SpecterError & Result<T>
│   ├── pcap.rs                    # Libpcap .pcap decoder, L2/L3/L4 parser & generator
│   ├── tls_ja3.rs                 # TLS ClientHello parser, GREASE filter & JA3 engine
│   └── dns.rs                     # RFC 1035 DNS decoder & Shannon entropy tunnel auditor
└── tests/
    ├── pcap_tls_test.rs           # PCAP, L2/L3/L4, GREASE & JA3 integration tests
    └── dns_audit_test.rs          # DNS compression loop & covert tunnel integration tests
```

See [ROADMAP.md](../../ROADMAP.md) for planned PCAPNG, JA4/JA4S, QUIC Initial decryption, and TCP stream reassembly capabilities.

</details>

---

## 🔒 内存安全与解析器加固

<details open>
<summary><b>🔒 内存安全与解析器加固</b></summary>
<br>

- **100% Safe Rust**: Zero `unsafe` blocks across all binary frame decoders.
- **RFC 1035 Compression Loop Defense**: DNS name decompression enforces a strict 32-hop pointer ceiling and forward/self-pointer rejection.
- **Transient Buffer Zeroization**: Ephemeral TLS random and session ID byte buffers are wiped on drop via `zeroize`.
- **Policy & Vulnerability Reporting**: Refer to [SECURITY.md](../../SECURITY.md).

</details>

---

## 📄 开源许可证与归属声明

<details open>
<summary><b>📄 开源许可证与归属声明</b></summary>
<br>

```text
Copyright 2026 GHSFS

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
