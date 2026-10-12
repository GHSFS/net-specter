<div align="center">

[🇺🇸 English](../../README.md) · [🇰🇷 한국어](./ko.md) · [🇨🇳 中文](./zh-CN.md) · [🇪🇸 Español](./es.md) · [🇮🇳 हिन्दी](./hi.md) · [🇸🇦 العربية](./ar.md) · **🇧🇷 Português** · [🇷🇺 Русский](./ru.md) · [🇫🇷 Français](./fr.md) · [🇮🇩 Bahasa Indonesia](./id.md)

</div>
<br>

<p align="center">
  <img src="../assets/locales/pt-BR/banner.svg" alt="NetSpecter (nspecter) banner" width="100%" />
</p>

# NetSpecter (nspecter)

**Forense de Pacotes de Rede, Fingerprinting TLS JA3/JA4 e Detector de Canais Ocultos em Rust Puro**

[![CI](https://github.com/GHSFS/net-specter/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/net-specter/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](./Cargo.toml)
[![Zero Unsafe](https://img.shields.io/badge/Memory_Safety-100%25_Safe_Rust-10b981.svg)](../../SECURITY.md)

---

## 🛡️ Visão Geral e Recursos Principais

<details open>
<summary><b>🛡️ Visão Geral e Recursos Principais</b></summary>
<br>

O net-specter (nspecter) é um utilitário de linha de comando e biblioteca em Rust puro para análise forense offline de pacotes, extração de fingerprints TLS JA3 e detecção de tunelamento DNS sem depender da libpcap.

1. **Zero-Dependency PCAP Capture Engine (`src/pcap.rs`)** — Decodes classic libpcap `.pcap` files across both little-endian and big-endian microsecond/nanosecond headers (`0xA1B2C3D4`, `0xA1B23C4D`), Ethernet II frames (with IEEE 802.1Q VLAN tag unwrapping), Raw IP captures (`linktype 101`), IPv4/IPv6 headers, and TCP/UDP transport segments.
2. **TLS `ClientHello` Deep Inspector & JA3 Engine (`src/tls_ja3.rs`)** — Parses TLS Handshake (`0x16`) `ClientHello` (`0x01`) records, extracts SNI hostnames (`0x0000`), Supported Groups (`0x000a`), EC Point Formats (`0x000b`), ALPN protocols (`0x0010`), and Supported Versions (`0x002b`), filters RFC 8701 GREASE values (`0x?a?a`), and computes both **JA3 MD5** and **SHA-256** fingerprints.
3. **DNS Wire-Format Parser & Covert Tunneling Auditor (`src/dns.rs`)** — Decodes RFC 1035 DNS packets with strict compression pointer loop protection (`<= 32` hops) and scores subdomain Shannon entropy, label lengths, and hexadecimal/Base32 payload density to flag covert C2 or data exfiltration channels (`Low`, `Elevated`, `High`).
4. **Deterministic Capture Synthesis (`nspecter synth-pcap`)** — Generates self-contained multi-packet `.pcap` captures containing TLS 1.3 `ClientHello` and benign/covert DNS queries for reproducible CI testing and analyst validation.

</details>

---

## 🏛️ Arquitetura de Inspeção e Fingerprinting

<details open>
<summary><b>🏛️ Arquitetura de Inspeção e Fingerprinting</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/pt-BR/architecture.svg" alt="Arquitetura de Inspeção e Fingerprinting" width="100%" />
</p>

| # | Component | Module | Responsibility |
|---|---|---|---|
| **01** | **01 · Decodificador PCAP** | `src/pcap.rs` | Suporte Little/Big-Endian e decodificação Ethernet/VLAN/IPv4/IPv6/TCP/UDP |
| **02** | **02 · Inspetor TLS ClientHello** | `src/tls_ja3.rs` | Extração de SNI, ALPN, grupos de curvas elípticas e extensões TLS |
| **03** | **03 · Fingerprinting JA3** | `MD5 + SHA-256` | Filtragem GREASE RFC 8701 e geração de hashes MD5 e SHA-256 |
| **04** | **04 · Auditor de Tunelamento DNS** | `src/dns.rs` | Proteção contra loops de ponteiro RFC 1035 e entropia de Shannon |
| **05** | **05 · Síntese de Capturas PCAP** | `synth-pcap & --json` | Geração determinística de arquivos PCAP e saída JSON estruturada |

</details>

---

## 🚀 Início Rápido e Uso da CLI

<details open>
<summary><b>🚀 Início Rápido e Uso da CLI</b></summary>
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

## 📦 Referência de Módulos e Subcomandos

<details open>
<summary><b>📦 Referência de Módulos e Subcomandos</b></summary>
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

## 🔒 Segurança de Memória e Blindagem do Parser

<details open>
<summary><b>🔒 Segurança de Memória e Blindagem do Parser</b></summary>
<br>

- **100% Safe Rust**: Zero `unsafe` blocks across all binary frame decoders.
- **RFC 1035 Compression Loop Defense**: DNS name decompression enforces a strict 32-hop pointer ceiling and forward/self-pointer rejection.
- **Transient Buffer Zeroization**: Ephemeral TLS random and session ID byte buffers are wiped on drop via `zeroize`.
- **Policy & Vulnerability Reporting**: Refer to [SECURITY.md](../../SECURITY.md).

</details>

---

## 📄 Licença e Atribuição

<details open>
<summary><b>📄 Licença e Atribuição</b></summary>
<br>

```text
Copyright 2026 GHSFS

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
