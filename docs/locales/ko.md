<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <strong>🇰🇷 한국어</strong> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="../assets/locales/ko/banner.svg" alt="NetSpecter (nspecter) banner" width="100%" />
</p>

# NetSpecter (nspecter)

**외부 C 의존성 없는 순수 Rust 네트워크 패킷 포렌식, TLS JA3/JA4 핑거프린팅 및 은닉 채널 탐지 엔진**

[![CI](https://github.com/GHSFS/net-specter/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/net-specter/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](../../Cargo.toml)
[![Zero Unsafe](https://img.shields.io/badge/Memory_Safety-100%25_Safe_Rust-10b981.svg)](../../SECURITY.md)

</div>

---

## 🛡️ 개요 및 핵심 기능

<details open>
<summary><b>🛡️ 개요 및 핵심 기능</b></summary>
<br>

net-specter (nspecter)는 외부 C 라이브러리(libpcap 등) 의존성 없이 순수 Rust로 구현된 고속 오프라인 패킷 포렌식, 암호화 핸드셰이크 핑거프린팅 및 은닉 터널링 탐지 CLI 도구이자 라이브러리입니다.

1. **외부 의존성 제로의 PCAP & PCAPNG 캡처 엔진 (`src/pcap.rs` & `src/pcapng.rs`)** — 리틀엔디안 및 빅엔디안 마이크로초/나노초 헤더(`0xA1B2C3D4`, `0xA1B23C4D`)를 지원하는 클래식 libpcap `.pcap` 파일, Ethernet II 프레임(IEEE 802.1Q VLAN 태그 언래핑 포함), Raw IP 캡처(`linktype 101`), IPv4/IPv6 헤더 및 TCP/UDP 전송 세그먼트 디코딩 지원. 임의의 타임스탬프 정밀도를 갖춘 차세대 `.pcapng` 섹션 헤더 블록(SHB, `0x0A0D0D0A`), 인터페이스 설명 블록(IDB), 향상된 패킷 블록(EPB), 단순 패킷 블록(SPB) 파싱 지원.
2. **TLS `ClientHello` 심층 검사기 및 JA3 엔진 (`src/tls_ja3.rs`)** — TLS 핸드셰이크(`0x16`) `ClientHello`(`0x01`) 레코드를 정밀 파싱하여 SNI 호스트명(`0x0000`), 지원 그룹(`0x000a`), EC 포인트 포맷(`0x000b`), ALPN 프로토콜(`0x0010`), 지원 버전(`0x002b`) 추출. RFC 8701 GREASE 값(`0x?a?a`) 자동 필터링 및 **JA3 MD5**와 **SHA-256** 핑거프린트 동시 산출.
3. **DNS 유선 포맷 파서 및 은닉 터널링 감사기 (`src/dns.rs`)** — 엄격한 압축 포인터 루프 방어(`<= 32` 홉) 기능을 갖춘 RFC 1035 DNS 패킷 디코딩 및 서브도메인 섀넌 엔트로피, 레이블 길이, 16진수/Base32 페이로드 밀도 점수화를 통해 은닉 C2 및 데이터 유출 채널 탐지(`Low`, `Elevated`, `High`).
4. **결정론적 패킷 캡처 합성기 (`nspecter synth-pcap`)** — 재현 가능한 CI 테스트 및 보안 분석가 검증을 위해 TLS 1.3 `ClientHello` 및 정상/은닉 DNS 쿼리를 포함하는 독립형 멀티 패킷 `.pcap` 및 `.pcapng` 캡처 파일 자동 생성.
5. **JA4 & JA4S 차세대 TLS / QUIC 핑거프린팅 엔진 (`src/ja4.rs`)** — TCP, QUIC, DTLS 전송 계층 전반에서 TLS 확장 필드 순서 무작위화에 내성을 갖는 FoxIO 호환 정렬 JA4 클라이언트 핑거프린트(`t13d1516h2_<cipher_hash>_<ext_hash>`) 및 JA4S 서버 응답 핑거프린트 산출.
6. **TCP 스트림 재조립 및 순서 역전(Out-of-Order) 세그먼트 추적기 (`src/tcp_stream.rs`)** — RFC 793 32비트 시퀀스 래핑, DoS 방어 메모리 한도 관리, 단편화·재전송·순서 역전 세그먼트에 대한 양방향 TCP 바이트 스트림 재조립 및 멀티 세그먼트 애플리케이션 프로토콜 심층 검사(TLS JA3/JA4, HTTP/1.1, HTTP/2, SSH).
7. **HTTP/1.1 & HTTP/2 프레임 검사기 및 JA4H 핑거프린팅 (`src/http_inspect.rs`)** — HTTP/1.1 요청 및 응답 파싱, HTTP/2 연결 서문(preface), 바이너리 프레임 스트림, `SETTINGS` 파라미터 디코딩 및 FoxIO 규격 호환 `JA4H` 클라이언트 핑거프린트 산출 (`nspecter http-audit`).
8. **TLS ServerHello JA3S 및 X.509 인증서 체인 포렌식 (`src/tls_cert.rs`)** — JA3S 서버 응답 핑거프린트(RFC 8701 GREASE 면역 MD5 및 SHA-256) 추출, TLS 1.2 및 TLS 1.3 `Certificate`(`0x0b`) 메시지 디코딩, X.509 인증서용 제로 디펜던시 ASN.1 DER 파서(주체/발급자 DN, 유효 기간 타임스탬프, DNS/IP SAN, 일련번호, 서명 알고리즘) 제공 및 PCAP, PCAPNG, 재조립된 TCP 스트림 전반의 인증서 이상 징후(만료, 미래 유효, 역전된 유효 기간, 취약한 서명 알고리즘, 자체 서명) 탐지 (`nspecter cert-audit`).
9. **QUIC 초기 패킷 및 RFC 9001 복호화기 (`src/quic.rs`, `src/quic_crypto.rs`)** — HKDF-SHA256 기반 초기 키 유도, RFC 9001 헤더 보호 마스킹 해제, 순수 Rust AES-128-GCM 기반 QUIC Initial 패킷 복호화, CRYPTO 프레임 재조립 및 UDP/443 상의 TLS 1.3 JA3/JA4 핑거프린트 추출 (`nspecter quic-audit`).
10. **C2 비콘 지터 및 주기적 간격 스펙트로그램 탐지기 (`src/beacon.rs`)** — 플로우 패킷 간 도착 시차($Delta t$), 평균/분산/중앙값 지터, 변동 계수($CV$), 간격 주파수 스펙트로그램 및 주기성 점수를 분석하여 PCAP 및 PCAPNG 캡처 전반에서 자동화된 C2 하트비트 분류(`HighConfidenceBeacon`, `JitteredBeacon`, `SuspectInterval`, `Benign`) 수행 (`nspecter beacon-audit`).
11. **BPF 스타일 패킷 필터 표현식 엔진 (`src/filter/`)** — IPv4/IPv6 CIDR, 포트 범위, 전송 프로토콜, TCP 플래그 마스크, 프레임 길이에 대한 패킷 필터 표현식 평가 (`nspecter filter`).
12. **SSH HASSH 클라이언트 및 서버 키 교환 핑거프린팅 (`src/ssh_hassh.rs`)** — RFC 4253 SSH 배너 및 `SSH_MSG_KEXINIT` 패킷을 파싱하여 PCAP, PCAPNG, 원시 바이트 스트림 전반에서 Salesforce `HASSH` 및 `HASSHServer` MD5와 SHA-256 핑거프린트 산출 (`nspecter hassh`).

</details>

---

## 🏛️ 패킷 포렌식 및 핑거프린팅 아키텍처

<details open>
<summary><b>🏛️ 패킷 포렌식 및 핑거프린팅 아키텍처</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/ko/architecture.svg" alt="패킷 포렌식 및 핑거프린팅 아키텍처" width="100%" />
</p>

| # | 구성요소 | 모듈 | 담당 역할 |
|---|---|---|---|
| **01** | **01 · PCAP 유선 디코더** | `src/pcap.rs` | 리틀/빅엔디안 마이크로초/나노초 libpcap 파서 및 Ethernet/VLAN/IPv4/IPv6/TCP/UDP 해독 |
| **02** | **02 · TLS ClientHello 검사기** | `src/tls_ja3.rs` | 제로카피 SNI, ALPN, 지원 그룹, EC 포맷 및 버전 추출기 |
| **03** | **03 · JA3 암호 핑거프린팅** | `MD5 + SHA-256` | RFC 8701 GREASE 필터링 및 표준 JA3 문자열·이중 다이제스트 산출 엔진 |
| **04** | **04 · DNS 터널링 감사기** | `src/dns.rs` | RFC 1035 포인터 루프 방어(<=32 홉) 및 섀넌 엔트로피 기반 C2 점수화 |
| **05** | **05 · 패킷 합성 랩** | `synth-pcap & --json` | 결정론적 멀티 패킷 PCAP 생성기 및 구조화된 JSON 텔레메트리 출력 |

</details>

---

## 🚀 빠른 시작 및 CLI 사용법

<details open>
<summary><b>🚀 빠른 시작 및 CLI 사용법</b></summary>
<br>

```bash
# 1. 릴리스 바이너리 빌드
cargo build --release

# 2. 결정론적 샘플 .pcap 또는 .pcapng 캡처 생성 (TLS 1.3 ClientHello + DNS 패킷)
./target/release/nspecter synth-pcap sample.pcap
./target/release/nspecter synth-pcap sample.pcapng --pcapng

# 3. 캡처 파일(.pcap 또는 .pcapng) 내 모든 플로우, TLS JA3 핸드셰이크, DNS 쿼리 정밀 검사
./target/release/nspecter inspect-pcap sample.pcap
./target/release/nspecter inspect-pcap sample.pcapng --json

# 4. 캡처 또는 16진수 문자열에서 TLS ClientHello 상세 정보 및 JA3 MD5 / SHA-256 다이제스트 추출
./target/release/nspecter ja3 sample.pcapng --json

# 5. 캡처 또는 16진수 문자열에서 FoxIO JA4 클라이언트 및 JA4S 서버 핑거프린트 추출
./target/release/nspecter ja4 sample.pcapng --json

# 6. 고엔트로피 은닉 터널링 및 C2 데이터 유출에 대한 DNS 패킷 감사
./target/release/nspecter dns-audit sample.pcapng --json

# 7. 양방향 TCP 스트림 재조립 및 애플리케이션 페이로드 검사
./target/release/nspecter tcp-stream sample.pcapng --json

# 8. HTTP/1.1 및 HTTP/2 프레임 검사 및 JA4H HTTP 클라이언트 핑거프린트 산출
./target/release/nspecter http-audit capture.pcap --json

# 9. TLS ServerHello JA3S 핑거프린트 및 X.509 인증서 체인 포렌식 감사
./target/release/nspecter cert-audit capture.pcap --json

# 10. QUIC Initial 패킷 복호화 및 TLS 1.3 JA3/JA4 핑거프린트 추출
./target/release/nspecter quic-audit capture.pcap --json

# 11. C2 비콘 지터 및 주기적 간격 스펙트로그램 감사
./target/release/nspecter beacon-audit capture.pcap --min-events 4 --json

# 12. BPF 스타일 표현식을 사용한 캡처 프레임 필터링
./target/release/nspecter filter capture.pcap "tcp port 443" --json

# 13. SSH 배너 추출, KEXINIT 협상 파싱 및 Salesforce HASSH 핑거프린트 산출
./target/release/nspecter hassh capture.pcap --json

# 14. 은닉 터널 및 페이로드 변조에 대한 ICMP Echo Request/Reply 플로우 감사
./target/release/nspecter icmp-tunnel capture.pcap --dump-payload --json

# 15. TCP SYN 패킷 기반 수동 운영체제 핑거프린팅 (p0f v3 및 FoxIO JA4T)
./target/release/nspecter os-fp capture.pcap --json

# 16. 스푸핑, Gratuitous 플러딩 및 L2 MITM 이상 징후에 대한 ARP 요청/응답 감사
./target/release/nspecter arp-audit capture.pcap --gateway 192.168.1.1 --json
```

</details>

---

## 📦 모듈 및 서브커맨드 명세

<details open>
<summary><b>📦 모듈 및 서브커맨드 명세</b></summary>
<br>

```text
net-specter/
├── Cargo.toml                     # 크레이트 매니페스트 (net-specter 라이브러리 및 nspecter 바이너리)
├── README.md                      # 영문 메인 문서
├── ROADMAP.md                     # 구현 완료 기능 및 향후 개발 로드맵
├── CHANGELOG.md                   # 버전별 릴리스 변경 이력
├── SECURITY.md                    # 메모리 안전성 및 파서 보안 정책
├── LICENSE                        # Apache-2.0 라이선스
├── NOTICE                         # 저작권 고지 (GHSFS)
├── src/
│   ├── lib.rs                     # 공개 라이브러리 인터페이스 모듈
│   ├── main.rs                    # CLI 엔트리포인트 (25줄 미만의 간결한 디스패처)
│   ├── cli.rs                     # Clap 서브커맨드 및 인자 정의
│   ├── error.rs                   # 통합 SpecterError 및 Result<T> 정의
│   ├── commands/                  # 모듈형 CLI 커맨드 핸들러 (arp, inspect, tls, dns, tcp, http, cert, quic, synth, beacon, filter, hassh, icmp, os_fp)
│   ├── filter/                    # BPF 스타일 재귀 하강 필터 파서 및 평가기
│   ├── arp_audit.rs               # RFC 826 / RFC 5227 ARP 스푸핑 및 L2 MITM 탐지기
│   ├── p0f/                       # 수동 OS 핑거프린팅 및 FoxIO JA4T/JA4TS 엔진
│   ├── icmp_tunnel.rs             # ICMP Echo 은닉 터널 및 페이로드 변조 탐지기
│   ├── beacon.rs                  # C2 비콘 지터 및 간격 스펙트로그램 탐지기
│   ├── pcap.rs                    # Libpcap .pcap 디코더, L2/L3/L4 파서 및 생성기
│   ├── pcapng.rs                  # PCAPNG 블록 파서 (SHB/IDB/EPB/SPB) 및 생성기
│   ├── quic.rs                    # QUIC Initial 패킷 및 CRYPTO 스트림 추출기
│   ├── quic_crypto.rs             # 순수 Rust HKDF-SHA256, AES-128 & GCM 복호화기
│   ├── ssh_hassh.rs               # SSH-2.0 배너 및 Salesforce HASSH/HASSHServer 엔진
│   ├── tls_ja3.rs                 # TLS ClientHello 파서, GREASE 필터 및 JA3 엔진
│   ├── tls_cert.rs                # TLS ServerHello JA3S, TLS 1.2/1.3 인증서 및 X.509 ASN.1 파서
│   ├── ja4.rs                     # 최신 FoxIO JA4 클라이언트 및 JA4S 서버 핑거프린트 엔진
│   ├── tcp_stream.rs              # 상태 보존형 TCP 스트림 재조립 및 순서 역전 추적기
│   ├── http_inspect.rs            # HTTP/1.1, HTTP/2 SETTINGS 프레임 및 JA4H 핑거프린트 엔진
│   └── dns.rs                     # RFC 1035 DNS 디코더 및 섀넌 엔트로피 터널 감사기
└── tests/
    ├── arp_audit_test.rs          # ARP 스푸핑, 게이트웨이 플래핑 및 비정상 플러딩 통합 테스트
    ├── p0f_test.rs                # TCP SYN 수동 OS 핑거프린팅 및 FoxIO JA4T 통합 테스트
    ├── icmp_tunnel_test.rs        # ICMP 은닉 터널 및 섀넌 엔트로피 통합 테스트
    ├── beacon_test.rs             # C2 비콘 지터, 스펙트로그램 및 분류 통합 테스트
    ├── filter_test.rs             # BPF 스타일 패킷 필터 표현식 평가 통합 테스트
    ├── pcap_tls_test.rs           # PCAP, L2/L3/L4, GREASE 및 JA3 통합 테스트
    ├── pcapng_test.rs             # PCAPNG 블록, 나노초 타임스탬프 및 CLI 통합 테스트
    ├── ja4_test.rs                # JA4/JA4S, QUIC Initial 및 GREASE 면역 통합 테스트
    ├── quic_test.rs               # RFC 9001 HKDF, AES-GCM 및 QUIC Initial 복호화 통합 테스트
    ├── ssh_hassh_test.rs          # SSH 배너, KEXINIT 및 Salesforce HASSH 통합 테스트
    ├── tcp_stream_test.rs         # TCP 스트림 재조립 및 멀티 세그먼트 TLS 통합 테스트
    ├── http_inspect_test.rs       # HTTP/1.1, HTTP/2 프레임 및 JA4H 통합 테스트
    ├── tls_cert_test.rs           # ServerHello JA3S, X.509 ASN.1 DER 및 이상 징후 통합 테스트
    └── dns_audit_test.rs          # DNS 압축 루프 및 은닉 터널 탐지 통합 테스트
```

계획된 전송 계층 및 프로토콜 포렌식 기능은 [ROADMAP.md](../../ROADMAP.md)를 참조하십시오.

</details>

---

## 🔒 메모리 안전성 및 파서 보안 설계

<details open>
<summary><b>🔒 메모리 안전성 및 파서 보안 설계</b></summary>
<br>

- **100% Safe Rust**: 모든 바이너리 프레임 디코더 전반에 걸쳐 `unsafe` 블록을 단 하나도 사용하지 않습니다.
- **RFC 1035 압축 루프 방어**: DNS 이름 압축 해제 시 최대 32홉의 엄격한 포인터 상한을 적용하며, 전방 참조 및 자기 참조 포인터를 즉시 거부합니다.
- **휘발성 버퍼 안전 제로화**: 메모리 해제 시 `zeroize`를 통해 임시 TLS 난수, 세션 ID 및 재조립 바이트 버퍼를 안전하게 소거합니다.
- **DoS 방어 세그먼트 버퍼링**: 순서가 어긋난 TCP 세그먼트 큐잉 시 스트림당 고정된 메모리 쿼터를 강제하여 분할 세그먼트 플러딩으로 인한 메모리 고갈을 방지합니다.
- **보안 정책 및 취약점 제보**: [SECURITY.md](../../SECURITY.md)를 참조하십시오.

</details>

---

## 📄 라이선스 및 저작권 안내

<details open>
<summary><b>📄 라이선스 및 저작권 안내</b></summary>
<br>

```text
Copyright 2026 GHSFS

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
