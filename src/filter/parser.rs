// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::{
    Direction, FilterExpr, IpMatch, IpNetwork, LenMatch, LenOp, PortMatch, Protocol,
    TcpFlagComparison, TcpFlagMatch, TCP_FLAG_ACK, TCP_FLAG_CWR, TCP_FLAG_ECE, TCP_FLAG_FIN,
    TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG,
};
use crate::error::{Result, SpecterError};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) fn parse_filter_expr(trimmed: &str) -> Result<FilterExpr> {
    let tokens = tokenize(trimmed)?;
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
    };
    let expr = parser.parse_or()?;
    if parser.pos < parser.tokens.len() {
        return Err(SpecterError::InvalidFilter(format!(
            "Unexpected trailing tokens starting at {:?}",
            parser.tokens[parser.pos]
        )));
    }
    Ok(expr)
}

// Tokenizer & Parser Implementation

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Tcp,
    Udp,
    Icmp,
    Ipv4,
    Ipv6,
    Src,
    Dst,
    Host,
    Net,
    Port,
    PortRange,
    Len,
    TcpFlagsField,
    TcpFlagsKeyword,
    Flag(u8, String),
    Not,
    And,
    Or,
    Amp,
    Pipe,
    Cmp(LenOp),
    LParen,
    RParen,
    Number(u32),
    PortRangeLiteral(u16, u16),
    IpNet(IpNetwork),
    Hyphen,
    Comma,
    Ident(String),
}

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        match b {
            b'(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            b')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            b'!' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    tokens.push(Token::Cmp(LenOp::Ne));
                    i += 2;
                } else {
                    tokens.push(Token::Not);
                    i += 1;
                }
            }
            b'&' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'&' {
                    tokens.push(Token::And);
                    i += 2;
                } else {
                    tokens.push(Token::Amp);
                    i += 1;
                }
            }
            b'|' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'|' {
                    tokens.push(Token::Or);
                    i += 2;
                } else {
                    tokens.push(Token::Pipe);
                    i += 1;
                }
            }
            b'<' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    tokens.push(Token::Cmp(LenOp::Le));
                    i += 2;
                } else {
                    tokens.push(Token::Cmp(LenOp::Lt));
                    i += 1;
                }
            }
            b'>' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    tokens.push(Token::Cmp(LenOp::Ge));
                    i += 2;
                } else {
                    tokens.push(Token::Cmp(LenOp::Gt));
                    i += 1;
                }
            }
            b'=' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    tokens.push(Token::Cmp(LenOp::Eq));
                    i += 2;
                } else {
                    tokens.push(Token::Cmp(LenOp::Eq));
                    i += 1;
                }
            }
            b'-' => {
                tokens.push(Token::Hyphen);
                i += 1;
            }
            b',' => {
                tokens.push(Token::Comma);
                i += 1;
            }
            _ => {
                let start = i;
                if bytes[i..].starts_with(b"tcp[") {
                    if let Some(close_idx) = input[i..].find(']') {
                        let inner = input[i + 4..i + close_idx].trim();
                        if inner.eq_ignore_ascii_case("tcpflags") || inner == "13" {
                            tokens.push(Token::TcpFlagsField);
                            i += close_idx + 1;
                            continue;
                        }
                    }
                }

                while i < bytes.len() {
                    let c = bytes[i];
                    if c.is_ascii_alphanumeric()
                        || c == b'_'
                        || c == b'.'
                        || c == b':'
                        || c == b'/'
                        || c == b'-'
                        || c == b','
                    {
                        i += 1;
                    } else {
                        break;
                    }
                }
                if start == i {
                    return Err(SpecterError::InvalidFilter(format!(
                        "Unexpected character '{}' at offset {i}",
                        bytes[i] as char
                    )));
                }
                let word = &input[start..i];
                let token = classify_word(word)?;
                tokens.push(token);
            }
        }
    }

    Ok(tokens)
}

fn classify_word(word: &str) -> Result<Token> {
    if word.eq_ignore_ascii_case("and") {
        return Ok(Token::And);
    }
    if word.eq_ignore_ascii_case("or") {
        return Ok(Token::Or);
    }
    if word.eq_ignore_ascii_case("not") {
        return Ok(Token::Not);
    }
    if word.eq_ignore_ascii_case("tcp") {
        return Ok(Token::Tcp);
    }
    if word.eq_ignore_ascii_case("udp") {
        return Ok(Token::Udp);
    }
    if word.eq_ignore_ascii_case("icmp") {
        return Ok(Token::Icmp);
    }
    if word.eq_ignore_ascii_case("ip")
        || word.eq_ignore_ascii_case("ip4")
        || word.eq_ignore_ascii_case("ipv4")
    {
        return Ok(Token::Ipv4);
    }
    if word.eq_ignore_ascii_case("ip6") || word.eq_ignore_ascii_case("ipv6") {
        return Ok(Token::Ipv6);
    }
    if word.eq_ignore_ascii_case("src") {
        return Ok(Token::Src);
    }
    if word.eq_ignore_ascii_case("dst") {
        return Ok(Token::Dst);
    }
    if word.eq_ignore_ascii_case("host") {
        return Ok(Token::Host);
    }
    if word.eq_ignore_ascii_case("net") {
        return Ok(Token::Net);
    }
    if word.eq_ignore_ascii_case("port") {
        return Ok(Token::Port);
    }
    if word.eq_ignore_ascii_case("portrange") {
        return Ok(Token::PortRange);
    }
    if word.eq_ignore_ascii_case("len") || word.eq_ignore_ascii_case("length") {
        return Ok(Token::Len);
    }
    if word.eq_ignore_ascii_case("tcpflags") {
        return Ok(Token::TcpFlagsKeyword);
    }

    if word.eq_ignore_ascii_case("tcp-syn") || word.eq_ignore_ascii_case("syn") {
        return Ok(Token::Flag(TCP_FLAG_SYN, "syn".into()));
    }
    if word.eq_ignore_ascii_case("tcp-ack") || word.eq_ignore_ascii_case("ack") {
        return Ok(Token::Flag(TCP_FLAG_ACK, "ack".into()));
    }
    if word.eq_ignore_ascii_case("tcp-fin") || word.eq_ignore_ascii_case("fin") {
        return Ok(Token::Flag(TCP_FLAG_FIN, "fin".into()));
    }
    if word.eq_ignore_ascii_case("tcp-rst") || word.eq_ignore_ascii_case("rst") {
        return Ok(Token::Flag(TCP_FLAG_RST, "rst".into()));
    }
    if word.eq_ignore_ascii_case("tcp-psh") || word.eq_ignore_ascii_case("psh") {
        return Ok(Token::Flag(TCP_FLAG_PSH, "psh".into()));
    }

    if word.contains(',') {
        let mut mask = 0u8;
        for part in word.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            mask |= match part.to_ascii_lowercase().as_str() {
                "syn" | "tcp-syn" => TCP_FLAG_SYN,
                "ack" | "tcp-ack" => TCP_FLAG_ACK,
                "fin" | "tcp-fin" => TCP_FLAG_FIN,
                "rst" | "tcp-rst" => TCP_FLAG_RST,
                "psh" | "tcp-psh" => TCP_FLAG_PSH,
                "urg" | "tcp-urg" => TCP_FLAG_URG,
                "ece" | "tcp-ece" => TCP_FLAG_ECE,
                "cwr" | "tcp-cwr" => TCP_FLAG_CWR,
                other => {
                    return Err(SpecterError::InvalidFilter(format!(
                        "Unknown TCP flag '{other}' in '{word}'"
                    )))
                }
            };
        }
        return Ok(Token::Flag(mask, word.to_string()));
    }

    if let Some((start_s, end_s)) = word.split_once('-') {
        if let (Ok(start), Ok(end)) = (start_s.parse::<u16>(), end_s.parse::<u16>()) {
            return Ok(Token::PortRangeLiteral(start, end));
        }
    }

    if word.starts_with("0x") || word.starts_with("0X") {
        if let Ok(num) = u32::from_str_radix(&word[2..], 16) {
            return Ok(Token::Number(num));
        }
    }
    if let Ok(num) = word.parse::<u32>() {
        return Ok(Token::Number(num));
    }

    if let Some(net) = parse_ipv4_cidr(word) {
        return Ok(Token::IpNet(net));
    }
    if let Some(net) = parse_ipv6_cidr(word) {
        return Ok(Token::IpNet(net));
    }

    Ok(Token::Ident(word.to_string()))
}

fn parse_ipv4_cidr(s: &str) -> Option<IpNetwork> {
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        let ip = ip_str.parse::<Ipv4Addr>().ok()?;
        let prefix = prefix_str.parse::<u8>().ok()?;
        if prefix <= 32 {
            Some(IpNetwork::V4 { net: ip, prefix })
        } else {
            None
        }
    } else if s.contains('.') {
        let ip = s.parse::<Ipv4Addr>().ok()?;
        Some(IpNetwork::V4 {
            net: ip,
            prefix: 32,
        })
    } else {
        None
    }
}

fn parse_ipv6_cidr(s: &str) -> Option<IpNetwork> {
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        let ip = ip_str.parse::<Ipv6Addr>().ok()?;
        let prefix = prefix_str.parse::<u8>().ok()?;
        if prefix <= 128 {
            Some(IpNetwork::V6 { net: ip, prefix })
        } else {
            None
        }
    } else if s.contains(':') {
        let ip = s.parse::<Ipv6Addr>().ok()?;
        Some(IpNetwork::V6 {
            net: ip,
            prefix: 128,
        })
    } else {
        None
    }
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<&Token> {
        if self.pos < self.tokens.len() {
            let tok = &self.tokens[self.pos];
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn check<F: Fn(&Token) -> bool>(&self, f: F) -> bool {
        self.peek().map(f).unwrap_or(false)
    }

    fn match_token<F: Fn(&Token) -> bool>(&mut self, f: F) -> bool {
        if self.check(&f) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn can_start_unary(&self) -> bool {
        matches!(
            self.peek(),
            Some(
                Token::Not
                    | Token::LParen
                    | Token::Tcp
                    | Token::Udp
                    | Token::Icmp
                    | Token::Ipv4
                    | Token::Ipv6
                    | Token::Src
                    | Token::Dst
                    | Token::Host
                    | Token::Net
                    | Token::Port
                    | Token::PortRange
                    | Token::Len
                    | Token::TcpFlagsField
                    | Token::TcpFlagsKeyword
                    | Token::Flag(..)
                    | Token::PortRangeLiteral(..)
                    | Token::IpNet(..)
            )
        )
    }

    fn parse_or(&mut self) -> Result<FilterExpr> {
        let first = self.parse_and()?;
        let mut items = vec![first];
        while self.match_token(|t| matches!(t, Token::Or)) {
            items.push(self.parse_and()?);
        }
        if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(FilterExpr::Or(items))
        }
    }

    fn parse_and(&mut self) -> Result<FilterExpr> {
        let first = self.parse_unary()?;
        let mut items = vec![first];
        while self.match_token(|t| matches!(t, Token::And)) || self.can_start_unary() {
            items.push(self.parse_unary()?);
        }
        if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(FilterExpr::And(items))
        }
    }

    fn parse_unary(&mut self) -> Result<FilterExpr> {
        if self.match_token(|t| matches!(t, Token::Not)) {
            let inner = self.parse_unary()?;
            Ok(FilterExpr::Not(Box::new(inner)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<FilterExpr> {
        if self.match_token(|t| matches!(t, Token::LParen)) {
            let inner = self.parse_or()?;
            if !self.match_token(|t| matches!(t, Token::RParen)) {
                return Err(SpecterError::InvalidFilter(
                    "Missing closing parenthesis ')'".into(),
                ));
            }
            return Ok(inner);
        }

        if self.match_token(|t| matches!(t, Token::Tcp)) {
            return Ok(FilterExpr::Protocol(Protocol::Tcp));
        }
        if self.match_token(|t| matches!(t, Token::Udp)) {
            return Ok(FilterExpr::Protocol(Protocol::Udp));
        }
        if self.match_token(|t| matches!(t, Token::Icmp)) {
            return Ok(FilterExpr::Protocol(Protocol::Icmp));
        }
        if self.match_token(|t| matches!(t, Token::Ipv4)) {
            return Ok(FilterExpr::Protocol(Protocol::Ipv4));
        }
        if self.match_token(|t| matches!(t, Token::Ipv6)) {
            return Ok(FilterExpr::Protocol(Protocol::Ipv6));
        }

        let direction = if self.match_token(|t| matches!(t, Token::Src)) {
            Direction::Src
        } else if self.match_token(|t| matches!(t, Token::Dst)) {
            Direction::Dst
        } else {
            Direction::SrcOrDst
        };

        if direction != Direction::SrcOrDst {
            if self.match_token(|t| matches!(t, Token::Host | Token::Net)) {
                return self.parse_ip_target(direction);
            }
            if self.match_token(|t| matches!(t, Token::Port | Token::PortRange)) {
                return self.parse_port_target(direction);
            }
            if matches!(self.peek(), Some(Token::IpNet(..))) {
                return self.parse_ip_target(direction);
            }
            if matches!(
                self.peek(),
                Some(Token::Number(..) | Token::PortRangeLiteral(..))
            ) {
                return self.parse_port_target(direction);
            }
            return Err(SpecterError::InvalidFilter(
                "Expected host, net, port, IP, or port number after direction qualifier".into(),
            ));
        }

        if self.match_token(|t| matches!(t, Token::Host | Token::Net)) {
            return self.parse_ip_target(Direction::SrcOrDst);
        }
        if self.match_token(|t| matches!(t, Token::Port | Token::PortRange)) {
            return self.parse_port_target(Direction::SrcOrDst);
        }
        if matches!(self.peek(), Some(Token::IpNet(..))) {
            return self.parse_ip_target(Direction::SrcOrDst);
        }
        if matches!(self.peek(), Some(Token::PortRangeLiteral(..))) {
            return self.parse_port_target(Direction::SrcOrDst);
        }

        if self.match_token(|t| matches!(t, Token::Len)) {
            let op = match self.next() {
                Some(Token::Cmp(op)) => *op,
                _ => {
                    return Err(SpecterError::InvalidFilter(
                        "Expected comparison operator (<, <=, >, >=, ==, !=) after 'len'".into(),
                    ))
                }
            };
            let value = match self.next() {
                Some(Token::Number(n)) => *n,
                _ => {
                    return Err(SpecterError::InvalidFilter(
                        "Expected numeric packet length".into(),
                    ))
                }
            };
            return Ok(FilterExpr::Length(LenMatch { op, value }));
        }

        if self.match_token(|t| matches!(t, Token::TcpFlagsField)) {
            let mask = if self.match_token(|t| matches!(t, Token::Amp)) {
                self.parse_flag_mask()?
            } else {
                0xFF
            };

            let (cmp_op, cmp_val) = if let Some(Token::Cmp(op)) = self.peek() {
                let op = *op;
                self.pos += 1;
                let val = match self.next() {
                    Some(Token::Number(n)) => *n as u8,
                    Some(Token::Flag(m, _)) => *m,
                    _ => {
                        return Err(SpecterError::InvalidFilter(
                            "Expected integer or flag value after comparison operator".into(),
                        ))
                    }
                };
                (Some(op), val)
            } else {
                (None, 0)
            };

            let comparison = match cmp_op {
                Some(LenOp::Ne) if cmp_val == 0 => TcpFlagComparison::NonZero,
                Some(LenOp::Eq) if cmp_val == 0 => TcpFlagComparison::Zero,
                Some(LenOp::Eq) => TcpFlagComparison::Exact(cmp_val),
                Some(LenOp::Gt) if cmp_val == 0 => TcpFlagComparison::NonZero,
                None => TcpFlagComparison::NonZero,
                _ => TcpFlagComparison::Exact(cmp_val),
            };

            return Ok(FilterExpr::TcpFlag(TcpFlagMatch { mask, comparison }));
        }

        if self.match_token(|t| matches!(t, Token::TcpFlagsKeyword)) {
            let mask = self.parse_flag_mask()?;
            return Ok(FilterExpr::TcpFlag(TcpFlagMatch {
                mask,
                comparison: TcpFlagComparison::AllSet,
            }));
        }

        if let Some(Token::Flag(mask, _)) = self.peek() {
            let m = *mask;
            self.pos += 1;
            return Ok(FilterExpr::TcpFlag(TcpFlagMatch {
                mask: m,
                comparison: TcpFlagComparison::NonZero,
            }));
        }

        Err(SpecterError::InvalidFilter(format!(
            "Unexpected token {:?}",
            self.peek()
        )))
    }

    fn parse_ip_target(&mut self, direction: Direction) -> Result<FilterExpr> {
        match self.next() {
            Some(Token::IpNet(net)) => Ok(FilterExpr::Ip(IpMatch {
                direction,
                network: net.clone(),
            })),
            other => Err(SpecterError::InvalidFilter(format!(
                "Expected IP address or CIDR network, found {other:?}"
            ))),
        }
    }

    fn parse_port_target(&mut self, direction: Direction) -> Result<FilterExpr> {
        match self.next() {
            Some(Token::PortRangeLiteral(start, end)) => Ok(FilterExpr::Port(PortMatch {
                direction,
                start: *start,
                end: *end,
            })),
            Some(Token::Number(num)) => {
                let start = *num as u16;
                if self.match_token(|t| matches!(t, Token::Hyphen)) {
                    match self.next() {
                        Some(Token::Number(end_num)) => Ok(FilterExpr::Port(PortMatch {
                            direction,
                            start,
                            end: *end_num as u16,
                        })),
                        _ => Err(SpecterError::InvalidFilter(
                            "Expected upper port number in range".into(),
                        )),
                    }
                } else {
                    Ok(FilterExpr::Port(PortMatch {
                        direction,
                        start,
                        end: start,
                    }))
                }
            }
            other => Err(SpecterError::InvalidFilter(format!(
                "Expected port number or range, found {other:?}"
            ))),
        }
    }

    fn parse_flag_mask(&mut self) -> Result<u8> {
        if self.match_token(|t| matches!(t, Token::LParen)) {
            let mut mask = self.parse_flag_mask_single()?;
            while self.match_token(|t| matches!(t, Token::Pipe | Token::Comma)) {
                mask |= self.parse_flag_mask_single()?;
            }
            if !self.match_token(|t| matches!(t, Token::RParen)) {
                return Err(SpecterError::InvalidFilter(
                    "Missing closing ')' in flag mask".into(),
                ));
            }
            return Ok(mask);
        }
        let mut mask = self.parse_flag_mask_single()?;
        while self.match_token(|t| matches!(t, Token::Pipe | Token::Comma)) {
            mask |= self.parse_flag_mask_single()?;
        }
        Ok(mask)
    }

    fn parse_flag_mask_single(&mut self) -> Result<u8> {
        match self.next() {
            Some(Token::Flag(m, _)) => Ok(*m),
            Some(Token::Number(n)) => Ok(*n as u8),
            Some(Token::Ident(s)) => {
                let mut m = 0u8;
                for part in s.split(',') {
                    let part = part.trim();
                    m |= match part.to_ascii_lowercase().as_str() {
                        "syn" | "tcp-syn" => TCP_FLAG_SYN,
                        "ack" | "tcp-ack" => TCP_FLAG_ACK,
                        "fin" | "tcp-fin" => TCP_FLAG_FIN,
                        "rst" | "tcp-rst" => TCP_FLAG_RST,
                        "psh" | "tcp-psh" => TCP_FLAG_PSH,
                        "urg" | "tcp-urg" => TCP_FLAG_URG,
                        "ece" | "tcp-ece" => TCP_FLAG_ECE,
                        "cwr" | "tcp-cwr" => TCP_FLAG_CWR,
                        other => {
                            return Err(SpecterError::InvalidFilter(format!(
                                "Unknown TCP flag '{other}'"
                            )))
                        }
                    };
                }
                Ok(m)
            }
            other => Err(SpecterError::InvalidFilter(format!(
                "Expected TCP flag or numeric mask, found {other:?}"
            ))),
        }
    }
}
