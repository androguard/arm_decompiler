//! Source token stream + address map (Ghidra `ClangToken` analogue) — P4-4.
//!
//! Tokens are byte spans into the decompiled source. When a span overlaps a
//! basic-block body, it inherits that block's `start_vaddr` for UI highlighting.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::cfg::FunctionCfg;
use crate::ir::Stmt;

/// Lexical class for a decompiled C/ObjC fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Whitespace,
    Comment,
    Keyword,
    Ident,
    Number,
    String,
    Punct,
}

impl TokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Whitespace => "ws",
            TokenKind::Comment => "comment",
            TokenKind::Keyword => "kw",
            TokenKind::Ident => "ident",
            TokenKind::Number => "num",
            TokenKind::String => "string",
            TokenKind::Punct => "punct",
        }
    }
}

/// One token with optional instruction address (block start).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceToken {
    pub kind: TokenKind,
    pub text: String,
    pub start: usize,
    pub end: usize,
    pub vaddr: Option<u64>,
}

/// Byte span in source mapped to a code address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrSpan {
    pub start: usize,
    pub end: usize,
    pub vaddr: u64,
}

/// Tokenize decompiled source (C/ObjC-ish lexer).
pub fn tokenize(source: &str) -> Vec<SourceToken> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let start = i;
        let c = bytes[i] as char;
        if c.is_ascii_whitespace() {
            while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
                i += 1;
            }
            push(&mut out, TokenKind::Whitespace, source, start, i, None);
            continue;
        }
        if c == '/' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'/' {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                push(&mut out, TokenKind::Comment, source, start, i, None);
                continue;
            }
            if bytes[i + 1] == b'*' {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                if i + 1 < bytes.len() {
                    i += 2;
                }
                push(&mut out, TokenKind::Comment, source, start, i, None);
                continue;
            }
        }
        if c == '"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            push(&mut out, TokenKind::String, source, start, i, None);
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            i += 1;
            while i < bytes.len() {
                let ch = bytes[i] as char;
                if ch.is_ascii_alphanumeric() || ch == '_' {
                    i += 1;
                } else {
                    break;
                }
            }
            let text = &source[start..i];
            let kind = if is_keyword(text) {
                TokenKind::Keyword
            } else {
                TokenKind::Ident
            };
            push(&mut out, kind, source, start, i, None);
            continue;
        }
        if c.is_ascii_digit() || (c == '0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')) {
            if c == '0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
                i += 2;
                while i < bytes.len() && (bytes[i] as char).is_ascii_hexdigit() {
                    i += 1;
                }
            } else {
                while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
                    i += 1;
                }
            }
            push(&mut out, TokenKind::Number, source, start, i, None);
            continue;
        }
        // punctuation (multi-char first)
        if i + 1 < bytes.len() {
            let two = &source[i..i + 2];
            if matches!(
                two,
                "==" | "!=" | "<=" | ">=" | "<<" | ">>" | "&&" | "||" | "->" | "++" | "--"
            ) {
                i += 2;
                push(&mut out, TokenKind::Punct, source, start, i, None);
                continue;
            }
        }
        i += 1;
        push(&mut out, TokenKind::Punct, source, start, i, None);
    }
    out
}

fn push(
    out: &mut Vec<SourceToken>,
    kind: TokenKind,
    source: &str,
    start: usize,
    end: usize,
    vaddr: Option<u64>,
) {
    out.push(SourceToken {
        kind,
        text: source[start..end].to_string(),
        start,
        end,
        vaddr,
    });
}

fn is_keyword(s: &str) -> bool {
    matches!(
        s,
        "if" | "else"
            | "while"
            | "for"
            | "do"
            | "switch"
            | "case"
            | "default"
            | "return"
            | "break"
            | "continue"
            | "goto"
            | "void"
            | "int"
            | "long"
            | "short"
            | "char"
            | "unsigned"
            | "signed"
            | "const"
            | "static"
            | "struct"
            | "enum"
            | "typedef"
            | "sizeof"
            | "id"
            | "self"
            | "super"
            | "nil"
            | "NULL"
            | "true"
            | "false"
            | "BOOL"
            | "YES"
            | "NO"
            | "undefined4"
            | "undefined8"
    )
}

/// Map each basic-block body (statement lines) to a source byte span → block VA.
pub fn build_addr_map(
    source: &str,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
) -> Vec<AddrSpan> {
    let mut spans = Vec::new();
    let mut cursor = 0usize;
    for (id, block) in cfg.blocks.iter().enumerate() {
        let Some(stmts) = block_stmts.get(id) else {
            continue;
        };
        let lines: Vec<String> = stmts
            .iter()
            .filter(|s| !matches!(s, Stmt::Phi { .. }))
            .map(|s| s.to_c_line())
            .filter(|l| !l.is_empty())
            .collect();
        if lines.is_empty() {
            continue;
        }
        // Find the first statement line at/after cursor.
        let first = lines[0].as_str();
        let Some(rel) = source[cursor..].find(first) else {
            continue;
        };
        let start = cursor + rel;
        let mut end = start + first.len();
        let mut search_from = end;
        for line in lines.iter().skip(1) {
            if let Some(r) = source[search_from..].find(line.as_str()) {
                let abs = search_from + r;
                end = abs + line.len();
                search_from = end;
            }
        }
        spans.push(AddrSpan {
            start,
            end,
            vaddr: block.start_vaddr,
        });
        cursor = end;
    }
    spans
}

/// Attach overlapping addr-map VAs onto tokens (first matching span wins).
pub fn apply_addr_map(tokens: &mut [SourceToken], map: &[AddrSpan]) {
    for tok in tokens.iter_mut() {
        if tok.kind == TokenKind::Whitespace {
            continue;
        }
        for span in map {
            if tok.start < span.end && tok.end > span.start {
                tok.vaddr = Some(span.vaddr);
                break;
            }
        }
    }
}

/// Full pipeline: tokenize + CFG address annotation.
pub fn tokenize_with_addrs(
    source: &str,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
) -> Vec<SourceToken> {
    let mut tokens = tokenize(source);
    let map = build_addr_map(source, cfg, block_stmts);
    apply_addr_map(&mut tokens, &map);
    tokens
}

/// Compact JSON array of tokens (no_std).
pub fn tokens_to_json(tokens: &[SourceToken]) -> String {
    let mut out = String::from("[");
    for (i, t) in tokens.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        out.push_str("\"kind\":\"");
        out.push_str(t.kind.as_str());
        out.push_str("\",\"text\":");
        push_json_str(&mut out, &t.text);
        out.push_str(",\"start\":");
        out.push_str(&format!("{}", t.start));
        out.push_str(",\"end\":");
        out.push_str(&format!("{}", t.end));
        if let Some(va) = t.vaddr {
            out.push_str(",\"vaddr\":\"");
            out.push_str(&format!("0x{va:x}"));
            out.push('"');
        }
        out.push('}');
    }
    out.push(']');
    out
}

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{BlockEnd, CfgBlock};
    use crate::ir::{Expr, Place, VarId};
    use alloc::collections::BTreeMap;
    use alloc::vec;

    #[test]
    fn tokenizes_keywords_and_idents() {
        let src = "int foo(void) {\n    return 1;\n}\n";
        let toks = tokenize(src);
        assert!(toks.iter().any(|t| t.kind == TokenKind::Keyword && t.text == "int"));
        assert!(toks.iter().any(|t| t.kind == TokenKind::Ident && t.text == "foo"));
        assert!(toks.iter().any(|t| t.kind == TokenKind::Keyword && t.text == "return"));
        assert!(toks.iter().any(|t| t.kind == TokenKind::Number && t.text == "1"));
    }

    #[test]
    fn addr_map_marks_return() {
        let source = "// decompiled\nint _f(void) {\n    return x0;\n}\n";
        let cfg = FunctionCfg {
            blocks: vec![CfgBlock {
                start_vaddr: 0x1000,
                end_vaddr: 0x1008,
                end: BlockEnd::Exit,
                insn_indices: vec![],
            }],
            block_by_start: BTreeMap::new(),
            loop_headers: Default::default(),
            entry: 0,
        };
        let stmts = vec![vec![Stmt::Return {
            value: Some(Expr::Var(VarId::from_x(0))),
            comment: None,
        }]];
        let mut toks = tokenize(source);
        let map = build_addr_map(source, &cfg, &stmts);
        assert!(!map.is_empty(), "{map:?}");
        apply_addr_map(&mut toks, &map);
        let ret = toks
            .iter()
            .find(|t| t.text == "return")
            .expect("return tok");
        assert_eq!(ret.vaddr, Some(0x1000));
    }
}
