//! Swift demangling + prototypes (Phase 6 / S0).
//!
//! Covers New Mangling (`$s` / `_$s`) free functions and simple methods well
//! enough to emit Swift `func` prototypes. Full ABI / generics remain best-effort.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::locals::FrameRecovery;
use crate::types::Ty;

/// Kind of Swift entity recovered from a mangled symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwiftKind {
    Function,
    Method,
    Getter,
    Setter,
    Other,
}

/// Structured demangle result used for prototypes and emit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwiftSymbol {
    pub module: String,
    /// Nested type / function path segments after the module.
    pub path: Vec<String>,
    pub kind: SwiftKind,
    pub arg_types: Vec<String>,
    pub ret_type: Option<String>,
    pub is_static: bool,
    /// True when this is an instance method (first param is `self`).
    pub is_method: bool,
}

impl SwiftSymbol {
    /// `module.Type.method` style display name (no signature).
    pub fn qualified_name(&self) -> String {
        let mut parts = Vec::with_capacity(1 + self.path.len());
        if !self.module.is_empty() {
            parts.push(self.module.as_str());
        }
        for p in &self.path {
            parts.push(p.as_str());
        }
        parts.join(".")
    }

    /// Short function name (last path segment).
    pub fn short_name(&self) -> &str {
        self.path.last().map(String::as_str).unwrap_or("fn")
    }
}

/// True when `name` looks like a Swift mangled symbol.
pub fn is_swift_mangled(name: &str) -> bool {
    let n = strip_leading_underscores(name);
    n.starts_with("$s") || n.starts_with("$S") || n.starts_with("_T0") || n.starts_with("_T")
}

/// Demangle a Swift symbol to a readable signature string, if we can.
///
/// Uses in-process New Mangling first; if the native toolchain demangler is
/// available and **disagrees**, prefer the native result (G1 / Ghidra fidelity).
pub fn demangle_swift(name: &str) -> Option<String> {
    let local = parse_swift_symbol(name).map(|sym| display_signature(&sym));
    let native = crate::swift_native::demangle_swift_native(name);
    crate::swift_native::prefer_demangle(local, native)
}

/// Parse into a structured [`SwiftSymbol`].
pub fn parse_swift_symbol(name: &str) -> Option<SwiftSymbol> {
    let raw = strip_leading_underscores(name);
    let rest = raw.strip_prefix("$s").or_else(|| raw.strip_prefix("$S"))?;
    demangle_new_struct(rest)
}

/// Demangle if Swift; otherwise return `None`.
pub fn try_demangle_symbol(name: &str) -> Option<String> {
    if is_swift_mangled(name) {
        demangle_swift(name)
    } else {
        None
    }
}

/// Format a Swift `func` prototype line (no trailing `{`).
pub fn format_swift_prototype(sym: &SwiftSymbol, frame: &FrameRecovery) -> String {
    if let Some(proto) = &frame.swift_proto {
        return proto.clone();
    }
    let mut out = String::new();
    if sym.is_static {
        out.push_str("static ");
    }
    out.push_str("func ");
    // Prefer short name for methods; qualified for free functions.
    if sym.is_method && sym.path.len() >= 2 {
        out.push_str(sym.short_name());
    } else {
        out.push_str(&sym.qualified_name());
    }
    out.push('(');
    let mut args: Vec<String> = Vec::new();
    let mut param_i = 0usize;
    for (ai, ty) in sym.arg_types.iter().enumerate() {
        if ty == "()" {
            continue;
        }
        let pname = frame
            .params
            .get(param_i)
            .cloned()
            .unwrap_or_else(|| format!("arg{}", ai + 1));
        param_i += 1;
        if pname == "self" {
            continue; // Swift methods: self is implicit in emit
        }
        let sty = swift_type_display(ty);
        args.push(format!("_ {pname}: {sty}"));
    }
    // Fall back to frame params when mangling had no arg types.
    if args.is_empty() && !frame.params.is_empty() {
        for p in &frame.params {
            if p == "self" {
                continue;
            }
            let ty = frame
                .local_types
                .get(p)
                .copied()
                .unwrap_or(Ty::Undefined);
            args.push(format!("_ {p}: {}", ty.as_swift_str()));
        }
    }
    out.push_str(&args.join(", "));
    out.push(')');
    let ret = sym
        .ret_type
        .as_deref()
        .map(swift_type_display)
        .filter(|t| t != "()" && t != "Void")
        .or_else(|| {
            if frame.returns_value {
                Some(frame.return_ty.as_swift_str().to_string())
            } else {
                None
            }
        });
    if let Some(r) = ret {
        if r != "Any" && r != "undefined8" {
            out.push_str(" -> ");
            out.push_str(&r);
        }
    }
    out
}

/// Build and store a Swift prototype on the frame when the symbol is mangled.
pub fn apply_swift_prototype(frame: &mut FrameRecovery, mangled: &str) -> Option<SwiftSymbol> {
    if let Some(mut sym) = parse_swift_symbol(mangled) {
        if sym.is_method {
            // First AAPCS arg is self for instance methods.
            if frame.params.first().map(String::as_str) == Some("param_1") {
                frame.params[0] = String::from("self");
            } else if frame.params.is_empty() {
                frame.params.push(String::from("self"));
            }
            frame
                .local_types
                .insert(String::from("self"), Ty::ObjCId);
        }
        let proto = format_swift_prototype(&sym, frame);
        frame.swift_proto = Some(proto);
        if sym.path.len() >= 2 && !sym.is_static {
            sym.is_method = true;
            sym.kind = SwiftKind::Method;
        }
        return Some(sym);
    }
    // Native-only demangle: still emit a Swift prototype.
    let native = crate::swift_native::demangle_swift_native(mangled)?;
    let prefer_short = native.matches('.').count() >= 2;
    frame.swift_proto = Some(crate::swift_native::prototype_from_native_demangle(
        &native,
        prefer_short,
    ));
    // Synthesize a minimal symbol for callers (method detection).
    let is_method = prefer_short;
    if is_method && frame.params.first().map(String::as_str) == Some("param_1") {
        frame.params[0] = String::from("self");
    } else if is_method && frame.params.is_empty() {
        frame.params.push(String::from("self"));
    }
    Some(SwiftSymbol {
        module: String::new(),
        path: alloc::vec![String::from("fn")],
        kind: if is_method {
            SwiftKind::Method
        } else {
            SwiftKind::Function
        },
        arg_types: Vec::new(),
        ret_type: None,
        is_static: false,
        is_method,
    })
}

fn display_signature(sym: &SwiftSymbol) -> String {
    let mut name = sym.qualified_name();
    let args: Vec<String> = sym
        .arg_types
        .iter()
        .filter(|t| *t != "()")
        .map(|t| swift_type_display(t))
        .collect();
    name.push('(');
    name.push_str(&args.join(", "));
    name.push(')');
    if let Some(ret) = &sym.ret_type {
        let r = swift_type_display(ret);
        if r != "()" && r != "Void" {
            name.push_str(" -> ");
            name.push_str(&r);
        }
    }
    name
}

fn swift_type_display(ty: &str) -> String {
    match ty {
        "Swift.Int" => String::from("Int"),
        "Swift.String" => String::from("String"),
        "Swift.Bool" => String::from("Bool"),
        "Swift.Float" => String::from("Float"),
        "Swift.Double" => String::from("Double"),
        "Swift.UInt" => String::from("UInt"),
        "()" | "Void" => String::from("Void"),
        other => {
            // Drop module prefix for local types when single component after module.
            if let Some((_, rest)) = other.rsplit_once('.') {
                if !rest.is_empty() && !other.starts_with("Swift.") {
                    return rest.to_string();
                }
            }
            other.to_string()
        }
    }
}

fn strip_leading_underscores(name: &str) -> &str {
    name.trim_start_matches('_')
}

fn demangle_new_struct(s: &str) -> Option<SwiftSymbol> {
    let mut p = Parser { s, i: 0 };
    let mut parts: Vec<String> = Vec::new();
    // Identifiers interleaved with nominal markers: `CounterV4bump` → Counter, bump.
    loop {
        while matches!(p.peek(), Some('V' | 'C' | 'O')) {
            p.bump();
        }
        if !p.remaining().starts_with(|c: char| c.is_ascii_digit()) {
            break;
        }
        let ident = p.read_identifier()?;
        parts.push(ident);
        if p.done() {
            break;
        }
    }
    if parts.is_empty() {
        return None;
    }
    let module = parts.remove(0);
    let path = parts;

    let rem = p.remaining();
    let is_static = rem.contains('Z');
    let is_getter = rem.contains("vg") || rem.ends_with("g");
    let is_setter = rem.contains("vs") || (rem.contains('s') && rem.contains('F'));
    let is_method = path.len() >= 2;

    let (ret_ty, args_ty) = p.parse_function_types().unwrap_or((None, None));
    let arg_types = match args_ty {
        Some(a) if a.is_empty() => Vec::new(),
        Some(a) => a
            .split(", ")
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        None => Vec::new(),
    };

    let kind = if is_getter {
        SwiftKind::Getter
    } else if is_setter {
        SwiftKind::Setter
    } else if is_method {
        SwiftKind::Method
    } else {
        SwiftKind::Function
    };

    Some(SwiftSymbol {
        module,
        path,
        kind,
        arg_types,
        ret_type: ret_ty,
        is_static,
        is_method,
    })
}

struct Parser<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Parser<'a> {
    fn remaining(&self) -> &'a str {
        &self.s[self.i..]
    }

    fn done(&self) -> bool {
        self.i >= self.s.len()
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let mut chs = self.remaining().chars();
        let c = chs.next()?;
        self.i += c.len_utf8();
        Some(c)
    }

    fn read_decimal(&mut self) -> Option<usize> {
        let start = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.bump();
        }
        if self.i == start {
            return None;
        }
        self.s[start..self.i].parse().ok()
    }

    fn read_identifier(&mut self) -> Option<String> {
        let len = self.read_decimal()?;
        let start = self.i;
        let end = start.checked_add(len)?;
        if end > self.s.len() {
            return None;
        }
        let id = self.s[start..end].to_string();
        self.i = end;
        Some(id)
    }

    fn parse_function_types(&mut self) -> Option<(Option<String>, Option<String>)> {
        let rem = self.remaining();
        if rem.is_empty() {
            return Some((None, None));
        }
        let body = rem.trim_end_matches(|c| matches!(c, 'F' | 'C' | 'V' | 'O' | 'Z' | 'f' | 'A'));
        if body.is_empty() {
            return Some((None, Some(String::new())));
        }
        let (ret, args) = split_ret_args(body);
        Some((ret, args))
    }
}

fn split_ret_args(body: &str) -> (Option<String>, Option<String>) {
    let atoms = parse_type_atoms(body);
    if atoms.is_empty() {
        return (None, None);
    }
    // `yS2i` style: leading void marker + N Ints → first Int is return, rest args
    // (matches swift-demangle for `add1(Int)->Int`).
    if body.starts_with('y') && atoms.len() >= 2 && atoms[0] == "()" {
        let ret = atoms[1].clone();
        let args = atoms[2..].join(", ");
        return (Some(ret), Some(args));
    }
    if body.ends_with('y') && !atoms.is_empty() {
        let ret = atoms[..atoms.len().saturating_sub(1)]
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let ret = if ret.is_empty() { None } else { Some(ret) };
        return (ret, Some(String::new()));
    }
    if body.starts_with('y') {
        let args = atoms
            .iter()
            .skip(1)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        return (Some(String::from("()")), Some(args));
    }
    if atoms.len() == 1 {
        return (Some(atoms[0].clone()), Some(String::new()));
    }
    let ret = atoms[0].clone();
    let args = atoms[1..].join(", ");
    (Some(ret), Some(args))
}

fn parse_type_atoms(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        // `S` + count + abbr  →  repeat stdlib type (e.g. S2i = Int, Int)
        if b[i] == b'S' && i + 1 < b.len() && (b[i + 1] as char).is_ascii_digit() {
            i += 1;
            let start = i;
            while i < b.len() && (b[i] as char).is_ascii_digit() {
                i += 1;
            }
            let count: usize = s[start..i].parse().unwrap_or(1);
            if i >= b.len() {
                break;
            }
            let code = b[i] as char;
            i += 1;
            if let Some(name) = stdlib_abbr(code) {
                for _ in 0..count.max(1) {
                    out.push(String::from(name));
                }
            }
            continue;
        }
        if i + 1 < b.len() && b[i] == b'S' {
            let code = b[i + 1] as char;
            if let Some(name) = stdlib_abbr(code) {
                out.push(String::from(name));
                i += 2;
                continue;
            }
            out.push(format!("S{code}"));
            i += 2;
            continue;
        }
        if b[i] == b'y' {
            out.push(String::from("()"));
            i += 1;
            continue;
        }
        // `_` separates labeled params in some forms — skip.
        if b[i] == b'_' {
            i += 1;
            continue;
        }
        if (b[i] as char).is_ascii_digit() {
            let start = i;
            while i < b.len() && (b[i] as char).is_ascii_digit() {
                i += 1;
            }
            if let Ok(len) = s[start..i].parse::<usize>() {
                if i + len <= s.len() {
                    out.push(s[i..i + len].to_string());
                    i += len;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

fn stdlib_abbr(code: char) -> Option<&'static str> {
    Some(match code {
        'i' => "Swift.Int",
        's' | 'S' => "Swift.String",
        'b' => "Swift.Bool",
        'f' => "Swift.Float",
        'd' => "Swift.Double",
        'u' => "Swift.UInt",
        'q' => "Swift.Optional",
        'a' => "Swift.Array",
        'c' => "Swift.Unicode.Scalar",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_simple_hello() {
        let d = demangle_swift("_$s1t5helloSiyF").expect("demangle");
        assert!(d.starts_with("t.hello("), "{d}");
        assert!(d.contains("Swift.Int") || d.contains("Int"), "{d}");
    }

    #[test]
    fn parse_struct_smoke_hello() {
        let s = parse_swift_symbol("_$s5smoke5helloSiyF").expect("parse");
        assert_eq!(s.module, "smoke");
        assert_eq!(s.path, alloc::vec![String::from("hello")]);
        assert_eq!(s.ret_type.as_deref(), Some("Swift.Int"));
        assert!(!s.is_method);
    }

    #[test]
    fn format_proto_free_func() {
        let sym = parse_swift_symbol("_$s5smoke5helloSiyF").unwrap();
        let frame = FrameRecovery {
            returns_value: true,
            return_ty: Ty::Int64,
            ..Default::default()
        };
        let p = format_swift_prototype(&sym, &frame);
        assert!(p.starts_with("func smoke.hello("), "{p}");
        assert!(p.contains("-> Int"), "{p}");
    }

    #[test]
    fn rejects_c_symbols() {
        assert!(!is_swift_mangled("_add1"));
        assert!(demangle_swift("_add1").is_none());
    }

    #[test]
    fn parse_add1_repeat_int() {
        let s = parse_swift_symbol("_$s5smoke4add1yS2iF").expect("parse");
        assert_eq!(s.short_name(), "add1");
        assert_eq!(s.ret_type.as_deref(), Some("Swift.Int"));
        assert_eq!(s.arg_types, alloc::vec![String::from("Swift.Int")]);
    }

    #[test]
    fn parse_method_bump() {
        let s = parse_swift_symbol("_$s5smoke7CounterV4bumpSiyF").expect("parse");
        assert_eq!(s.module, "smoke");
        assert_eq!(
            s.path,
            alloc::vec![String::from("Counter"), String::from("bump")]
        );
        assert!(s.is_method);
        let frame = FrameRecovery {
            params: alloc::vec![String::from("self")],
            returns_value: true,
            return_ty: Ty::Int64,
            ..Default::default()
        };
        let p = format_swift_prototype(&s, &frame);
        assert!(p.contains("func bump(") || p.contains("func Counter.bump"), "{p}");
        assert!(p.contains("-> Int"), "{p}");
    }
}
