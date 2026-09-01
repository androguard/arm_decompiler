//! Best-effort Swift metadata / string recovery from Mach-O (Phase 6 / S3).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use macho_core::MachoFile;

/// Recovered Swift reflection / string hints keyed by virtual address.
#[derive(Clone, Debug, Default)]
pub struct SwiftMetadata {
    /// VA → type or field name from `__swift5_types` / typeref-ish sections.
    pub type_names: BTreeMap<u64, String>,
    /// VA → UTF-8 string from `__swift5_reflstr` / cstring-like Swift sections.
    pub strings: BTreeMap<u64, String>,
    /// Ordered property-like names from `__swift5_reflstr` (G3).
    pub field_names: Vec<String>,
}

impl SwiftMetadata {
    /// Parse available `__TEXT.__swift5_*` (and related) sections. Never fails hard.
    pub fn parse(file: &MachoFile<'_>) -> Self {
        let mut meta = Self::default();
        let mut reflstr = BTreeMap::new();
        let _ = collect_cstring_section(file, "__TEXT", "__swift5_reflstr", &mut reflstr);
        for (k, v) in &reflstr {
            meta.strings.insert(*k, v.clone());
        }
        let _ = collect_cstring_section(file, "__TEXT", "__swift5_fieldmd", &mut meta.strings);
        let _ = collect_printable_names(file, "__TEXT", "__swift5_typeref", &mut meta.type_names);
        let _ = collect_printable_names(file, "__TEXT", "__swift5_types", &mut meta.type_names);
        let _ = collect_cstring_section(file, "__TEXT", "__cstring", &mut meta.strings);
        // G3: property names come from reflection strings, not generic cstrings ("hi", …).
        meta.field_names = collect_field_names(&reflstr);
        meta
    }

    pub fn lookup_string(&self, va: u64) -> Option<&str> {
        self.strings.get(&va).map(String::as_str)
    }

    pub fn lookup_type(&self, va: u64) -> Option<&str> {
        self.type_names.get(&va).map(String::as_str)
    }

    /// Best primary stored property name (e.g. `value` for `Counter`).
    pub fn primary_field(&self) -> Option<&str> {
        self.field_names.first().map(String::as_str)
    }
}

fn collect_field_names(strings: &BTreeMap<u64, String>) -> Vec<String> {
    let mut out = Vec::new();
    for s in strings.values() {
        if is_field_ident(s) && !out.iter().any(|x| x == s) {
            out.push(s.clone());
        }
    }
    out
}

fn is_field_ident(s: &str) -> bool {
    let b = s.as_bytes();
    if s.len() < 2 || s.len() > 48 {
        return false;
    }
    // Lowercase-leading Swift properties; skip type names (Capitalized).
    if !b[0].is_ascii_lowercase() {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn collect_cstring_section(
    file: &MachoFile<'_>,
    seg: &str,
    sect: &str,
    out: &mut BTreeMap<u64, String>,
) -> Result<(), ()> {
    let Some(s) = file.find_section(seg, sect).ok().flatten() else {
        return Ok(());
    };
    let data = file.section_data(s).map_err(|_| ())?;
    let base = s.addr;
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len() && data[i] != 0 {
            i += 1;
        }
        if let Ok(s) = core::str::from_utf8(&data[start..i]) {
            if is_useful_swift_string(s) {
                out.insert(base + start as u64, s.to_string());
            }
        }
        i += 1;
    }
    Ok(())
}

fn collect_printable_names(
    file: &MachoFile<'_>,
    seg: &str,
    sect: &str,
    out: &mut BTreeMap<u64, String>,
) -> Result<(), ()> {
    let Some(s) = file.find_section(seg, sect).ok().flatten() else {
        return Ok(());
    };
    let data = file.section_data(s).map_err(|_| ())?;
    let base = s.addr;
    let mut i = 0usize;
    while i < data.len() {
        if !data[i].is_ascii_alphabetic() && data[i] != b'_' {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len()
            && (data[i].is_ascii_alphanumeric() || data[i] == b'_' || data[i] == b'.')
        {
            i += 1;
        }
        if i - start >= 2 {
            if let Ok(name) = core::str::from_utf8(&data[start..i]) {
                out.insert(base + start as u64, name.to_string());
            }
        }
    }
    Ok(())
}

fn is_useful_swift_string(s: &str) -> bool {
    if s.len() < 2 || s.len() > 200 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_graphic() || c == ' ')
        && s.chars().any(|c| c.is_ascii_alphabetic())
}

/// Replace `Expr::Imm(va)` string loads with Swift string literals when known.
pub fn rewrite_swift_string_imms(
    block_stmts: &mut [Vec<crate::ir::Stmt>],
    meta: &SwiftMetadata,
) {
    if meta.strings.is_empty() {
        return;
    }
    use crate::ir::Stmt;
    for stmts in block_stmts.iter_mut() {
        for s in stmts.iter_mut() {
            match s {
                Stmt::Assign { rhs, .. } => rewrite_imm_string(rhs, meta),
                Stmt::Store { value, .. } => rewrite_imm_string(value, meta),
                Stmt::Expr { expr, .. } => rewrite_imm_string(expr, meta),
                Stmt::Return {
                    value: Some(v), ..
                } => rewrite_imm_string(v, meta),
                _ => {}
            }
        }
    }
}

fn rewrite_imm_string(expr: &mut crate::ir::Expr, meta: &SwiftMetadata) {
    use crate::ir::Expr;
    match expr {
        Expr::Imm(va) => {
            if let Some(s) = meta.lookup_string(*va) {
                *expr = Expr::Raw(format!("\"{}\"", escape_swift_string(s)));
            }
        }
        Expr::Call { args, .. } => {
            for a in args.iter_mut() {
                rewrite_imm_string(a, meta);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            rewrite_imm_string(lhs, meta);
            rewrite_imm_string(rhs, meta);
        }
        Expr::MsgSend {
            receiver, args, ..
        } => {
            rewrite_imm_string(receiver, meta);
            for a in args.iter_mut() {
                rewrite_imm_string(a, meta);
            }
        }
        _ => {}
    }
}

fn escape_swift_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

/// Rewrite `*(self)` / `*(local_alias_of_self)` loads/stores to `self.field` (G3).
pub fn rewrite_swift_fields(
    block_stmts: &mut [Vec<crate::ir::Stmt>],
    meta: &SwiftMetadata,
    self_aliases: &[String],
) {
    use crate::ir::Stmt;
    let Some(field) = meta.primary_field() else {
        return;
    };
    let field = field.to_string();
    for stmts in block_stmts.iter_mut() {
        for s in stmts.iter_mut() {
            match s {
                Stmt::Assign { rhs, .. } => rewrite_field_expr(rhs, &field, self_aliases),
                Stmt::Store {
                    addr,
                    value,
                    comment,
                } => {
                    rewrite_field_expr(value, &field, self_aliases);
                    if is_self_addr(addr, self_aliases) {
                        let v = value.clone();
                        let c = comment.clone();
                        *s = crate::ir::Stmt::Assign {
                            dst: crate::ir::Place::Name(format!("self.{field}")),
                            rhs: v,
                            comment: c,
                        };
                    }
                }
                Stmt::Expr { expr, .. } => rewrite_field_expr(expr, &field, self_aliases),
                Stmt::Return {
                    value: Some(v), ..
                } => rewrite_field_expr(v, &field, self_aliases),
                _ => {}
            }
        }
    }
}

fn is_self_addr(addr: &crate::ir::Expr, self_aliases: &[String]) -> bool {
    use crate::ir::Expr;
    match addr {
        Expr::Name(n) => n == "self" || self_aliases.iter().any(|a| a == n),
        Expr::Mem(s) | Expr::Raw(s) => mem_to_field(s, "_", self_aliases).is_some(),
        _ => false,
    }
}

fn rewrite_field_expr(
    expr: &mut crate::ir::Expr,
    field: &str,
    self_aliases: &[String],
) {
    use crate::ir::Expr;
    match expr {
        Expr::Mem(s) => {
            if let Some(repl) = mem_to_field(s, field, self_aliases) {
                *expr = Expr::Raw(repl);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            rewrite_field_expr(lhs, field, self_aliases);
            rewrite_field_expr(rhs, field, self_aliases);
        }
        Expr::Call { args, .. } => {
            for a in args.iter_mut() {
                rewrite_field_expr(a, field, self_aliases);
            }
        }
        _ => {}
    }
}

fn mem_to_field(s: &str, field: &str, self_aliases: &[String]) -> Option<String> {
    let t = s.trim();
    let inner = t
        .strip_prefix("*(")
        .and_then(|r| r.strip_suffix(')'))
        .unwrap_or(t);
    let inner = inner.trim();
    if inner == "self" || self_aliases.iter().any(|a| a == inner) {
        return Some(format!("self.{field}"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Expr, Place, Stmt};
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn primary_field_from_reflstr_like_map() {
        let mut strings = BTreeMap::new();
        strings.insert(1, String::from("value"));
        strings.insert(2, String::from("Counter"));
        let names = collect_field_names(&strings);
        assert_eq!(names, alloc::vec![String::from("value")]);
    }

    #[test]
    fn rewrites_star_self_to_field() {
        let meta = SwiftMetadata {
            field_names: alloc::vec![String::from("value")],
            ..Default::default()
        };
        let mut blocks = vec![vec![Stmt::Assign {
            dst: Place::Name(String::from("local_10")),
            rhs: Expr::Mem(String::from("*(self)")),
            comment: None,
        }]];
        rewrite_swift_fields(&mut blocks, &meta, &[]);
        match &blocks[0][0] {
            Stmt::Assign {
                rhs: Expr::Raw(s),
                ..
            } => assert_eq!(s, "self.value"),
            other => panic!("{other:?}"),
        }
    }
}
