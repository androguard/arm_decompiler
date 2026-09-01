//! User-defined renames for decompiled C/ObjC (dex-decompiler `rename.rs` analogue).
//!
//! Keys for per-function variables use the symbol name (e.g. `_while_sum` or
//! `-[CDSmoke hello:]`).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Map of old identifier → new identifier for renaming in decompiled source.
#[derive(Clone, Debug, Default)]
pub struct RenameMap {
    /// Function / IMP symbol renames: `_add1` → `add_one`, `-[Foo bar:]` → …
    pub symbol: BTreeMap<String, String>,
    /// Global variable renames applied in every function (`local_c` → `sum`).
    pub variable: BTreeMap<String, String>,
    /// Per-function variable renames: symbol → (old → new).
    pub variable_in: BTreeMap<String, BTreeMap<String, String>>,
    /// ObjC selector fragment renames inside `[recv sel:…]` (e.g. `hello:` → `greet:`).
    pub selector: BTreeMap<String, String>,
}

impl RenameMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge a `old=new` CLI pair into global variable renames.
    pub fn insert_var_pair(&mut self, old: &str, new: &str) {
        self.variable.insert(old.into(), new.into());
    }

    /// Build replacement list for one decompiled function.
    pub fn replacements_for(&self, function_symbol: &str) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        for (old, new) in &self.symbol {
            out.push((old.clone(), new.clone()));
        }
        for (old, new) in &self.variable {
            out.push((old.clone(), new.clone()));
        }
        if let Some(per) = self.variable_in.get(function_symbol) {
            for (old, new) in per {
                out.push((old.clone(), new.clone()));
            }
        }
        // Also try bare name without leading `_`.
        let bare = function_symbol.trim_start_matches('_');
        if bare != function_symbol {
            if let Some(per) = self.variable_in.get(bare) {
                for (old, new) in per {
                    out.push((old.clone(), new.clone()));
                }
            }
        }
        for (old, new) in &self.selector {
            out.push((old.clone(), new.clone()));
        }
        out
    }

    /// Apply renames to decompiled C/ObjC text for `function_symbol`.
    pub fn apply(&self, source: &str, function_symbol: &str) -> String {
        let reps = self.replacements_for(function_symbol);
        apply_replacements(source, &reps)
    }
}

/// Replace only whole identifiers (C: letters, digits, `_`; ObjC selectors may include `:`).
pub fn apply_replacements(source: &str, replacements: &[(String, String)]) -> String {
    if replacements.is_empty() {
        return source.into();
    }
    let mut sorted: Vec<&(String, String)> = replacements.iter().collect();
    sorted.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    let mut out = source.to_string();
    for (old, new) in sorted {
        out = replace_identifier_occurrences(&out, old, new);
    }
    out
}

fn replace_identifier_occurrences(s: &str, old: &str, new: &str) -> String {
    if old.is_empty() {
        return s.into();
    }
    let mut result = String::with_capacity(s.len());
    let mut search_start = 0;
    while let Some(rel) = s[search_start..].find(old) {
        let start = search_start + rel;
        let end = start + old.len();
        let before = start
            .checked_sub(1)
            .and_then(|i| s[i..].chars().next())
            .map(is_ident_char)
            .unwrap_or(false);
        let after = if end >= s.len() {
            false
        } else {
            s[end..]
                .chars()
                .next()
                .map(is_ident_char)
                .unwrap_or(false)
        };
        // Selectors: allow `:` only as part of the matched token, not as a boundary killer
        // when old already ends with `:`.
        if !before && !after {
            result.push_str(&s[search_start..start]);
            result.push_str(new);
            search_start = end;
        } else {
            result.push_str(&s[search_start..=start]);
            search_start = start + 1;
        }
    }
    result.push_str(&s[search_start..]);
    result
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == ':'
}

/// Parse CLI pairs `old=new` / `old:new` into a [`RenameMap`] (global variables).
pub fn rename_map_from_pairs(pairs: &[String]) -> Result<RenameMap, String> {
    let mut map = RenameMap::new();
    for p in pairs {
        let (old, new) = p
            .split_once('=')
            .or_else(|| p.split_once(':'))
            .ok_or_else(|| format!("bad --rename '{p}' (expected old=new)"))?;
        let old = old.trim();
        let new = new.trim();
        if old.is_empty() || new.is_empty() {
            return Err(format!("bad --rename '{p}' (empty name)"));
        }
        if old.starts_with('_') || old.starts_with("-[") || old.starts_with("+[") {
            map.symbol.insert(old.into(), new.into());
        } else if old.ends_with(':') {
            map.selector.insert(old.into(), new.into());
        } else {
            map.variable.insert(old.into(), new.into());
        }
    }
    Ok(map)
}

/// Parse a DSC / host selector map file.
///
/// Accepted lines (blank / `#` comments ignored):
/// - `0xvaddr selector_name`
/// - `vaddr=selector_name` / `vaddr:selector_name`
pub fn parse_selector_map_text(text: &str) -> Result<Vec<(u64, String)>, String> {
    let mut out = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (va_s, name) = if let Some((a, b)) = line.split_once('=') {
            (a.trim(), b.trim())
        } else if let Some((a, b)) = line.split_once(':') {
            // Prefer hex VA before first whitespace when `:` is in selector.
            if a.trim().starts_with("0x") || a.trim().chars().all(|c| c.is_ascii_hexdigit()) {
                (a.trim(), b.trim())
            } else if let Some((va, rest)) = line.split_once(char::is_whitespace) {
                (va, rest.trim())
            } else {
                return Err(format!(
                    "sel-map line {}: expected `VA name` or `VA=name`",
                    lineno + 1
                ));
            }
        } else if let Some((va, rest)) = line.split_once(char::is_whitespace) {
            (va, rest.trim())
        } else {
            return Err(format!(
                "sel-map line {}: expected `VA name` or `VA=name`",
                lineno + 1
            ));
        };
        if name.is_empty() {
            return Err(format!("sel-map line {}: empty selector", lineno + 1));
        }
        let va = if let Some(h) = va_s.strip_prefix("0x").or_else(|| va_s.strip_prefix("0X")) {
            u64::from_str_radix(h, 16)
        } else {
            u64::from_str_radix(va_s, 16).or_else(|_| va_s.parse::<u64>())
        }
        .map_err(|_| format!("sel-map line {}: bad VA '{va_s}'", lineno + 1))?;
        out.push((va, name.to_string()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_word_only() {
        let s = "int local_c; local_c = local_c8;";
        let out = replace_identifier_occurrences(s, "local_c", "sum");
        assert_eq!(out, "int sum; sum = local_c8;");
    }

    #[test]
    fn per_function_vars() {
        let mut m = RenameMap::new();
        m.variable_in
            .entry(String::from("_while_sum"))
            .or_default()
            .insert(String::from("local_c"), String::from("sum"));
        let src = "int _while_sum(void) {\n    int local_c;\n    return local_c;\n}\n";
        let out = m.apply(src, "_while_sum");
        assert!(out.contains("int sum;"), "{out}");
        assert!(out.contains("return sum;"), "{out}");
    }

    #[test]
    fn pairs_classify_symbol_and_selector() {
        let m = rename_map_from_pairs(&[
            String::from("_add1=increment"),
            String::from("hello:=greet:"),
            String::from("local_4=result"),
        ])
        .unwrap();
        assert_eq!(m.symbol.get("_add1").map(String::as_str), Some("increment"));
        assert_eq!(m.selector.get("hello:").map(String::as_str), Some("greet:"));
        assert_eq!(m.variable.get("local_4").map(String::as_str), Some("result"));
    }

    #[test]
    fn parses_selector_map_lines() {
        let m = parse_selector_map_text(
            "# comment\n0x1000 description\n2000=length\n",
        )
        .unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0], (0x1000, String::from("description")));
        assert_eq!(m[1], (0x2000, String::from("length")));
    }
}
