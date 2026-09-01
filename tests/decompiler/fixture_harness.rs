//! Shared harness: decompile fixture Mach-O symbols, extract bodies, compare to C sources.
//!
//! Mirrors dex-decompiler `tests/decompiler/fixture_harness.rs`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use arm_decompiler::{decompile_macho_symbol, DecompilerOptions, FunctionDecompile};

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/decompiler_fixtures")
}

pub fn fixtures_binary_path() -> PathBuf {
    fixtures_dir().join("decompiler_fixtures")
}

pub fn fixtures_src_dir() -> PathBuf {
    fixtures_dir().join("src")
}

pub fn load_fixture_bytes() -> Vec<u8> {
    let path = fixtures_binary_path();
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

pub fn decompile_symbol(symbol: &str) -> FunctionDecompile {
    decompile_macho_symbol(&load_fixture_bytes(), symbol, &DecompilerOptions::default())
        .unwrap_or_else(|e| panic!("decompile {symbol}: {e}"))
}

/// Extract one function body (`name(…) { … }` or Swift `func … { … }`) from decompiled or source.
pub fn function_region(c: &str, symbol: &str) -> String {
    // Swift mangled symbols emit `func … {`.
    if symbol.contains("$s") || symbol.contains("$S") {
        if let Some(i) = c.find("func ") {
            return extract_brace_region(c, i, symbol);
        }
    }
    // ObjC IMP symbols decompile as `- (ret)sel:… {` without the Class name.
    if let Some(sel) = objc_selector_from_symbol(symbol) {
        if let Some(region) = objc_method_region(c, sel) {
            return region;
        }
    }
    let bare = symbol.trim_start_matches('_');
    let needles = [symbol, bare];
    let mut idx = 0;
    let sig_start = loop {
        let mut found = None;
        for n in needles {
            let needle = format!("{n}(");
            let mut search = idx;
            while let Some(rel) = c[search..].find(&needle) {
                let start = search + rel;
                if start > 0 {
                    let prev = c.as_bytes()[start - 1] as char;
                    if prev.is_ascii_alphanumeric() || prev == '_' {
                        search = start + 1;
                        continue;
                    }
                }
                if found.map(|f| start < f).unwrap_or(true) {
                    found = Some(start);
                }
                break;
            }
        }
        let Some(start) = found else {
            panic!("function {symbol} not found in:\n{c}");
        };
        let line_start = c[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line = &c[line_start..start];
        // Skip prototype-only lines and call sites (`x = foo(` / `return foo(`).
        let is_call = line.contains('=') || line.trim_start().starts_with("return");
        let looks_def = line.contains("int ")
            || line.contains("void ")
            || line.contains("static ")
            || line.trim().starts_with("void ")
            || c[start..].contains('{');
        if looks_def && !is_call {
            // Prefer the definition that has a `{` soon after.
            if let Some(brace_rel) = c[start..].find('{') {
                if brace_rel < 80 {
                    let between = c[start..start + brace_rel].trim();
                    if !between.contains(';') {
                        break start;
                    }
                }
            }
        }
        idx = start + 1;
    };
    extract_brace_region(c, sig_start, symbol)
}

fn objc_selector_from_symbol(symbol: &str) -> Option<&str> {
    let rest = symbol
        .strip_prefix("-[")
        .or_else(|| symbol.strip_prefix("+["))?;
    let rest = rest.strip_suffix(']')?;
    rest.split_once(' ').map(|(_, sel)| sel)
}

fn objc_method_region(c: &str, selector: &str) -> Option<String> {
    let first = selector.split(':').next().unwrap_or(selector);
    let mut offset = 0usize;
    for line in c.lines() {
        let t = line.trim_start();
        if (t.starts_with("- (") || t.starts_with("+ ("))
            && t.contains(first)
            && (selector.contains(':') && t.contains(':') || t.contains(selector))
        {
            // Align to the `-`/`+` on this line.
            let trim_off = line.len() - line.trim_start().len();
            return Some(extract_brace_region(c, offset + trim_off, selector));
        }
        offset += line.len() + 1;
    }
    None
}

fn extract_brace_region(c: &str, sig_start: usize, label: &str) -> String {
    let open_rel = c[sig_start..]
        .find('{')
        .unwrap_or_else(|| panic!("function {label} has no opening brace"));
    let open = sig_start + open_rel;
    let mut depth = 0i32;
    for (i, ch) in c[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return c[sig_start..=open + i].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("function {label} has unbalanced braces");
}

#[allow(dead_code)]
pub fn normalize_c_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out.trim().to_string()
}

const C_KEYWORDS: &[&str] = &[
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
    "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
    "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
    "union", "unsigned", "void", "volatile", "while", "true", "false", "bool",
];

fn is_c_keyword(s: &str) -> bool {
    C_KEYWORDS.contains(&s)
}

/// Identifiers from a C function that should appear in faithful decompilation.
pub fn source_identifiers(method_src: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut word = String::new();
    for ch in method_src.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_alphabetic() || ch == '_' || (!word.is_empty() && ch.is_ascii_digit()) {
            word.push(ch);
        } else if !word.is_empty() {
            if word.len() > 1 && !is_c_keyword(&word) {
                out.insert(word.clone());
            }
            word.clear();
        }
    }
    out
}

/// Register / stack soup still common before M2 locals.
fn looks_like_reg_soup(name: &str) -> bool {
    let b = name.as_bytes();
    if b.len() >= 2 {
        let (p, rest) = (b[0], &b[1..]);
        if matches!(p, b'x' | b'w' | b'd' | b's' | b'v') && rest.iter().all(|c| c.is_ascii_digit())
        {
            return true;
        }
    }
    matches!(name, "sp" | "fp" | "lr" | "xzr" | "wzr" | "x29" | "x30")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareTier {
    /// Method decompiles; minimal string checks.
    Smoke,
    /// Control-flow / call shape without requiring source names.
    Structural,
    /// Prefer source identifiers; discourage raw register soup.
    SourceLike,
}

#[derive(Clone, Copy, Debug)]
pub struct FixtureSpec {
    /// Source file stem under `src/` (e.g. `control_flow`).
    pub group: &'static str,
    /// Mach-O symbol including leading `_`.
    pub symbol: &'static str,
    pub tier: CompareTier,
    /// Require C source identifiers to appear in decompiled text.
    pub source_ids: bool,
    pub must_contain: &'static [&'static str],
    pub must_not_contain: &'static [&'static str],
    pub skip_source_ids: &'static [&'static str],
    /// Optional Mach-O path relative to `testdata/` (Swift fixtures, etc.).
    pub macho_rel: Option<&'static str>,
    /// Optional source path relative to `testdata/` (`.swift` / `.c`).
    pub source_rel: Option<&'static str>,
}

impl FixtureSpec {
    pub fn full_name(&self) -> String {
        format!("{}.{}", self.group, self.symbol)
    }

    pub fn check_errors(&self, decompiled: &str, source_c: &str) -> Vec<String> {
        let body = function_region(decompiled, self.symbol);
        let source = if self.source_ids {
            function_region(source_c, self.symbol)
        } else {
            String::new()
        };
        let ctx = self.full_name();
        let mut errors = Vec::new();

        if body.trim().is_empty() {
            errors.push(format!("{ctx}: empty decompiled body"));
        }

        for needle in self.must_contain {
            if !body.contains(needle) && !decompiled.contains(needle) {
                errors.push(format!(
                    "{ctx}: expected `{needle}` in decompiled output:\n{body}"
                ));
            }
        }
        for needle in self.must_not_contain {
            if body.contains(needle) || decompiled.contains(needle) {
                errors.push(format!("{ctx}: must not contain `{needle}`:\n{body}"));
            }
        }

        if self.tier == CompareTier::Smoke {
            return errors;
        }

        let mut allowed = source_identifiers(&source);
        for s in self.skip_source_ids {
            allowed.remove(*s);
        }

        if self.source_ids {
            for id in &allowed {
                if id.len() <= 1 {
                    continue;
                }
                if !body.contains(id.as_str()) {
                    errors.push(format!(
                        "{ctx}: source identifier `{id}` missing from decompiled output:\n{body}\n\nsource:\n{source}"
                    ));
                }
            }
        }

        if self.tier == CompareTier::SourceLike {
            // Flag heavy register soup as soft progress signal.
            let soup: Vec<_> = body
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|t| looks_like_reg_soup(t))
                .collect();
            if soup.len() > 12 {
                errors.push(format!(
                    "{ctx}: SourceLike tier still has heavy register soup ({count} tokens); promote only after M2 locals:\n{body}",
                    count = soup.len()
                ));
            }
        }

        errors
    }
}

pub fn load_group_source(group: &str) -> String {
    let dir = fixtures_src_dir();
    for ext in ["c", "m", "mm"] {
        let path = dir.join(format!("{group}.{ext}"));
        if path.is_file() {
            return std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        }
    }
    panic!(
        "no source for group `{group}` under {} (tried .c/.m/.mm)",
        dir.display()
    )
}

pub fn load_spec_source(spec: &FixtureSpec) -> String {
    if let Some(rel) = spec.source_rel {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(rel);
        return std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    }
    load_group_source(spec.group)
}

pub fn decompile_spec(spec: &FixtureSpec) -> FunctionDecompile {
    let bytes = if let Some(rel) = spec.macho_rel {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(rel);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    } else {
        load_fixture_bytes()
    };
    decompile_macho_symbol(&bytes, spec.symbol, &DecompilerOptions::default())
        .unwrap_or_else(|e| panic!("decompile {}: {e}", spec.symbol))
}

/// Decompile one symbol and return its source text (full emit).
pub fn decompile_symbol_source(symbol: &str) -> String {
    decompile_symbol(symbol).source
}

pub fn check_all_fixtures(manifest: &[FixtureSpec]) -> Vec<(String, Vec<String>)> {
    let mut by_group: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    let mut results = Vec::new();
    for spec in manifest {
        let source = if spec.source_rel.is_some() {
            load_spec_source(spec)
        } else {
            by_group
                .entry(spec.group)
                .or_insert_with(|| load_group_source(spec.group))
                .clone()
        };
        let decompiled = decompile_spec(spec).source;
        let errors = spec.check_errors(&decompiled, &source);
        results.push((spec.full_name(), errors));
    }
    results
}

pub fn assert_all_fixtures(manifest: &[FixtureSpec]) {
    let results = check_all_fixtures(manifest);
    let mut failed = Vec::new();
    for (name, errors) in results {
        if !errors.is_empty() {
            failed.push(format!(
                "{name}:\n{}",
                errors.join("\n")
            ));
        }
    }
    assert!(
        failed.is_empty(),
        "{} fixture(s) failed fidelity checks:\n\n{}",
        failed.len(),
        failed.join("\n\n---\n\n")
    );
}

/// Top-level function definitions in fixture `.c` files (bare names, no `_`).
pub fn catalog_c_functions() -> Vec<(String, String)> {
    let src = fixtures_src_dir();
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&src).expect("read fixture src") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("c") {
            continue;
        }
        let group = path
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string();
        // Callee-only TUs (e.g. jump-table helpers) are not scoreboard fixtures.
        if group.ends_with("_helpers") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read c");
        for name in parse_c_function_names(&text) {
            // Skip local prototypes that are only declarations (no body in this file).
            if function_has_body(&text, &name) {
                out.push((group.clone(), name));
            }
        }
    }
    out.sort();
    out
}

fn function_has_body(text: &str, bare: &str) -> bool {
    let needle = format!("{bare}(");
    let mut idx = 0;
    while let Some(rel) = text[idx..].find(&needle) {
        let start = idx + rel;
        // Require a word boundary so `call_add1(` does not match `add1(`.
        if start > 0 {
            let prev = text.as_bytes()[start - 1] as char;
            if prev.is_ascii_alphanumeric() || prev == '_' {
                idx = start + 1;
                continue;
            }
        }
        let line_start = text[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line = &text[line_start..start];
        if line.contains('=') || line.trim_start().starts_with("return") {
            idx = start + 1;
            continue;
        }
        if let Some(brace_rel) = text[start..].find('{') {
            if brace_rel < 80 {
                let between = text[start + needle.len() - 1..start + brace_rel].trim();
                // `int foo(int x);` has `;` before `{` elsewhere — require `{` before `;` on this decl.
                if !between.contains(';') {
                    return true;
                }
            }
        }
        idx = start + 1;
    }
    false
}

fn parse_c_function_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }
        // Skip prototypes (`int foo(int x);`).
        if trimmed.ends_with(';') {
            continue;
        }
        if trimmed.starts_with("int ") || trimmed.starts_with("void ") || trimmed.starts_with("static ")
        {
            if let Some(paren) = trimmed.find('(') {
                let before = trimmed[..paren].trim();
                if let Some(name) = before.split_whitespace().last() {
                    if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                        names.push(name.to_string());
                    }
                }
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

pub fn assert_manifest_covers_catalog(manifest: &[FixtureSpec]) {
    let catalog = catalog_c_functions();
    let covered: HashSet<String> = manifest
        .iter()
        .map(|s| {
            let bare = s.symbol.trim_start_matches('_');
            format!("{}.{}", s.group, bare)
        })
        .collect();
    let mut missing = Vec::new();
    for (group, bare) in catalog {
        let key = format!("{group}.{bare}");
        if !covered.contains(&key) {
            missing.push(key);
        }
    }
    assert!(
        missing.is_empty(),
        "fixture manifest missing C functions (add to fixture_manifest.rs):\n{}",
        missing.join("\n")
    );
}

pub fn scoreboard_lines(manifest: &[FixtureSpec]) -> Vec<String> {
    let results = check_all_fixtures(manifest);
    let mut lines = Vec::new();
    let mut pass = 0usize;
    let mut fail = 0usize;
    for (spec, (_, errors)) in manifest.iter().zip(results) {
        let ok = errors.is_empty();
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        let mark = if ok { "PASS" } else { "FAIL" };
        lines.push(format!(
            "{mark}  {:<12}  {}",
            format!("{:?}", spec.tier),
            spec.full_name()
        ));
        for e in errors.iter().take(2) {
            lines.push(format!("        · {}", e.lines().next().unwrap_or(e)));
        }
    }
    lines.push(format!(
        "---\n{pass} passed, {fail} failed / {} total",
        pass + fail
    ));
    lines
}

#[allow(dead_code)]
pub fn fixtures_dir_exists() -> bool {
    Path::new(&fixtures_binary_path()).is_file()
}
