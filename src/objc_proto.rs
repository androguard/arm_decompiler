//! ObjC method prototype recovery from class-dump metadata (P3-4).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use apple_metadata::{format_type, split_method_types, ObjcMetadata, ObjcMethod};

/// Parsed `-[Class sel:]` / `+[Class sel:]` symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjcMethodRef {
    pub is_class: bool,
    pub class_name: String,
    pub selector: String,
}

/// Parse `-[Foo bar:baz:]` / `+[Foo bar]`.
pub fn parse_objc_method_symbol(sym: &str) -> Option<ObjcMethodRef> {
    let s = sym.trim();
    let (is_class, rest) = if let Some(r) = s.strip_prefix("-[") {
        (false, r)
    } else if let Some(r) = s.strip_prefix("+[") {
        (true, r)
    } else {
        return None;
    };
    let rest = rest.strip_suffix(']')?;
    let (class_name, selector) = rest.split_once(' ')?;
    if class_name.is_empty() || selector.is_empty() {
        return None;
    }
    Some(ObjcMethodRef {
        is_class,
        class_name: class_name.to_string(),
        selector: selector.to_string(),
    })
}

/// Look up method encoding by symbol name or IMP address.
pub fn find_objc_method<'a>(
    meta: &'a ObjcMetadata,
    symbol: &str,
    imp: u64,
) -> Option<(bool, &'a ObjcMethod, &'a str)> {
    if let Some(r) = parse_objc_method_symbol(symbol) {
        for c in &meta.classes {
            if c.name != r.class_name {
                continue;
            }
            let methods = if r.is_class {
                &c.class_methods
            } else {
                &c.methods
            };
            if let Some(m) = methods.iter().find(|m| m.name == r.selector) {
                return Some((r.is_class, m, c.name.as_str()));
            }
        }
        for cat in &meta.categories {
            if cat.class_name != r.class_name {
                continue;
            }
            let methods = if r.is_class {
                &cat.class_methods
            } else {
                &cat.methods
            };
            if let Some(m) = methods.iter().find(|m| m.name == r.selector) {
                return Some((r.is_class, m, cat.class_name.as_str()));
            }
        }
    }
    // Fall back: match IMP address.
    for c in &meta.classes {
        for m in &c.methods {
            if m.imp == imp && imp != 0 {
                return Some((false, m, c.name.as_str()));
            }
        }
        for m in &c.class_methods {
            if m.imp == imp && imp != 0 {
                return Some((true, m, c.name.as_str()));
            }
        }
    }
    None
}

/// Format `- (int)hello:(int)x` style prototype (no trailing `;`).
pub fn format_objc_method_prototype(
    is_class: bool,
    selector: &str,
    types: &str,
    param_names: &[String],
) -> String {
    let (ret, args) = split_method_types(types);
    let ret_s = format_type(&ret);
    let prefix = if is_class { '+' } else { '-' };
    let params = if args.len() > 2 { &args[2..] } else { &[] };

    let mut out = format!("{prefix} ({ret_s})");
    if !selector.contains(':') {
        out.push_str(selector);
        return out;
    }

    let sel_parts: Vec<&str> = selector.split(':').collect();
    let mut pi = 0usize;
    for (i, part) in sel_parts.iter().enumerate() {
        if part.is_empty() && i == sel_parts.len() - 1 {
            break;
        }
        out.push_str(part);
        out.push(':');
        let ty = params
            .get(pi)
            .map(|t| format_type(t))
            .unwrap_or_else(|| String::from("id"));
        // Prefer recovered names: skip self/param_1 if present; use later params.
        let name = param_names
            .get(pi + 1) // param_1 is self → index 0; first real arg is param_2 → index 1
            .filter(|n| *n != "self" && !n.starts_with("param_1"))
            .cloned()
            .or_else(|| param_names.get(pi + 1).cloned())
            .unwrap_or_else(|| format!("arg{pi}"));
        // If we still have generic param_N, use argN for readability in prototype only
        // when the body still uses those names — keep consistent with frame.params.
        let name = if name == "self" {
            format!("arg{pi}")
        } else {
            name
        };
        out.push_str(&format!("({ty}){name}"));
        if i + 2 < sel_parts.len() || (i + 1 < sel_parts.len() && !sel_parts[i + 1].is_empty())
        {
            out.push(' ');
        }
        pi += 1;
    }
    out
}

/// Prefer body param names after `self`: `param_2`… or renamed locals.
#[allow(dead_code)]
pub fn objc_proto_param_names(params: &[String]) -> Vec<String> {
    params.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_instance_method_symbol() {
        let r = parse_objc_method_symbol("-[CDSmoke hello:]").unwrap();
        assert!(!r.is_class);
        assert_eq!(r.class_name, "CDSmoke");
        assert_eq!(r.selector, "hello:");
    }

    #[test]
    fn formats_hello_proto() {
        let p = format_objc_method_prototype(
            false,
            "hello:",
            "i24@0:8i16",
            &[String::from("self"), String::from("param_2")],
        );
        assert!(p.starts_with("- (int)hello:(int)"), "{p}");
        assert!(p.contains("param_2") || p.contains("arg0"), "{p}");
    }
}
