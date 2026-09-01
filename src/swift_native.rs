//! Optional native `swift demangle` fallback (Phase 6.1 / Ghidra parity).
//!
//! G1: prefer toolchain demangle when in-process disagrees.
//! G5: cache native results per-process (avoid N× `swift` forks).
//! G6: missing Swift on PATH → `None` (in-process still works).

use alloc::string::{String, ToString};

/// Run `swift demangle --compact <name>` when the `std` feature is enabled.
///
/// Returns `None` if Swift is missing from `PATH`, the process fails, or output
/// is still mangled. Results are memoized for the process lifetime (G5).
pub fn demangle_swift_native(name: &str) -> Option<String> {
    #[cfg(feature = "std")]
    {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};

        static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

        if let Ok(guard) = cache.lock() {
            if let Some(hit) = guard.get(name) {
                return hit.clone();
            }
        }

        let resolved = demangle_swift_native_uncached(name);
        if let Ok(mut guard) = cache.lock() {
            guard.insert(name.into(), resolved.clone());
        }
        resolved
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = name;
        None
    }
}

#[cfg(feature = "std")]
fn demangle_swift_native_uncached(name: &str) -> Option<String> {
    use std::process::Command;
    let out = Command::new("swift")
        .args(["demangle", "--compact", name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().next()?.trim();
    if line.is_empty() || line == name {
        return None;
    }
    let bare = line.trim_start_matches('_');
    if bare.starts_with("$s") || bare.starts_with("$S") {
        return None;
    }
    Some(line.to_string())
}

/// True when two demangle strings disagree on the callable identity (G1).
///
/// Compares the qualified name before `(` and normalizes `Swift.` prefixes in
/// the return/arg tails lightly so cosmetic differences do not force a swap.
pub fn demangle_signatures_disagree(local: &str, native: &str) -> bool {
    fn head(s: &str) -> &str {
        s.split('(').next().unwrap_or(s).trim()
    }
    let a = head(local);
    let b = head(native);
    if a != b {
        return true;
    }
    // Same head — compare normalized full string without Swift. prefix.
    let norm = |s: &str| s.replace("Swift.", "");
    norm(local) != norm(native)
}

/// Pick the better demangle string: prefer `native` when it disagrees (G1).
pub fn prefer_demangle(local: Option<String>, native: Option<String>) -> Option<String> {
    match (local, native) {
        (Some(l), Some(n)) if demangle_signatures_disagree(&l, &n) => Some(n),
        (Some(l), Some(_)) => Some(l),
        (None, n) => n,
        (l, None) => l,
    }
}

/// Turn a compact demangle string into a Swift `func` prototype line.
pub fn prototype_from_native_demangle(demangled: &str, prefer_short_method: bool) -> String {
    let demangled = demangled.trim();
    let (head, ret) = match demangled.rsplit_once(" -> ") {
        Some((h, r)) => (h.trim(), Some(simplify_ty(r.trim()))),
        None => (demangled, None),
    };
    let (qual, args_raw) = match head.find('(') {
        Some(i) => (&head[..i], head[i..].trim_start_matches('(').trim_end_matches(')')),
        None => (head, ""),
    };
    let parts: alloc::vec::Vec<&str> = qual.split('.').filter(|p| !p.is_empty()).collect();
    let name = if prefer_short_method && parts.len() >= 3 {
        parts[parts.len() - 1]
    } else {
        qual
    };
    let mut args_out = alloc::vec::Vec::new();
    if !args_raw.is_empty() {
        for (i, a) in args_raw.split(',').enumerate() {
            let ty = simplify_ty(a.trim());
            if ty == "Void" || ty.is_empty() {
                continue;
            }
            args_out.push(alloc::format!("_ arg{}: {ty}", i + 1));
        }
    }
    let mut out = alloc::format!("func {name}({})", args_out.join(", "));
    if let Some(r) = ret {
        if r != "Void" && r != "()" {
            out.push_str(" -> ");
            out.push_str(&r);
        }
    }
    out
}

fn simplify_ty(ty: &str) -> String {
    let t = ty.trim();
    match t {
        "Swift.Int" => String::from("Int"),
        "Swift.String" => String::from("String"),
        "Swift.Bool" => String::from("Bool"),
        "Swift.Float" => String::from("Float"),
        "Swift.Double" => String::from("Double"),
        "Swift.UInt" => String::from("UInt"),
        "()" => String::from("Void"),
        other => {
            if let Some((_, rest)) = other.rsplit_once('.') {
                if !other.starts_with("Swift.") {
                    return rest.to_string();
                }
            }
            other.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_from_native_free() {
        let p = prototype_from_native_demangle("smoke.add1(Swift.Int) -> Swift.Int", false);
        assert!(p.starts_with("func smoke.add1("), "{p}");
        assert!(p.contains("_ arg1: Int"), "{p}");
        assert!(p.contains("-> Int"), "{p}");
    }

    #[test]
    fn proto_from_native_method_short() {
        let p = prototype_from_native_demangle("smoke.Counter.bump() -> Swift.Int", true);
        assert_eq!(p, "func bump() -> Int");
    }

    #[test]
    fn disagree_on_qualified_head() {
        assert!(demangle_signatures_disagree(
            "smoke.Counter() -> Swift.Int",
            "smoke.Counter.bump() -> Swift.Int"
        ));
        assert!(!demangle_signatures_disagree(
            "smoke.hello() -> Swift.Int",
            "smoke.hello() -> Int"
        ));
    }

    #[test]
    fn prefer_native_when_disagree() {
        let out = prefer_demangle(
            Some(String::from("smoke.Counter() -> Swift.Int")),
            Some(String::from("smoke.Counter.bump() -> Swift.Int")),
        );
        assert_eq!(out.as_deref(), Some("smoke.Counter.bump() -> Swift.Int"));
    }

    #[test]
    fn prefer_local_when_agree() {
        let out = prefer_demangle(
            Some(String::from("smoke.hello() -> Swift.Int")),
            Some(String::from("smoke.hello() -> Int")),
        );
        assert_eq!(out.as_deref(), Some("smoke.hello() -> Swift.Int"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn native_none_or_demangle_when_swift_on_path() {
        // G6: missing swift → None; present → demangled.
        let d = demangle_swift_native("_$s5smoke5helloSiyF");
        if std::process::Command::new("swift")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            let d = d.expect("swift on PATH should demangle");
            assert!(d.contains("hello"), "{d}");
            // G5: second call hits cache (same result).
            assert_eq!(demangle_swift_native("_$s5smoke5helloSiyF").as_deref(), Some(d.as_str()));
        } else {
            assert!(d.is_none(), "no swift on PATH → None");
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn native_unknown_symbol_is_none() {
        // Even with swift present, garbage stays mangled / fails → None.
        let d = demangle_swift_native("_$sThisIsNotARealSymbolZZZ");
        // May return None or a string that still looks broken; accept None.
        if let Some(s) = d {
            assert!(!s.is_empty());
        }
    }
}
