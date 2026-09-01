//! Ghidra alignment backlog (G1–G6) integration tests.
//!
//! See `docs/SWIFT_GHIDRA_ALIGNMENT.md`.

use arm_decompiler::{
    demangle_swift, demangle_swift_native, decompile_macho_symbol, prefer_demangle,
    DecompilerOptions, SwiftMetadata,
};
use macho_core::MachoFile;
use std::path::PathBuf;

fn libsmoke() -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/swift_fixtures/libsmoke.dylib"),
    )
    .expect("libsmoke.dylib")
}

#[test]
fn g1_prefer_native_when_available() {
    let mangled = "_$s5smoke7CounterV4bumpSiyF";
    let d = demangle_swift(mangled).expect("demangle");
    // Must identify bump (native or fixed in-process) — not a truncated Counter().
    assert!(d.contains("bump"), "{d}");
}

#[test]
fn g2_add1_uses_param_not_x0() {
    let f = decompile_macho_symbol(
        &libsmoke(),
        "_$s5smoke4add1yS2iF",
        &DecompilerOptions::default(),
    )
    .expect("decompile");
    assert!(
        f.source.contains("param_1"),
        "missing param_1:\n{}",
        f.source
    );
    assert!(
        !f.source.contains("(x0 +"),
        "spill fold failed:\n{}",
        f.source
    );
}

#[test]
fn g3_bump_uses_self_value_field() {
    let bytes = libsmoke();
    let file = MachoFile::parse(&bytes).expect("macho");
    let meta = SwiftMetadata::parse(&file);
    assert_eq!(meta.primary_field(), Some("value"), "{:?}", meta.field_names);

    let f = decompile_macho_symbol(&bytes, "_$s5smoke7CounterV4bumpSiyF", &DecompilerOptions::default())
        .expect("decompile");
    assert!(
        f.source.contains("self.value"),
        "expected self.value:\n{}",
        f.source
    );
    assert!(
        !f.source.contains("*(self)"),
        "raw *(self) remains:\n{}",
        f.source
    );
}

#[test]
fn g4_add1_no_overflow_if_soup() {
    let f = decompile_macho_symbol(
        &libsmoke(),
        "_$s5smoke4add1yS2iF",
        &DecompilerOptions::default(),
    )
    .expect("decompile");
    assert!(!f.source.contains("cset "), "{}", f.source);
    assert!(
        !f.source.contains(">> 0"),
        "overflow cond remains:\n{}",
        f.source
    );
}

#[test]
fn g5_native_cache_stable() {
    let a = demangle_swift_native("_$s5smoke5helloSiyF");
    let b = demangle_swift_native("_$s5smoke5helloSiyF");
    assert_eq!(a, b);
}

#[test]
fn g6_prefer_handles_missing_native() {
    // When native is None, local is kept (PATH-less environments).
    let out = prefer_demangle(Some(String::from("smoke.hello() -> Int")), None);
    assert_eq!(out.as_deref(), Some("smoke.hello() -> Int"));
}
