//! Phase 6: Swift dialect emit + demangle prototypes.

use arm_decompiler::{
    demangle_swift, decompile_macho_symbol, is_swift_mangled, parse_swift_symbol,
    DecompilerOptions,
};
use std::path::PathBuf;

fn libsmoke() -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/swift_fixtures/libsmoke.dylib"),
    )
    .expect("libsmoke.dylib")
}

#[test]
fn demangle_matches_swift_demangle_tool() {
    let mangled = "_$s5smoke5helloSiyF";
    assert!(is_swift_mangled(mangled));
    let d = demangle_swift(mangled).expect("demangle");
    assert!(d.starts_with("smoke.hello("), "{d}");
    assert!(d.contains("Swift.Int") || d.contains("Int"), "{d}");
}

#[test]
fn decompile_emits_swift_func() {
    let f = decompile_macho_symbol(
        &libsmoke(),
        "_$s5smoke5helloSiyF",
        &DecompilerOptions::default(),
    )
    .expect("decompile");
    assert!(
        f.source.contains("func smoke.hello("),
        "missing Swift func:\n{}",
        f.source
    );
    assert!(f.source.contains("-> Int"), "{}", f.source);
    assert!(f.frame.swift_dialect);
    assert!(f.frame.swift_proto.is_some());
}

#[test]
fn method_prototype_uses_short_name() {
    let sym = parse_swift_symbol("_$s5smoke7CounterV4bumpSiyF").expect("parse");
    assert!(sym.is_method);
    let f = decompile_macho_symbol(
        &libsmoke(),
        "_$s5smoke7CounterV4bumpSiyF",
        &DecompilerOptions::default(),
    )
    .expect("decompile");
    assert!(
        f.source.contains("func bump("),
        "expected method proto:\n{}",
        f.source
    );
    assert!(
        !f.source.contains("swift_retain"),
        "retain noise:\n{}",
        f.source
    );
}
