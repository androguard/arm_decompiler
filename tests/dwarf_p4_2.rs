//! P4-2: DWARF formal names from Mach-O `__DWARF` (object file fixture).

use arm_decompiler::{
    decompile_macho_symbol, detect_unwind_hints, load_dwarf_subprograms, DecompilerOptions,
};
use macho_core::MachoFile;
use std::path::PathBuf;

fn dwarf_o() -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/dwarf_names.o");
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn loads_subprograms_and_params() {
    let bytes = dwarf_o();
    let file = MachoFile::parse(&bytes).unwrap();
    let hints = detect_unwind_hints(&file);
    assert!(hints.has_dwarf_debug_info);
    assert!(hints.has_compact_unwind);
    let subs = load_dwarf_subprograms(&file);
    assert!(
        subs.iter().any(|s| s.name == "add1" && s.params == ["x"]),
        "{subs:?}"
    );
    assert!(
        subs.iter()
            .any(|s| s.name == "absdiff" && s.params == ["a", "b"]),
        "{subs:?}"
    );
}

#[test]
fn decompile_uses_dwarf_param_names() {
    let f = decompile_macho_symbol(&dwarf_o(), "_add1", &DecompilerOptions::default()).unwrap();
    assert!(f.unwind_hints.has_dwarf_debug_info);
    assert!(
        f.source.contains("(int x)") || f.source.contains(" x)"),
        "expected DWARF param x:\n{}",
        f.source
    );
    assert!(!f.source.contains("param_1"), "{}", f.source);
}
