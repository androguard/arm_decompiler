//! P0-7: Restructure / Simple / Fallback mode smoke tests.

use arm_decompiler::{decompile_macho_symbol, mode_name, DecompilationMode, DecompilerOptions};
use std::path::PathBuf;

fn fixture_bytes() -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/decompiler_fixtures/decompiler_fixtures");
    std::fs::read(p).expect("fixture macho")
}

#[test]
fn restructure_emits_if_without_goto_soup() {
    let f = decompile_macho_symbol(
        &fixture_bytes(),
        "_if_else",
        &DecompilerOptions {
            mode: DecompilationMode::Restructure,
            ..DecompilerOptions::default()
        },
    )
    .unwrap();
    assert_eq!(f.mode_used, DecompilationMode::Restructure);
    assert!(f.source.contains("if ("), "{}", f.source);
    assert!(!f.source.contains("goto "), "{}", f.source);
}

#[test]
fn simple_emits_labels_and_conditional_gotos() {
    let f = decompile_macho_symbol(
        &fixture_bytes(),
        "_if_else",
        &DecompilerOptions {
            mode: DecompilationMode::Simple,
            show_labels: true,
            ..DecompilerOptions::default()
        },
    )
    .unwrap();
    assert_eq!(f.mode_used, DecompilationMode::Simple);
    assert!(f.source.contains("if ("), "missing if edge:\n{}", f.source);
    assert!(f.source.contains("goto "), "missing goto:\n{}", f.source);
    assert!(
        f.source.contains("L_") || f.source.contains("lab_"),
        "missing labels:\n{}",
        f.source
    );
}

#[test]
fn fallback_prefixes_banner() {
    let f = decompile_macho_symbol(
        &fixture_bytes(),
        "_add1",
        &DecompilerOptions {
            mode: DecompilationMode::Fallback,
            ..DecompilerOptions::default()
        },
    )
    .unwrap();
    assert_eq!(f.mode_used, DecompilationMode::Fallback);
    assert_eq!(mode_name(f.mode_used), "fallback");
    assert!(
        f.source.starts_with("// mode: fallback"),
        "{}",
        f.source.lines().next().unwrap_or("")
    );
}
