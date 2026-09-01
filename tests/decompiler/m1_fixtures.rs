//! M1 fixture locks: function bounds + cmp→branch fold.
//!
//! Uses the dedicated `testdata/m1_bounds` binary (also covered loosely by the
//! suite `arithmetic` group in `decompiler_fixtures`).

use std::path::PathBuf;

use apple_metadata::SymbolTable;
use arm_disassembler::Decoder;
use arm_decompiler::{
    decompile_macho_symbol, resolve_function_bounds, DecompilerOptions, FunctionCfg,
};
use macho_core::MachoFile;

fn fixture_bytes() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/m1_bounds");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn bounds_add1_stops_before_absdiff() {
    let bytes = fixture_bytes();
    let file = MachoFile::parse(&bytes).unwrap();
    let symbols = SymbolTable::from_macho(&file).unwrap();
    let add1 = symbols
        .iter()
        .find(|(_, n)| *n == "_add1")
        .map(|(va, _)| va)
        .expect("_add1");
    let absdiff = symbols
        .iter()
        .find(|(_, n)| *n == "_absdiff")
        .map(|(va, _)| va)
        .expect("_absdiff");
    let bounds = resolve_function_bounds(&file, &symbols, add1, 40_000).unwrap();
    assert_eq!(bounds.start, add1);
    assert_eq!(
        bounds.end, absdiff,
        "add1 must end at next function (_absdiff)"
    );
}

#[test]
fn bounds_absdiff_includes_both_returns() {
    let bytes = fixture_bytes();
    let file = MachoFile::parse(&bytes).unwrap();
    let symbols = SymbolTable::from_macho(&file).unwrap();
    let absdiff = symbols
        .iter()
        .find(|(_, n)| *n == "_absdiff")
        .map(|(va, _)| va)
        .expect("_absdiff");
    let main = symbols
        .iter()
        .find(|(_, n)| *n == "_main")
        .map(|(va, _)| va)
        .expect("_main");
    let bounds = resolve_function_bounds(&file, &symbols, absdiff, 40_000).unwrap();
    assert_eq!(bounds.end, main);
    assert!(bounds.len_bytes() > 16);
}

#[test]
fn decompile_add1_does_not_spill_into_absdiff() {
    let r = decompile_macho_symbol(&fixture_bytes(), "_add1", &DecompilerOptions::default())
        .expect("decompile");
    assert_eq!(r.bounds.end - r.bounds.start, r.end_vaddr - r.start_vaddr);
    assert!(
        r.cfg.blocks.len() <= 4,
        "add1 spilled? blocks={}",
        r.cfg.blocks.len()
    );
}

#[test]
fn absdiff_cfg_folds_subs_branch_condition() {
    let bytes = fixture_bytes();
    let file = MachoFile::parse(&bytes).unwrap();
    let symbols = SymbolTable::from_macho(&file).unwrap();
    let absdiff = symbols
        .iter()
        .find(|(_, n)| *n == "_absdiff")
        .map(|(va, _)| va)
        .unwrap();
    let bounds = resolve_function_bounds(&file, &symbols, absdiff, 40_000).unwrap();
    let code = arm_decompiler::read_function_bytes(&file, bounds).unwrap();
    let mut dec = Decoder::new(&code, bounds.start);
    let mut insns = Vec::new();
    while dec.can_decode() {
        insns.push(dec.decode());
    }
    let cfg = FunctionCfg::build(&insns);
    let conds: Vec<_> = cfg
        .blocks
        .iter()
        .filter_map(|b| match &b.end {
            arm_decompiler::BlockEnd::Conditional { condition, .. } => Some(condition.clone()),
            _ => None,
        })
        .collect();
    assert!(
        conds
            .iter()
            .any(|c| c.contains(" <= ") || c.contains(" > ") || c.contains(" < ")),
        "expected folded relational condition, got {conds:?}"
    );
    assert!(
        !conds.iter().any(|c| c.starts_with("flags.")),
        "cmp/subs should be folded away from flags.*: {conds:?}"
    );
}

#[test]
fn main_preserves_call_results_across_x0_reload() {
    use arm_decompiler::{decompile_macho_symbol, DecompilerOptions};
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/decompiler_fixtures/decompiler_fixtures");
    let bytes = std::fs::read(&path).unwrap();
    let r = decompile_macho_symbol(&bytes, "_main", &DecompilerOptions::default()).unwrap();
    assert!(
        !r.source.contains("local_1c = local_28"),
        "absdiff result must not be confused with add1 arg reload:\n{}",
        r.source
    );
    assert!(
        !r.source.contains("x0 = local_28"),
        "redundant arg reload should be elided:\n{}",
        r.source
    );
    assert!(
        !r.source.contains("x0 = local_1c"),
        "dead reload before add fold should be elided:\n{}",
        r.source
    );
    assert!(
        r.source.contains("local_18 = (local_1c + x0)"),
        "expected add1 result referenced as x0:\n{}",
        r.source
    );
}
