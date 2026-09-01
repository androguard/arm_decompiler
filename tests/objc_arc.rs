use apple_metadata::SymbolTable;
use arm_decompiler::{decompile_macho_symbol, DecompilationMode, DecompilerOptions};
use macho_core::MachoFile;
use std::path::PathBuf;

fn fixture() -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/decompiler_fixtures/decompiler_fixtures");
    std::fs::read(p).expect("fixture binary")
}

#[test]
fn stubs_name_objc_store_strong() {
    let data = fixture();
    let file = MachoFile::parse(&data).unwrap();
    let syms = SymbolTable::from_macho(&file).unwrap();
    assert!(
        syms.iter().any(|(_, n)| n.contains("storeStrong")),
        "expected __stubs entry for _objc_storeStrong"
    );
}

#[test]
fn smoke_call_recovers_self_receiver() {
    let data = fixture();
    let opts = DecompilerOptions {
        mode: DecompilationMode::Restructure,
        ..Default::default()
    };
    let r = decompile_macho_symbol(&data, "_cd_smoke_call", &opts).unwrap();
    assert!(
        r.source.contains("[self hello:"),
        "expected [self hello:…]:\n{}",
        r.source
    );
}

#[test]
fn smoke_sum_recovers_self_receiver() {
    let data = fixture();
    let opts = DecompilerOptions {
        mode: DecompilationMode::Restructure,
        ..Default::default()
    };
    let r = decompile_macho_symbol(&data, "_cd_smoke_sum", &opts).unwrap();
    assert!(
        r.source.contains("[self sum:") && r.source.contains("with:"),
        "expected [self sum:… with:…]:\n{}",
        r.source
    );
}
