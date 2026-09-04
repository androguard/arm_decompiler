//! P5-2: PAC / arm64e control-flow lifts without crashing or emitting raw soup.

use apple_metadata::SymbolTable;
use arm_decompiler::{
    decompile_text_slice, is_pac_hint, is_pac_return, strip_ptrauth, DecompilerOptions,
};
use arm_disassembler::{Decoder, Mnemonic};
use macho_core::MachoFile;

fn fixture_symbols() -> SymbolTable {
    let bytes = std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/decompiler_fixtures/decompiler_fixtures"),
    )
    .expect("fixture");
    let file = MachoFile::parse(&bytes).unwrap();
    SymbolTable::from_macho(&file).unwrap()
}

#[test]
fn classifies_pac_opcodes() {
    let mut dec = Decoder::new(&[0x3f, 0x23, 0x03, 0xd5], 0);
    assert_eq!(dec.decode().mnemonic, Mnemonic::Paciasp);
    assert!(is_pac_hint(Mnemonic::Paciasp));
    let mut dec = Decoder::new(&[0xbf, 0x23, 0x03, 0xd5], 0);
    assert_eq!(dec.decode().mnemonic, Mnemonic::Autiasp);
    assert!(is_pac_hint(Mnemonic::Autiasp));
    let mut dec = Decoder::new(&[0xff, 0x0b, 0x5f, 0xd6], 0);
    assert_eq!(dec.decode().mnemonic, Mnemonic::Retaa);
    assert!(is_pac_return(Mnemonic::Retaa));
}

#[test]
fn decompile_pac_epilogue_is_clean() {
    // paciasp ; mov x0, #1 ; autiasp ; retaa
    let code: &[u8] = &[
        0x3f, 0x23, 0x03, 0xd5,
        0x20, 0x00, 0x80, 0xd2,
        0xbf, 0x23, 0x03, 0xd5,
        0xff, 0x0b, 0x5f, 0xd6,
    ];
    let f = decompile_text_slice(
        code,
        0x1000,
        "_pac_leaf",
        &fixture_symbols(),
        &DecompilerOptions::default(),
    )
    .unwrap();
    assert!(f.source.contains("return"), "{}", f.source);
    assert!(
        !f.source.contains("paciasp")
            && !f.source.contains("autiasp")
            && !f.source.contains("retaa")
            && !f.source.contains("hint"),
        "PAC ops should be elided:\n{}",
        f.source
    );
}

#[test]
fn strip_ptrauth_masks_high_bits() {
    assert_eq!(strip_ptrauth(0x8010_0000_0000_abcd), 0x0000_0000_0000_abcd);
}
