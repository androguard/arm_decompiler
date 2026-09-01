//! P4-4: token stream carries block start VAs.

use arm_decompiler::{decompile_macho_symbol, TokenKind, DecompilerOptions};
use std::path::PathBuf;

#[test]
fn add1_tokens_include_return_with_vaddr() {
    let bytes = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/decompiler_fixtures/decompiler_fixtures"),
    )
    .unwrap();
    let f = decompile_macho_symbol(&bytes, "_add1", &DecompilerOptions::default()).unwrap();
    assert!(
        f.tokens.iter().any(|t| t.kind == TokenKind::Keyword && t.text == "int"),
        "missing int kw"
    );
    let ret = f
        .tokens
        .iter()
        .find(|t| t.kind == TokenKind::Keyword && t.text == "return")
        .expect("return token");
    assert!(ret.vaddr.is_some(), "return should map to a VA: {ret:?}");
    assert!(ret.start < ret.end);
}
