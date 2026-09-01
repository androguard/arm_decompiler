//! P4-3: RenameMap applied through decompile pipeline.

use arm_decompiler::{decompile_macho_symbol, RenameMap, DecompilerOptions};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn fixture_bytes() -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/decompiler_fixtures/decompiler_fixtures");
    std::fs::read(p).expect("fixture macho")
}

#[test]
fn renames_loop_accumulator() {
    let mut map = RenameMap::new();
    map.variable_in.insert(
        "_while_sum".into(),
        BTreeMap::from([
            ("local_c".into(), "sum".into()),
            ("local_8".into(), "i".into()),
            ("param_1".into(), "n".into()),
        ]),
    );
    let f = decompile_macho_symbol(
        &fixture_bytes(),
        "_while_sum",
        &DecompilerOptions {
            rename_map: Some(map),
            ..DecompilerOptions::default()
        },
    )
    .unwrap();
    assert!(f.source.contains("(undefined8 n)") || f.source.contains("(int n)"), "{}", f.source);
    assert!(f.source.contains("int i"), "{}", f.source);
    assert!(f.source.contains("int sum"), "{}", f.source);
    assert!(f.source.contains("while (i <"), "{}", f.source);
    assert!(!f.source.contains("local_c"), "{}", f.source);
}
