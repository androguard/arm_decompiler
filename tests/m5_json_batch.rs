use arm_decompiler::{
    decompile_macho_all, decompile_macho_symbol, function_to_json, list_macho_functions,
    DecompilerOptions, Ty,
};
use std::path::PathBuf;

fn fixture() -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/decompiler_fixtures/decompiler_fixtures");
    std::fs::read(p).expect("fixture binary")
}

#[test]
fn json_export_has_cfg_and_source() {
    let r = decompile_macho_symbol(&fixture(), "_add1", &DecompilerOptions::default()).unwrap();
    let j = function_to_json(&r);
    assert!(j.contains("\"name\":\"_add1\""), "{j}");
    assert!(j.contains("\"cfg\""), "{j}");
    assert!(j.contains("\"source\""), "{j}");
    assert!(j.contains("\\n"), "{j}");
}

#[test]
fn objc_self_typed_as_id() {
    let r =
        decompile_macho_symbol(&fixture(), "_cd_smoke_call", &DecompilerOptions::default()).unwrap();
    assert_eq!(r.frame.local_types.get("self"), Some(&Ty::ObjCId));
    assert!(
        r.source.contains("id self") || r.source.contains("(id self)"),
        "expected id self in prototype:\n{}",
        r.source
    );
}

#[test]
fn batch_lists_and_decompiles_fixture_symbols() {
    let bytes = fixture();
    let listed = list_macho_functions(&bytes).unwrap();
    assert!(listed.iter().any(|(_, n)| n == "_add1"));
    assert!(listed.iter().any(|(_, n)| n == "_cd_smoke_call"));
    let results = decompile_macho_all(&bytes, &DecompilerOptions::default()).unwrap();
    let ok = results.iter().filter(|(_, r)| r.is_ok()).count();
    assert!(ok >= 10, "expected many successes, got {ok}/{}", results.len());
}
