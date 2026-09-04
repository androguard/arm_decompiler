//! ARM64 → C/ObjC-like decompiler (Mach-O today; ELF/Android later).
//!
//! Pipeline mirrors [dex-decompiler](https://github.com/androguard/dex-decompiler):
//!
//! ```text
//! Mach-O / IPA  →  decode ARM64  →  CFG  →  IR  →  PassRunner  →  Regions  →  source
//! ```

#![no_std]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod bounds;
mod blocks;
mod cfg;
mod decompile;
mod dwarf;
mod emit;
mod error;
mod flirt;
mod ir;
mod json;
mod jumptable;
mod lift;
mod locals;
mod modes;
mod objc;
mod objc_proto;
mod pac;
mod pass;
mod region;
mod rename;
mod ssa;
mod swift;
mod swift_fold;
mod swift_meta;
mod swift_native;
mod swift_runtime;
mod tokens;
mod types;
mod value_flow;
mod xrefs;

pub use blocks::{
    is_block_invoke_symbol, rewrite_block_invokes, signature_hint_from_descriptor_symbol,
};
pub use bounds::{
    function_start_vaddrs, read_function_bytes, resolve_function_bounds, FunctionBounds,
};
pub use cfg::{fold_cmp_branch, BlockEnd, BlockId, CfgBlock, FunctionCfg};
pub use decompile::{
    decompile_elf_symbol, decompile_function, decompile_macho_all, decompile_macho_symbol,
    decompile_text_slice, list_macho_functions, DecompilationMode, DecompilerOptions,
    FunctionDecompile,
};
pub use dwarf::{
    detect_unwind_hints, dwarf_param_renames, find_subprogram, load_dwarf_subprograms,
    DwarfSubprogram, UnwindHints,
};
pub use emit::emit_function;
pub use error::{Error, Result};
pub use flirt::flirt_match_names;
pub use ir::{BinOp, Expr, Place, Stmt, VarId};
pub use json::{function_to_json, symbol_to_filename};
pub use jumptable::{
    format_jump_table_switch, recover_jump_tables, strip_jump_table_dispatch_noise, JumpTable,
};
pub use modes::{mode_name, parse_mode};
pub use pac::{
    is_pac_call, is_pac_hint, is_pac_indirect_br, is_pac_return, strip_ptrauth,
};
pub use pass::{
    DeadAssignPass, ExprSimplifyPass, LocalCopyPropPass, Pass, PassRunner, RedundantMovPass,
};
pub use region::{build_regions, Region};
pub use rename::{apply_replacements, parse_selector_map_text, rename_map_from_pairs, RenameMap};
pub use ssa::{
    collapse_ssa_versions, construct_ssa, phi_canonical_map, ssa_copy_prop, strip_phis,
};
pub use swift::{
    apply_swift_prototype, demangle_swift, format_swift_prototype, is_swift_mangled,
    parse_swift_symbol, try_demangle_symbol, SwiftKind, SwiftSymbol,
};
pub use swift_fold::fold_swift_param_spills;
pub use swift_meta::{rewrite_swift_fields, rewrite_swift_string_imms, SwiftMetadata};
pub use swift_native::{
    demangle_signatures_disagree, demangle_swift_native, prefer_demangle,
    prototype_from_native_demangle,
};
pub use swift_runtime::{
    rewrite_swift_call_names, rewrite_swift_self, strip_swift_overflow_noise,
    strip_swift_runtime_noise,
};
pub use tokens::{
    apply_addr_map, build_addr_map, tokenize, tokenize_with_addrs, tokens_to_json, AddrSpan,
    SourceToken, TokenKind,
};
pub use types::Ty;
pub use value_flow::{
    analyze_flows, analyze_flows_default, FlowFinding, FlowRules, TaintKind,
};
pub use xrefs::{
    build_macho_xrefs, call_graph, scan_code_xrefs, xref_kind_name, xref_summary, xrefs_from,
    xrefs_to, CallEdge, CallGraph, Xref, XrefIndex, XrefKind,
};
