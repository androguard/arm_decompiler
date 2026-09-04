//! Top-level decompiler API (dex-decompiler `Decompiler` analogue).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use apple_metadata::{ObjcMetadata, ObjcRefs, SymbolTable};
use arm_disassembler::{Decoder, Instruction, SymbolResolver};
use macho_core::MachoFile;

use crate::blocks::rewrite_block_invokes;
use crate::bounds::{read_function_bytes, resolve_function_bounds, FunctionBounds};
use crate::cfg::FunctionCfg;
use crate::dwarf::{
    detect_unwind_hints, dwarf_param_renames, find_subprogram, load_dwarf_subprograms, UnwindHints,
};
use crate::error::{Error, Result};
use crate::ir::Stmt;
use crate::lift::lift_block;
use crate::locals::{recover_frame, FrameRecovery};
use crate::modes::{finalize_source, plan_for_mode};
use crate::objc::{
    fold_objc_self_receiver, lower_objc_store_strong, rename_objc_self, rewrite_msg_sends,
    strip_objc_runtime_noise, SelResolveCtx,
};
use crate::pass::{Pass, PassRunner, RedundantArgLoadPass};
use crate::ssa::{
    collapse_ssa_versions, construct_ssa, dead_ssa_version_assigns, fold_call_result_refs,
    inline_ssa_reg_defs, ssa_copy_prop, strip_phis,
};
use crate::jumptable::{
    format_jump_table_switch, recover_jump_tables, strip_jump_table_dispatch_noise,
};
use crate::objc_proto::{find_objc_method, format_objc_method_prototype};
use crate::rename::RenameMap;
use crate::swift::{apply_swift_prototype, is_swift_mangled, try_demangle_symbol};
use crate::swift_fold::fold_swift_param_spills;
use crate::swift_meta::{rewrite_swift_fields, rewrite_swift_string_imms, SwiftMetadata};
use crate::swift_runtime::{
    rewrite_swift_call_names, rewrite_swift_self, strip_swift_overflow_noise,
    strip_swift_runtime_noise,
};
use crate::tokens::tokenize_with_addrs;
use crate::types::{
    infer_name_types, infer_return_type, infer_types_from_conditions, mark_address_temps, Ty,
};
use crate::value_flow::analyze_flows_default;

pub use crate::modes::DecompilationMode;

#[derive(Clone, Debug)]
pub struct DecompilerOptions {
    pub mode: DecompilationMode,
    pub show_asm_comments: bool,
    pub show_labels: bool,
    /// Max instructions to decode for a function (safety).
    pub max_insns: usize,
    /// Optional user renames (P4-3); applied after emit.
    pub rename_map: Option<RenameMap>,
    /// Optional VA → selector map for DSC / shared methnames (P5-3).
    /// Lines applied onto `__objc_selrefs` placeholders; also consulted at msgSend rewrite.
    pub selector_map: Vec<(u64, String)>,
}

impl Default for DecompilerOptions {
    fn default() -> Self {
        Self {
            mode: DecompilationMode::Restructure,
            show_asm_comments: false,
            show_labels: false,
            max_insns: 10_000,
            rename_map: None,
            selector_map: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionDecompile {
    pub name: String,
    pub start_vaddr: u64,
    pub end_vaddr: u64,
    pub bounds: FunctionBounds,
    pub cfg: FunctionCfg,
    pub block_stmts: Vec<Vec<Stmt>>,
    pub frame: FrameRecovery,
    pub source: String,
    /// Mode that produced `source` (after optional auto-downgrade).
    pub mode_used: DecompilationMode,
    /// DWARF / compact-unwind section presence (P4-2).
    pub unwind_hints: UnwindHints,
    /// Source tokens with optional VA (P4-4).
    pub tokens: Vec<crate::tokens::SourceToken>,
    /// Swift demangled name when the symbol is mangled (P3-6).
    pub demangled_name: Option<String>,
    /// Value-flow findings (M6); empty when no source→sink path matched.
    pub findings: Vec<crate::value_flow::FlowFinding>,
    /// Recovered jump tables (P2-4).
    pub jump_tables: Vec<crate::jumptable::JumpTable>,
}

struct SymRes<'a>(&'a SymbolTable);
impl SymbolResolver for SymRes<'_> {
    fn resolve(&self, vaddr: u64) -> Option<&str> {
        self.0.get_symbol_str_at_vaddr(vaddr)
    }
}

/// Decompile a raw code slice at `base_vaddr` (caller supplies exact bytes).
pub fn decompile_text_slice(
    code: &[u8],
    base_vaddr: u64,
    name: &str,
    symbols: &SymbolTable,
    opts: &DecompilerOptions,
) -> Result<FunctionDecompile> {
    let end_vaddr = base_vaddr.saturating_add(code.len() as u64);
    let bounds = FunctionBounds {
        start: base_vaddr,
        end: end_vaddr,
    };
    let insns = decode_insns(code, base_vaddr, opts.max_insns);
    if insns.is_empty() {
        return Err(Error::EmptyFunction);
    }
    decompile_insns(&insns, name, symbols, opts, bounds, None, None)
}

/// Decompile an ELF function by symbol name using caller-supplied image bytes + symbol table.
///
/// Prefer resolving bounds via `elf_core` in the host; this helper wraps [`decompile_text_slice`].
pub fn decompile_elf_symbol(
    code: &[u8],
    base_vaddr: u64,
    symbol: &str,
    symbols: &SymbolTable,
    opts: &DecompilerOptions,
) -> Result<FunctionDecompile> {
    decompile_text_slice(code, base_vaddr, symbol, symbols, opts)
}

/// Decompile the function whose symbol is `name` (or demangled / ObjC selector form).
pub fn decompile_macho_symbol(
    macho_bytes: &[u8],
    symbol: &str,
    opts: &DecompilerOptions,
) -> Result<FunctionDecompile> {
    let file = MachoFile::parse(macho_bytes)?;
    let symbols = SymbolTable::from_macho(&file)?;
    let mut objc_refs = ObjcRefs::parse(&file).ok();
    if let Some(refs) = objc_refs.as_mut() {
        if !opts.selector_map.is_empty() {
            apple_metadata::apply_selector_map(refs, &opts.selector_map);
        }
    }
    let objc_meta = ObjcMetadata::parse(&file).ok();
    let swift_meta = SwiftMetadata::parse(&file);
    let (vaddr, _) = find_symbol(&symbols, symbol)
        .ok_or_else(|| Error::SymbolNotFound(symbol.to_string()))?;
    let max_bytes = opts.max_insns.saturating_mul(4);
    let bounds = resolve_function_bounds(&file, &symbols, vaddr, max_bytes)?;
    let code = read_function_bytes(&file, bounds)?;
    let end_vaddr = bounds.end;
    let insns = decode_insns(&code, bounds.start, opts.max_insns);
    if insns.is_empty() {
        return Err(Error::EmptyFunction);
    }
    let mut result = decompile_insns(
        &insns,
        symbol,
        &symbols,
        opts,
        bounds,
        objc_refs.as_ref(),
        Some(&swift_meta),
    )?;
    result.end_vaddr = end_vaddr;

    // P2-4: recover jump tables from the instruction stream.
    if let Ok(jts) = recover_jump_tables(&file, &insns) {
        if !jts.is_empty() {
            strip_jump_table_dispatch_noise(&mut result.block_stmts, &jts);
            let disc = result
                .frame
                .params
                .first()
                .cloned()
                .unwrap_or_else(|| format!("x{}", jts[0].index_reg));
            let plan = plan_for_mode(
                opts.mode,
                &result.cfg,
                &result.block_stmts,
                opts.show_labels,
            );
            let (mut source, mode_used) = finalize_source(
                opts.mode,
                plan,
                &result.cfg,
                &result.block_stmts,
                symbol,
                &result.frame,
                opts.show_labels,
            );
            let mut annot = String::from("/* recovered jump table(s) */\n");
            for jt in &jts {
                annot.push_str("/* ");
                annot.push_str(&jt.summary);
                annot.push_str(" */\n");
                annot.push_str(&format_jump_table_switch(jt, &disc));
            }
            if let Some(brace) = source.find('{') {
                let (head, tail) = source.split_at(brace + 1);
                source = alloc::format!("{head}\n{annot}{tail}");
            } else {
                source = alloc::format!("{annot}{source}");
            }
            if let Some(map) = &opts.rename_map {
                source = map.apply(&source, symbol);
            }
            result.source = source;
            result.mode_used = mode_used;
            result.jump_tables = jts;
        }
    }

    if let Some(meta) = objc_meta.as_ref() {
        if let Some((is_class, method, _class)) = find_objc_method(meta, symbol, vaddr) {
            // ObjC methods: ensure param_1 → self even without msgSend in the body.
            if result.frame.params.first().map(String::as_str) == Some("param_1") {
                result.frame.params[0] = String::from("self");
                crate::objc::rename_names_in_blocks(&mut result.block_stmts, "param_1", "self");
            }
            result.frame.objc_method_proto = Some(format_objc_method_prototype(
                is_class,
                &method.name,
                &method.types,
                &result.frame.params,
            ));
            // Re-emit with ObjC prototype (same mode plan / auto-downgrade).
            let plan = plan_for_mode(
                opts.mode,
                &result.cfg,
                &result.block_stmts,
                opts.show_labels,
            );
            let (mut source, mode_used) = finalize_source(
                opts.mode,
                plan,
                &result.cfg,
                &result.block_stmts,
                symbol,
                &result.frame,
                opts.show_labels,
            );
            if let Some(map) = &opts.rename_map {
                source = map.apply(&source, symbol);
            }
            result.source = source;
            result.mode_used = mode_used;
        }
    }

    // P4-2: DWARF formal names + unwind section hints.
    result.unwind_hints = detect_unwind_hints(&file);
    let dwarf_subs = load_dwarf_subprograms(&file);
    if let Some(sp) = find_subprogram(&dwarf_subs, vaddr, symbol) {
        apply_dwarf_names(&mut result, sp, symbol, opts);
    }

    result.tokens = tokenize_with_addrs(&result.source, &result.cfg, &result.block_stmts);
    result.demangled_name = try_demangle_symbol(symbol);
    Ok(result)
}

fn apply_dwarf_names(
    result: &mut FunctionDecompile,
    sp: &crate::dwarf::DwarfSubprogram,
    symbol: &str,
    opts: &DecompilerOptions,
) {
    let pairs = dwarf_param_renames(&result.frame.params, &sp.params);
    if pairs.is_empty() {
        return;
    }
    let mut map = crate::rename::RenameMap::new();
    for (old, new) in &pairs {
        for p in &mut result.frame.params {
            if p == old {
                *p = new.clone();
            }
        }
        if let Some(ty) = result.frame.local_types.remove(old) {
            result.frame.local_types.insert(new.clone(), ty);
        }
        crate::objc::rename_names_in_blocks(&mut result.block_stmts, old, new);
        map.variable.insert(old.clone(), new.clone());
    }
    result.source = map.apply(&result.source, symbol);
    if let Some(user) = &opts.rename_map {
        result.source = user.apply(&result.source, symbol);
    }
}

/// Decompile from already-decoded instructions.
pub fn decompile_function(
    insns: &[Instruction],
    name: &str,
    symbols: &SymbolTable,
    opts: &DecompilerOptions,
) -> Result<FunctionDecompile> {
    if insns.is_empty() {
        return Err(Error::EmptyFunction);
    }
    let start = insns[0].vaddr;
    let last = insns.last().unwrap();
    let end = last.vaddr + last.len as u64;
    decompile_insns(
        insns,
        name,
        symbols,
        opts,
        FunctionBounds { start, end },
        None,
        None,
    )
}

fn decompile_insns(
    insns: &[Instruction],
    name: &str,
    symbols: &SymbolTable,
    opts: &DecompilerOptions,
    bounds: FunctionBounds,
    objc_refs: Option<&ObjcRefs>,
    swift_meta: Option<&SwiftMetadata>,
) -> Result<FunctionDecompile> {
    let start_vaddr = bounds.start;
    let mut cfg = FunctionCfg::build(insns);
    let resolver = SymRes(symbols);

    let mut block_stmts = Vec::with_capacity(cfg.blocks.len());
    let runner = PassRunner::default_pipeline();
    for b in &cfg.blocks {
        let slice: Vec<Instruction> = b
            .insn_indices
            .iter()
            .filter_map(|&i| insns.get(i).copied())
            .collect();
        let mut stmts = lift_block(&slice, &resolver);
        if !opts.show_asm_comments {
            for s in &mut stmts {
                strip_comment(s);
            }
        }
        stmts = runner.run(stmts);
        block_stmts.push(stmts);
    }

    // M2: SSA on register defs (before frame → local recovery).
    construct_ssa(&cfg, &mut block_stmts);
    ssa_copy_prop(&mut block_stmts);

    let frame = recover_frame(&mut cfg, &mut block_stmts);
    // Light DCE again after local rewrite (temps that only fed stack).
    let runner2 = PassRunner::default_pipeline();
    for stmts in &mut block_stmts {
        *stmts = runner2.run(core::mem::take(stmts));
    }
    strip_phis(&mut block_stmts);
    inline_ssa_reg_defs(&mut block_stmts);
    let arg_load = RedundantArgLoadPass;
    for stmts in &mut block_stmts {
        *stmts = arg_load.run(core::mem::take(stmts));
    }
    dead_ssa_version_assigns(&mut block_stmts);
    fold_call_result_refs(&mut block_stmts);
    collapse_ssa_versions(&mut block_stmts);
    // M4: objc_storeStrong → local assign, then drop leftover ARC, then [recv sel:…]
    let mut frame = frame;
    lower_objc_store_strong(&mut block_stmts, &frame);
    strip_objc_runtime_noise(&mut block_stmts);
    rewrite_msg_sends(
        &mut block_stmts,
        SelResolveCtx {
            refs: objc_refs,
            symbols: Some(symbols),
            sel_map: if opts.selector_map.is_empty() {
                None
            } else {
                Some(opts.selector_map.as_slice())
            },
        },
    );
    rewrite_block_invokes(&mut block_stmts);
    rename_objc_self(&mut block_stmts, &mut frame);
    fold_objc_self_receiver(&mut block_stmts);

    // Phase 6 / 6.1 / Ghidra align: Swift runtime / overflow / calls / metadata / self / folds.
    strip_swift_runtime_noise(&mut block_stmts);
    strip_swift_overflow_noise(&mut block_stmts);
    rewrite_swift_call_names(&mut block_stmts);
    if let Some(meta) = swift_meta {
        rewrite_swift_string_imms(&mut block_stmts, meta);
    }

    // M5 / P1-6 / P4-1: coarse type lattice for locals / params / returns.
    let mut types = infer_name_types(&block_stmts);
    mark_address_temps(&block_stmts, &mut types);
    let conds: Vec<String> = cfg
        .blocks
        .iter()
        .filter_map(|b| match &b.end {
            crate::cfg::BlockEnd::Conditional { condition, .. } => Some(condition.clone()),
            _ => None,
        })
        .collect();
    infer_types_from_conditions(conds, &mut types);
    if frame.params.iter().any(|p| p == "self") {
        types.insert(String::from("self"), Ty::ObjCId);
    }
    frame.return_ty = if frame.returns_value {
        infer_return_type(&block_stmts, &types)
    } else {
        Ty::Undefined
    };
    frame.local_types = types;

    if is_swift_mangled(name) {
        if let Some(sym) = apply_swift_prototype(&mut frame, name) {
            frame.swift_dialect = true;
            fold_swift_param_spills(&mut block_stmts, &frame.params);
            let mut self_aliases = Vec::new();
            if sym.is_method || frame.params.iter().any(|p| p == "self") {
                crate::objc::rename_names_in_blocks(&mut block_stmts, "param_1", "self");
                rewrite_swift_self(&mut block_stmts, true);
                // Locals that hold self (local = self) become field-rewrite aliases.
                for stmts in &block_stmts {
                    for s in stmts {
                        if let Stmt::Assign {
                            dst: crate::ir::Place::Name(n),
                            rhs: crate::ir::Expr::Name(r),
                            ..
                        } = s
                        {
                            if r == "self" {
                                self_aliases.push(n.clone());
                            }
                        }
                    }
                }
                frame
                    .local_types
                    .insert(String::from("self"), Ty::ObjCId);
            }
            if let Some(meta) = swift_meta {
                rewrite_swift_fields(&mut block_stmts, meta, &self_aliases);
            }
            if let Some(sym2) = crate::swift::parse_swift_symbol(name) {
                frame.swift_proto = Some(crate::swift::format_swift_prototype(&sym2, &frame));
            }
        }
    }

    let findings = analyze_flows_default(&block_stmts);

    let plan = plan_for_mode(opts.mode, &cfg, &block_stmts, opts.show_labels);
    let (mut source, mode_used) = finalize_source(
        opts.mode,
        plan,
        &cfg,
        &block_stmts,
        name,
        &frame,
        opts.show_labels,
    );
    if let Some(map) = &opts.rename_map {
        source = map.apply(&source, name);
    }
    let tokens = tokenize_with_addrs(&source, &cfg, &block_stmts);
    let demangled_name = try_demangle_symbol(name);

    Ok(FunctionDecompile {
        name: name.to_string(),
        start_vaddr,
        end_vaddr: bounds.end,
        bounds,
        cfg,
        block_stmts,
        frame,
        source,
        mode_used,
        unwind_hints: UnwindHints::default(),
        tokens,
        demangled_name,
        findings,
        jump_tables: Vec::new(),
    })
}

fn strip_comment(s: &mut Stmt) {
    match s {
        Stmt::Assign { comment, .. }
        | Stmt::Store { comment, .. }
        | Stmt::Expr { comment, .. }
        | Stmt::Return { comment, .. } => *comment = None,
        _ => {}
    }
}

/// Decode every instruction in `code` (up to `max`), without stopping at the first `ret`.
///
/// Function extent is determined by the caller (`resolve_function_bounds`); early
/// returns and multiple epilogues must stay in the CFG.
fn decode_insns(code: &[u8], base: u64, max: usize) -> Vec<Instruction> {
    let mut dec = Decoder::new(code, base);
    let mut out = Vec::new();
    while dec.can_decode() && out.len() < max {
        out.push(dec.decode());
    }
    out
}

fn find_symbol<'a>(symbols: &'a SymbolTable, name: &str) -> Option<(u64, &'a str)> {
    let want = name.trim_start_matches('_');
    symbols.iter().find_map(|(va, n)| {
        if n == name || n.trim_start_matches('_') == want {
            Some((va, n))
        } else {
            None
        }
    })
}

/// Text-section function symbols suitable for batch decompile (sorted by address).
pub fn list_macho_functions(macho_bytes: &[u8]) -> Result<Vec<(u64, String)>> {
    let file = MachoFile::parse(macho_bytes)?;
    let symbols = SymbolTable::from_macho(&file)?;
    let text = file
        .find_section("__TEXT", "__text")?
        .ok_or(Error::NoCode)?;
    let text_end = text.addr.saturating_add(text.size);
    let mut out = Vec::new();
    for (va, name) in symbols.iter() {
        if va < text.addr || va >= text_end {
            continue;
        }
        if name == "__mh_execute_header" || name.starts_with("l_") || name.starts_with("ltmp") {
            continue;
        }
        // Skip pure data / abs; keep T/t-like names (anything in __text with a label).
        if name.starts_with('_') || name.starts_with("-[") || name.starts_with("+[") {
            out.push((va, name.to_string()));
        }
    }
    out.sort_by_key(|(va, _)| *va);
    out.dedup_by_key(|(va, _)| *va);
    Ok(out)
}

/// Decompile every listed text symbol; skips functions that fail individually.
pub fn decompile_macho_all(
    macho_bytes: &[u8],
    opts: &DecompilerOptions,
) -> Result<Vec<(String, core::result::Result<FunctionDecompile, Error>)>> {
    let funcs = list_macho_functions(macho_bytes)?;
    let mut out = Vec::with_capacity(funcs.len());
    for (_va, name) in funcs {
        let r = decompile_macho_symbol(macho_bytes, &name, opts);
        out.push((name, r));
    }
    Ok(out)
}
