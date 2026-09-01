//! Decompilation mode selection (P0-7): Restructure / Simple / Fallback.

use alloc::string::String;
use alloc::vec::Vec;

use crate::cfg::{BlockEnd, FunctionCfg};
use crate::emit::EmitOptions;
use crate::ir::Stmt;
use crate::locals::FrameRecovery;
use crate::region::{build_regions, Region};

/// Decompilation strategy (jadx / dex-decompiler inspired).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DecompilationMode {
    /// Structured control flow (if/else, loops). Default. Auto-downgrades to Simple
    /// when restructuring leaves only goto soup on a branching CFG.
    #[default]
    Restructure,
    /// Emit CFG blocks in order with labels and if/goto edges.
    Simple,
    /// Same CFG dump as Simple, with an explicit fallback banner.
    Fallback,
}

/// Planned region tree + emit flags for a mode.
pub struct EmitPlan {
    pub region: Region,
    pub emit: EmitOptions,
    /// Mode actually used (may differ from requested after auto-downgrade).
    pub mode: DecompilationMode,
}

/// Build the initial emit plan for `mode` (before quality downgrade).
pub fn plan_for_mode(
    mode: DecompilationMode,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    show_labels: bool,
) -> EmitPlan {
    match mode {
        DecompilationMode::Restructure => EmitPlan {
            region: build_regions(cfg, block_stmts),
            emit: EmitOptions {
                show_labels,
                structured: true,
                ..EmitOptions::default()
            },
            mode: DecompilationMode::Restructure,
        },
        DecompilationMode::Simple => EmitPlan {
            region: sequential_blocks(cfg),
            emit: EmitOptions {
                show_labels: true,
                structured: false,
                ..EmitOptions::default()
            },
            mode: DecompilationMode::Simple,
        },
        DecompilationMode::Fallback => EmitPlan {
            region: sequential_blocks(cfg),
            emit: EmitOptions {
                show_labels: true,
                structured: false,
                ..EmitOptions::default()
            },
            mode: DecompilationMode::Fallback,
        },
    }
}

fn sequential_blocks(cfg: &FunctionCfg) -> Region {
    Region::Seq(
        (0..cfg.blocks.len())
            .map(Region::Block)
            .collect::<Vec<_>>(),
    )
}

/// True when Restructure produced label/goto soup instead of structured CF.
pub fn restructure_needs_downgrade(source: &str, cfg: &FunctionCfg) -> bool {
    let has_cond = cfg
        .blocks
        .iter()
        .any(|b| matches!(b.end, BlockEnd::Conditional { .. }));
    if !has_cond {
        return false;
    }
    let structured = source.contains("if (")
        || source.contains("while (")
        || source.contains("for (")
        || source.contains("switch (")
        || source.contains("do {");
    if structured {
        return false;
    }
    source.contains("goto ")
}

/// Banner comment for Fallback mode (linear CFG dump).
pub fn fallback_banner() -> String {
    String::from("// mode: fallback (CFG blocks + goto)\n")
}

/// Apply Restructure→Simple downgrade when needed; prefix Fallback banner.
pub fn finalize_source(
    requested: DecompilationMode,
    mut plan: EmitPlan,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    name: &str,
    frame: &FrameRecovery,
    show_labels: bool,
) -> (String, DecompilationMode) {
    let demangled = crate::swift::try_demangle_symbol(name);
    let demangled_ref = demangled.as_deref();
    let mut source = crate::emit::emit_function_ex(
        name,
        cfg,
        block_stmts,
        &plan.region,
        frame,
        &plan.emit,
        demangled_ref,
    );
    let mut used = plan.mode;

    if requested == DecompilationMode::Restructure && restructure_needs_downgrade(&source, cfg)
    {
        plan = plan_for_mode(DecompilationMode::Simple, cfg, block_stmts, show_labels);
        source = crate::emit::emit_function_ex(
            name,
            cfg,
            block_stmts,
            &plan.region,
            frame,
            &plan.emit,
            demangled_ref,
        );
        used = DecompilationMode::Simple;
    }

    if used == DecompilationMode::Fallback {
        let mut s = fallback_banner();
        s.push_str(&source);
        source = s;
    }

    (source, used)
}

/// Parse CLI / API mode strings (`restructure`|`simple`|`fallback`|`auto`).
pub fn parse_mode(s: &str) -> Option<DecompilationMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "restructure" | "auto" | "structured" => Some(DecompilationMode::Restructure),
        "simple" => Some(DecompilationMode::Simple),
        "fallback" | "linear" => Some(DecompilationMode::Fallback),
        _ => None,
    }
}

/// Human-readable mode name for JSON / headers.
pub fn mode_name(mode: DecompilationMode) -> &'static str {
    match mode {
        DecompilationMode::Restructure => "restructure",
        DecompilationMode::Simple => "simple",
        DecompilationMode::Fallback => "fallback",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_aliases() {
        assert_eq!(parse_mode("auto"), Some(DecompilationMode::Restructure));
        assert_eq!(parse_mode("SIMPLE"), Some(DecompilationMode::Simple));
        assert_eq!(parse_mode("linear"), Some(DecompilationMode::Fallback));
        assert!(parse_mode("wat").is_none());
    }

    #[test]
    fn downgrade_when_gotos_without_if() {
        let mut cfg = FunctionCfg {
            blocks: Vec::new(),
            block_by_start: Default::default(),
            loop_headers: Default::default(),
            entry: 0,
        };
        cfg.blocks.push(crate::cfg::CfgBlock {
            start_vaddr: 0,
            end_vaddr: 4,
            end: BlockEnd::Conditional {
                condition: String::from("x > 0"),
                branch_target: 1,
                fall_through: 2,
            },
            insn_indices: Vec::new(),
        });
        assert!(restructure_needs_downgrade(
            "lab_0:\n    goto lab_1;\n",
            &cfg
        ));
        assert!(!restructure_needs_downgrade(
            "if (x > 0) {\n    return 1;\n}\n",
            &cfg
        ));
    }
}
