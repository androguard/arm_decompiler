//! Emit C/ObjC-like source from regions + per-block IR (Ghidra-shaped).

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::cfg::{BlockEnd, FunctionCfg};
use crate::ir::Stmt;
use crate::locals::{format_prototype, FrameRecovery};
use crate::region::Region;

pub struct EmitOptions {
    pub indent: String,
    pub show_labels: bool,
    /// Suppress `goto` to the natural successor after structured if/loop.
    pub structured: bool,
}

impl Default for EmitOptions {
    fn default() -> Self {
        Self {
            indent: String::from("    "),
            show_labels: false,
            structured: true,
        }
    }
}

/// `block_stmts[block_id]` = IR for that block (without CF terminators).
pub fn emit_function(
    name: &str,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    region: &Region,
    frame: &FrameRecovery,
    opts: &EmitOptions,
) -> String {
    emit_function_ex(name, cfg, block_stmts, region, frame, opts, None)
}

/// Like [`emit_function`], with an optional Swift demangled display name.
pub fn emit_function_ex(
    name: &str,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    region: &Region,
    frame: &FrameRecovery,
    opts: &EmitOptions,
    demangled: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str("// decompiled with arm_decompiler\n");
    if let Some(d) = demangled {
        if frame.swift_proto.is_none() {
            out.push_str(&format!("// Swift: {d}\n"));
        }
    }
    out.push_str(&format_prototype(name, frame));
    out.push_str(" {\n");

    let pad = &opts.indent;
    for local in &frame.locals {
        let ty = frame
            .local_types
            .get(local)
            .copied()
            .unwrap_or(crate::types::Ty::Undefined);
        if frame.swift_dialect {
            out.push_str(&format!("{pad}var {local}: {};\n", ty.as_swift_str()));
        } else {
            out.push_str(&format!("{pad}{} {local};\n", ty.as_c_str()));
        }
    }
    if !frame.locals.is_empty() {
        out.push('\n');
    }

    let mut emitted = BTreeSet::new();
    emit_region(
        &mut out,
        cfg,
        block_stmts,
        region,
        opts,
        1,
        &mut emitted,
        None,
    );
    out.push_str("}\n");
    out
}

fn emit_region(
    out: &mut String,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    region: &Region,
    opts: &EmitOptions,
    depth: usize,
    emitted: &mut BTreeSet<usize>,
    join_suppress: Option<usize>,
) {
    let pad = opts.indent.repeat(depth);
    match region {
        Region::Block(id) => {
            emit_block(
                out,
                cfg,
                block_stmts,
                *id,
                opts,
                depth,
                emitted,
                join_suppress,
            );
        }
        Region::Seq(parts) => {
            emit_seq(
                out,
                cfg,
                block_stmts,
                parts,
                opts,
                depth,
                emitted,
                join_suppress,
            );
        }
        Region::If {
            condition,
            then_branch,
            else_branch,
        } => {
            // Collect else-if cascade once; emit as `switch` when arms are `expr == imm`.
            let cascade = collect_if_cascade(condition, then_branch, else_branch, block_stmts);
            if let Some((disc, cases, default)) =
                try_switch_from_cascade(&cascade, block_stmts)
            {
                emit_switch(
                    out,
                    cfg,
                    block_stmts,
                    opts,
                    depth,
                    emitted,
                    join_suppress,
                    &disc,
                    &cases,
                    default,
                );
            } else {
                emit_if_else_cascade(
                    out,
                    cfg,
                    block_stmts,
                    opts,
                    depth,
                    emitted,
                    join_suppress,
                    &cascade,
                );
            }
        }
        Region::Loop {
            header,
            body,
            condition,
        } => {
            match condition {
                Some(c) => out.push_str(&format!("{pad}while ({c}) {{\n")),
                None => out.push_str(&format!(
                    "{pad}while (true) {{ // loop @{}\n",
                    cfg.label_for(*header)
                )),
            }
            emit_region(
                out,
                cfg,
                block_stmts,
                body,
                opts,
                depth + 1,
                emitted,
                Some(*header),
            );
            out.push_str(&format!("{pad}}}\n"));
        }
        Region::DoWhile { body, condition } => {
            out.push_str(&format!("{pad}do {{\n"));
            emit_region(
                out,
                cfg,
                block_stmts,
                body,
                opts,
                depth + 1,
                emitted,
                None,
            );
            out.push_str(&format!("{pad}}} while ({condition});\n"));
        }
        Region::Break => {
            out.push_str(&format!("{pad}break;\n"));
        }
        Region::Continue => {
            out.push_str(&format!("{pad}continue;\n"));
        }
    }
}

fn trim_semi(s: &str) -> &str {
    s.trim().trim_end_matches(';').trim()
}

fn emit_seq(
    out: &mut String,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    parts: &[Region],
    opts: &EmitOptions,
    depth: usize,
    emitted: &mut BTreeSet<usize>,
    join_suppress: Option<usize>,
) {
    let mut i = 0;
    while i < parts.len() {
        // M3: `init; while (cond) { body; step; }` → `for (init; cond; step) { body }`
        if let Some((init_idx, loop_idx, init_stmt, step_stmt, body)) =
            match_for_pattern(parts, i, block_stmts)
        {
            for p in &parts[i..init_idx] {
                emit_region(out, cfg, block_stmts, p, opts, depth, emitted, join_suppress);
            }
            // Emit any stmts in the init block except the for-init assign.
            if let Region::Block(bid) = &parts[init_idx] {
                emit_block_except(
                    out,
                    cfg,
                    block_stmts,
                    *bid,
                    opts,
                    depth,
                    emitted,
                    join_suppress,
                    Some(&init_stmt),
                );
            }
            let Region::Loop {
                condition: Some(cond),
                ..
            } = &parts[loop_idx]
            else {
                unreachable!()
            };
            let pad = opts.indent.repeat(depth);
            out.push_str(&format!(
                "{pad}for ({}; {}; {}) {{\n",
                trim_semi(&init_stmt),
                cond,
                trim_semi(&step_stmt)
            ));
            emit_region(
                out,
                cfg,
                block_stmts,
                &body,
                opts,
                depth + 1,
                emitted,
                join_suppress,
            );
            out.push_str(&format!("{pad}}}\n"));
            i = loop_idx + 1;
            continue;
        }
        emit_region(
            out,
            cfg,
            block_stmts,
            &parts[i],
            opts,
            depth,
            emitted,
            join_suppress,
        );
        i += 1;
    }
}

fn match_for_pattern(
    parts: &[Region],
    start: usize,
    block_stmts: &[Vec<Stmt>],
) -> Option<(usize, usize, String, String, Region)> {
    // Find a while loop at or after `start`.
    let loop_idx = (start..parts.len()).find(|&i| {
        matches!(
            &parts[i],
            Region::Loop {
                condition: Some(_),
                ..
            }
        )
    })?;
    let Region::Loop {
        body,
        condition: Some(cond),
        ..
    } = &parts[loop_idx]
    else {
        return None;
    };
    let (body_without_step, step_stmt, step_lhs) = peel_trailing_step(body, block_stmts)?;
    // Condition must mention the step variable.
    if !cond.contains(&step_lhs) {
        return None;
    }
    // Find nearest preceding block that assigns step_lhs (the init).
    let mut init_idx = None;
    let mut init_stmt = None;
    for j in (start..loop_idx).rev() {
        if let Region::Block(bid) = &parts[j] {
            if let Some(stmts) = block_stmts.get(*bid) {
                for s in stmts.iter().rev() {
                    if let Stmt::Assign {
                        dst: crate::ir::Place::Name(n),
                        ..
                    } = s
                    {
                        if n == &step_lhs {
                            init_idx = Some(j);
                            init_stmt = Some(s.to_c_line());
                            break;
                        }
                    }
                }
            }
            if init_idx.is_some() {
                break;
            }
        }
    }
    let init_idx = init_idx?;
    let init_stmt = init_stmt?;
    if init_stmt.is_empty() || step_stmt.is_empty() {
        return None;
    }
    Some((
        init_idx,
        loop_idx,
        init_stmt,
        step_stmt,
        body_without_step,
    ))
}

fn peel_trailing_step(body: &Region, block_stmts: &[Vec<Stmt>]) -> Option<(Region, String, String)> {
    match body {
        Region::Seq(parts) if !parts.is_empty() => {
            let last = parts.last().unwrap();
            let (step, lhs) = step_assign_from_region(last, block_stmts)?;
            let mut prefix = parts[..parts.len() - 1].to_vec();
            // If last block had only the step, drop it; else keep block without step (approx: drop whole block if single stmt).
            if let Region::Block(bid) = last {
                let stmts = block_stmts.get(*bid)?;
                if stmts.len() > 1 {
                    // Keep non-step stmts by emitting a synthetic Seq of remaining — approximate: don't peel.
                    return None;
                }
                let _ = bid;
            }
            let new_body = if prefix.is_empty() {
                Region::Seq(Vec::new())
            } else if prefix.len() == 1 {
                prefix.pop().unwrap()
            } else {
                Region::Seq(prefix)
            };
            Some((new_body, step, lhs))
        }
        Region::Block(bid) => {
            let stmts = block_stmts.get(*bid)?;
            if stmts.len() != 1 {
                return None;
            }
            let (step, lhs) = step_assign_from_stmt(&stmts[0])?;
            Some((Region::Seq(Vec::new()), step, lhs))
        }
        _ => None,
    }
}

fn step_assign_from_region(region: &Region, block_stmts: &[Vec<Stmt>]) -> Option<(String, String)> {
    match region {
        Region::Block(bid) => {
            let stmts = block_stmts.get(*bid)?;
            let last = stmts.last()?;
            step_assign_from_stmt(last)
        }
        _ => None,
    }
}

fn step_assign_from_stmt(s: &Stmt) -> Option<(String, String)> {
    let Stmt::Assign {
        dst: crate::ir::Place::Name(lhs),
        rhs,
        ..
    } = s
    else {
        return None;
    };
    // `x = (x + k)` / `x = (x - k)`
    match rhs {
        crate::ir::Expr::BinOp {
            op: crate::ir::BinOp::Add | crate::ir::BinOp::Sub,
            lhs: l,
            rhs: r,
        } => {
            let l_ok = matches!(l.as_ref(), crate::ir::Expr::Name(n) if n == lhs);
            let r_imm = matches!(r.as_ref(), crate::ir::Expr::Imm(_));
            if l_ok && r_imm {
                return Some((s.to_c_line(), lhs.clone()));
            }
        }
        _ => {}
    }
    None
}

fn emit_block_except(
    out: &mut String,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    id: usize,
    opts: &EmitOptions,
    depth: usize,
    emitted: &mut BTreeSet<usize>,
    join_suppress: Option<usize>,
    skip_line: Option<&str>,
) {
    let _ = join_suppress;
    let first = emitted.insert(id);
    let pad = opts.indent.repeat(depth);
    if opts.show_labels && first {
        out.push_str(&format!("{pad}{}:\n", cfg.label_for(id)));
    }
    if let Some(stmts) = block_stmts.get(id) {
        for s in stmts {
            if matches!(s, Stmt::Phi { .. }) {
                continue;
            }
            let line = s.to_c_line();
            if line.is_empty() {
                continue;
            }
            if skip_line == Some(line.as_str()) {
                continue;
            }
            out.push_str(&format!("{pad}{line}\n"));
        }
    }
}

/// One arm of a flattened if / else-if cascade.
struct CascadeArm<'a> {
    condition: &'a str,
    body: &'a Region,
}

fn collect_if_cascade<'a>(
    condition: &'a str,
    then_branch: &'a Region,
    else_branch: &'a Region,
    block_stmts: &[Vec<Stmt>],
) -> (Vec<CascadeArm<'a>>, Option<&'a Region>) {
    let mut arms = alloc::vec![CascadeArm {
        condition,
        body: then_branch,
    }];
    let mut else_r = else_branch;
    loop {
        if let Some((elif_cond, elif_then, elif_else)) = as_else_if(else_r, block_stmts) {
            arms.push(CascadeArm {
                condition: elif_cond,
                body: elif_then,
            });
            else_r = elif_else;
            continue;
        }
        let default = if region_is_empty(else_r) {
            None
        } else {
            Some(else_r)
        };
        return (arms, default);
    }
}

fn emit_if_else_cascade(
    out: &mut String,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    opts: &EmitOptions,
    depth: usize,
    emitted: &mut BTreeSet<usize>,
    join_suppress: Option<usize>,
    cascade: &(Vec<CascadeArm<'_>>, Option<&Region>),
) {
    let pad = opts.indent.repeat(depth);
    let (arms, default) = cascade;
    // Swift -Onone overflow: `if (overflow) { } else { real_body }` → emit body only.
    if arms.len() == 1
        && region_is_empty_with_stmts(arms[0].body, block_stmts)
        && crate::swift_runtime::is_swift_overflow_condition(arms[0].condition)
    {
        if let Some(d) = default {
            emit_region(
                out,
                cfg,
                block_stmts,
                d,
                opts,
                depth,
                emitted,
                join_suppress,
            );
            return;
        }
    }
    for (i, arm) in arms.iter().enumerate() {
        if i == 0 {
            out.push_str(&format!("{pad}if ({}) {{\n", arm.condition));
        } else {
            out.push_str(&format!("{pad}}} else if ({}) {{\n", arm.condition));
        }
        emit_region(
            out,
            cfg,
            block_stmts,
            arm.body,
            opts,
            depth + 1,
            emitted,
            join_suppress,
        );
    }
    if let Some(d) = default {
        out.push_str(&format!("{pad}}} else {{\n"));
        emit_region(
            out,
            cfg,
            block_stmts,
            d,
            opts,
            depth + 1,
            emitted,
            join_suppress,
        );
        out.push_str(&format!("{pad}}}\n"));
    } else {
        out.push_str(&format!("{pad}}}\n"));
    }
}

fn try_switch_from_cascade<'a>(
    cascade: &'a (Vec<CascadeArm<'a>>, Option<&'a Region>),
    block_stmts: &[Vec<Stmt>],
) -> Option<(String, Vec<(u64, &'a Region)>, Option<&'a Region>)> {
    let (arms, default) = cascade;
    // Need at least 2 equality arms for a worthwhile switch.
    if arms.len() < 2 {
        return None;
    }
    let mut parsed: Vec<(String, u64, &Region)> = Vec::new();
    for arm in arms {
        let (disc, imm) = parse_eq_imm(arm.condition)?;
        parsed.push((disc, imm, arm.body));
    }
    let disc = unify_discriminants(
        &parsed.iter().map(|(d, _, _)| d.as_str()).collect::<Vec<_>>(),
        block_stmts,
    )?;
    let cases: Vec<(u64, &Region)> = parsed.into_iter().map(|(_, imm, body)| (imm, body)).collect();
    Some((disc, cases, *default))
}

fn parse_eq_imm(cond: &str) -> Option<(String, u64)> {
    let cond = cond.trim();
    let (lhs, rhs) = cond.split_once("==")?;
    let lhs = lhs.trim();
    let rhs = rhs.trim();
    if let Some(imm) = parse_c_imm(rhs) {
        return Some((lhs.to_string(), imm));
    }
    if let Some(imm) = parse_c_imm(lhs) {
        return Some((rhs.to_string(), imm));
    }
    None
}

fn parse_c_imm(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(rest) = s.strip_prefix('-') {
        let v: i64 = rest.parse().ok()?;
        return Some((-v) as u64);
    }
    s.parse::<u64>().ok()
}

fn unify_discriminants(discs: &[&str], block_stmts: &[Vec<Stmt>]) -> Option<String> {
    if discs.is_empty() {
        return None;
    }
    if discs.iter().all(|d| *d == discs[0]) {
        return Some(discs[0].to_string());
    }
    // Build undirected aliases from `local_a = local_b` / `param` copies.
    let mut parent: alloc::collections::BTreeMap<String, String> = alloc::collections::BTreeMap::new();
    fn find(parent: &mut alloc::collections::BTreeMap<String, String>, x: &str) -> String {
        let p = parent.get(x).cloned().unwrap_or_else(|| x.to_string());
        if p != x {
            let root = find(parent, &p);
            parent.insert(x.to_string(), root.clone());
            root
        } else {
            p
        }
    }
    fn union(parent: &mut alloc::collections::BTreeMap<String, String>, a: &str, b: &str) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            parent.insert(rb, ra);
        }
    }
    for stmts in block_stmts {
        for s in stmts {
            if let Stmt::Assign {
                dst: crate::ir::Place::Name(dst),
                rhs: crate::ir::Expr::Name(src),
                ..
            } = s
            {
                union(&mut parent, dst, src);
            }
        }
    }
    let roots: Vec<String> = discs.iter().map(|d| find(&mut parent, d)).collect();
    if roots.iter().all(|r| r == &roots[0]) {
        // Prefer the first arm's spelling (usually the param spill).
        Some(discs[0].to_string())
    } else {
        None
    }
}

fn emit_switch(
    out: &mut String,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    opts: &EmitOptions,
    depth: usize,
    emitted: &mut BTreeSet<usize>,
    join_suppress: Option<usize>,
    disc: &str,
    cases: &[(u64, &Region)],
    default: Option<&Region>,
) {
    let pad = opts.indent.repeat(depth);
    let pad1 = opts.indent.repeat(depth + 1);
    out.push_str(&format!("{pad}switch ({disc}) {{\n"));
    for &(imm, body) in cases {
        out.push_str(&format!("{pad1}case {}:\n", format_case_imm(imm)));
        emit_region(
            out,
            cfg,
            block_stmts,
            body,
            opts,
            depth + 2,
            emitted,
            join_suppress,
        );
        out.push_str(&format!("{}break;\n", opts.indent.repeat(depth + 2)));
    }
    if let Some(d) = default {
        out.push_str(&format!("{pad1}default:\n"));
        emit_region(
            out,
            cfg,
            block_stmts,
            d,
            opts,
            depth + 2,
            emitted,
            join_suppress,
        );
        out.push_str(&format!("{}break;\n", opts.indent.repeat(depth + 2)));
    }
    out.push_str(&format!("{pad}}}\n"));
}

fn format_case_imm(imm: u64) -> String {
    // Prefer hex for large / typical switch case constants; decimal for small.
    if imm > 9 {
        format!("0x{imm:x}")
    } else {
        format!("{imm}")
    }
}

/// Peel `Seq([Block(empty)…, If])` / bare `If` so nested else-if cascades flatten.
fn as_else_if<'a>(
    region: &'a Region,
    block_stmts: &[Vec<Stmt>],
) -> Option<(&'a str, &'a Region, &'a Region)> {
    match region {
        Region::If {
            condition,
            then_branch,
            else_branch,
        } => Some((condition.as_str(), then_branch.as_ref(), else_branch.as_ref())),
        Region::Seq(parts) => {
            let mut if_idx = None;
            for (i, p) in parts.iter().enumerate() {
                match p {
                    Region::If { .. } if if_idx.is_none() => if_idx = Some(i),
                    Region::If { .. } => return None,
                    Region::Block(id) if if_idx.is_none() => {
                        // Leading condition blocks must be empty (cmp folded into cond).
                        if block_stmts
                            .get(*id)
                            .is_some_and(|s| s.iter().any(|st| !matches!(st, Stmt::Phi { .. }) && !st.to_c_line().is_empty()))
                        {
                            return None;
                        }
                    }
                    Region::Seq(_) if if_idx.is_none() && region_is_empty(p) => {}
                    _ => return None,
                }
            }
            let i = if_idx?;
            if i + 1 != parts.len() {
                return None;
            }
            as_else_if(&parts[i], block_stmts)
        }
        _ => None,
    }
}

fn region_is_empty(region: &Region) -> bool {
    match region {
        Region::Seq(parts) => parts.iter().all(region_is_empty),
        _ => false,
    }
}

fn region_is_empty_with_stmts(region: &Region, block_stmts: &[Vec<Stmt>]) -> bool {
    match region {
        Region::Seq(parts) => parts
            .iter()
            .all(|p| region_is_empty_with_stmts(p, block_stmts)),
        Region::Block(id) => block_stmts
            .get(*id)
            .map(|stmts| {
                stmts.iter().all(|s| {
                    matches!(s, Stmt::Phi { .. }) || s.to_c_line().trim().is_empty()
                })
            })
            .unwrap_or(true),
        _ => false,
    }
}

fn emit_block(
    out: &mut String,
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    id: usize,
    opts: &EmitOptions,
    depth: usize,
    emitted: &mut BTreeSet<usize>,
    join_suppress: Option<usize>,
) {
    let first = emitted.insert(id);
    let pad = opts.indent.repeat(depth);
    // Shared sinks (nested if / switch) may be referenced from multiple branches —
    // re-emit stmts so each branch shows the assignment (Ghidra-style).
    if opts.show_labels && first {
        out.push_str(&format!("{pad}{}:\n", cfg.label_for(id)));
    }
    if let Some(stmts) = block_stmts.get(id) {
        for s in stmts {
            if matches!(s, Stmt::Phi { .. }) {
                continue;
            }
            let line = s.to_c_line();
            if line.is_empty() {
                continue;
            }
            out.push_str(&pad);
            out.push_str(&line);
            out.push('\n');
        }
    }
    if let Some(b) = cfg.blocks.get(id) {
        match &b.end {
            BlockEnd::Goto(t) => {
                if opts.structured {
                    if join_suppress == Some(*t) || emitted.contains(t) {
                        return;
                    }
                    return;
                }
                out.push_str(&format!("{pad}goto {};\n", cfg.label_for(*t)));
            }
            BlockEnd::Conditional {
                condition,
                branch_target,
                fall_through,
            } if !opts.structured => {
                // Simple / Fallback: explicit if/goto edges (no region nesting).
                out.push_str(&format!("{pad}if ({condition}) {{\n"));
                out.push_str(&format!(
                    "{pad}{}goto {};\n",
                    opts.indent,
                    cfg.label_for(*branch_target)
                ));
                out.push_str(&format!("{pad}}}\n"));
                out.push_str(&format!(
                    "{pad}goto {};\n",
                    cfg.label_for(*fall_through)
                ));
            }
            _ => {}
        }
    }
}
