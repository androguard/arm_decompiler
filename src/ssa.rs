//! CFG-aware SSA construction (Cytron et al.), ported from dex-decompiler `ssa.rs`.
//!
//! φ-nodes are stripped before C emission; versions collapse via [`phi_canonical_map`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::cfg::{BlockId, FunctionCfg};
use crate::ir::{Expr, Place, Stmt, VarId};

fn defs_in_block(stmts: &[Stmt]) -> BTreeSet<u32> {
    let mut defs = BTreeSet::new();
    for s in stmts {
        match s {
            Stmt::Assign {
                dst: Place::Reg(v),
                ..
            } => {
                defs.insert(v.reg);
            }
            Stmt::Phi { dst, .. } => {
                defs.insert(dst.reg);
            }
            _ => {}
        }
    }
    defs
}

fn dominance_frontiers(cfg: &FunctionCfg) -> BTreeMap<BlockId, BTreeSet<BlockId>> {
    let idom = cfg.immediate_dominators();
    let preds = cfg.predecessors();
    let mut df: BTreeMap<BlockId, BTreeSet<BlockId>> = BTreeMap::new();
    for bid in 0..cfg.blocks.len() {
        df.insert(bid, BTreeSet::new());
    }
    for (&bid, pred_list) in &preds {
        if pred_list.len() < 2 {
            continue;
        }
        for &p in pred_list {
            let mut runner = p;
            let idom_b = idom.get(bid).copied();
            while Some(runner) != idom_b {
                df.entry(runner).or_default().insert(bid);
                let idom_runner = idom.get(runner).copied();
                match idom_runner {
                    Some(d) if d != runner => runner = d,
                    _ => break,
                }
            }
        }
    }
    df
}

/// Insert φ-nodes and rename register variables to SSA versions.
pub fn construct_ssa(cfg: &FunctionCfg, block_stmts: &mut [Vec<Stmt>]) {
    if cfg.blocks.is_empty() {
        return;
    }
    let df = dominance_frontiers(cfg);
    let preds = cfg.predecessors();

    let mut all_regs = BTreeSet::new();
    let mut def_sites: BTreeMap<u32, BTreeSet<BlockId>> = BTreeMap::new();
    for (bid, stmts) in block_stmts.iter().enumerate() {
        for r in defs_in_block(stmts) {
            all_regs.insert(r);
            def_sites.entry(r).or_default().insert(bid);
        }
    }

    // Insert φ at dominance frontiers.
    for &reg in &all_regs {
        let mut work: Vec<BlockId> = def_sites
            .get(&reg)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut has_phi = BTreeSet::new();
        while let Some(b) = work.pop() {
            for &d in df.get(&b).into_iter().flatten() {
                if has_phi.insert(d) {
                    let incomings: Vec<(BlockId, VarId)> = preds
                        .get(&d)
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|p| (p, VarId::new(reg, 0)))
                        .collect();
                    if incomings.len() >= 2 {
                        block_stmts[d].insert(
                            0,
                            Stmt::Phi {
                                dst: VarId::new(reg, 0),
                                incomings,
                            },
                        );
                        work.push(d);
                    }
                }
            }
        }
    }

    // Rename (stack-based, dominator tree walk).
    let mut next_ver: BTreeMap<u32, u32> = BTreeMap::new();
    let mut stacks: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for &r in &all_regs {
        next_ver.insert(r, 0);
        stacks.insert(r, alloc::vec![0]);
    }

    let idom = cfg.immediate_dominators();
    let mut children: BTreeMap<BlockId, Vec<BlockId>> = BTreeMap::new();
    for (bid, &dom) in idom.iter().enumerate() {
        if bid != dom {
            children.entry(dom).or_default().push(bid);
        }
    }

    rename_block(
        cfg.entry,
        cfg,
        block_stmts,
        &preds,
        &children,
        &mut next_ver,
        &mut stacks,
    );
}

fn new_name(
    reg: u32,
    next_ver: &mut BTreeMap<u32, u32>,
    stacks: &mut BTreeMap<u32, Vec<u32>>,
) -> VarId {
    let v = next_ver.entry(reg).or_insert(0);
    *v += 1;
    let ver = *v;
    stacks.entry(reg).or_default().push(ver);
    VarId::new(reg, ver)
}

fn rename_block(
    bid: BlockId,
    cfg: &FunctionCfg,
    block_stmts: &mut [Vec<Stmt>],
    preds: &BTreeMap<BlockId, Vec<BlockId>>,
    children: &BTreeMap<BlockId, Vec<BlockId>>,
    next_ver: &mut BTreeMap<u32, u32>,
    stacks: &mut BTreeMap<u32, Vec<u32>>,
) {
    let mut pushed = Vec::new();
    if let Some(stmts) = block_stmts.get_mut(bid) {
        for stmt in stmts.iter_mut() {
            match stmt {
                Stmt::Phi { dst, .. } => {
                    let nv = new_name(dst.reg, next_ver, stacks);
                    *dst = nv;
                    pushed.push(dst.reg);
                }
                Stmt::Assign {
                    dst: Place::Reg(dst),
                    rhs,
                    comment: _,
                } => {
                    *rhs = rename_expr(rhs.clone(), stacks);
                    let nv = new_name(dst.reg, next_ver, stacks);
                    *dst = nv;
                    pushed.push(dst.reg);
                }
                Stmt::Assign {
                    dst: Place::Name(_),
                    rhs,
                    comment: _,
                } => {
                    *rhs = rename_expr(rhs.clone(), stacks);
                }
                Stmt::Store { addr, value, .. } => {
                    *addr = rename_expr(addr.clone(), stacks);
                    *value = rename_expr(value.clone(), stacks);
                }
                Stmt::Expr { expr, .. } => {
                    *expr = rename_expr(expr.clone(), stacks);
                }
                Stmt::Return { value, .. } => {
                    if let Some(v) = value {
                        *v = rename_expr(v.clone(), stacks);
                    }
                }
                _ => {}
            }
        }
    }

    // Fill φ operands on successors from this block's stacks.
    for (from, succ) in cfg.successor_edges() {
        if from != bid {
            continue;
        }
        if let Some(succ_stmts) = block_stmts.get_mut(succ) {
            for stmt in succ_stmts.iter_mut() {
                if let Stmt::Phi { dst, incomings } = stmt {
                    for (pred, val) in incomings.iter_mut() {
                        if *pred == bid {
                            let ver = stacks
                                .get(&dst.reg)
                                .and_then(|s| s.last())
                                .copied()
                                .unwrap_or(0);
                            *val = VarId::new(dst.reg, ver);
                        }
                    }
                }
            }
        }
    }

    for &child in children.get(&bid).into_iter().flatten() {
        rename_block(child, cfg, block_stmts, preds, children, next_ver, stacks);
    }

    for reg in pushed {
        if let Some(st) = stacks.get_mut(&reg) {
            st.pop();
        }
    }
}

fn rename_expr(expr: Expr, stacks: &BTreeMap<u32, Vec<u32>>) -> Expr {
    match expr {
        Expr::Var(v) => {
            let ver = stacks
                .get(&v.reg)
                .and_then(|s| s.last())
                .copied()
                .unwrap_or(0);
            Expr::Var(VarId::new(v.reg, ver))
        }
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: alloc::boxed::Box::new(rename_expr(*lhs, stacks)),
            rhs: alloc::boxed::Box::new(rename_expr(*rhs, stacks)),
        },
        Expr::Call { target, args } => Expr::Call {
            target,
            args: args.into_iter().map(|a| rename_expr(a, stacks)).collect(),
        },
        Expr::MsgSend {
            receiver,
            selector,
            args,
            super_call,
        } => Expr::MsgSend {
            receiver: alloc::boxed::Box::new(rename_expr(*receiver, stacks)),
            selector,
            args: args.into_iter().map(|a| rename_expr(a, stacks)).collect(),
            super_call,
        },
        other => other,
    }
}

/// Remove φ statements (after SSA-based analysis passes).
pub fn strip_phis(block_stmts: &mut [Vec<Stmt>]) {
    for stmts in block_stmts.iter_mut() {
        stmts.retain(|s| !matches!(s, Stmt::Phi { .. }));
    }
}

/// Union-find map: SSA versions that share a φ web → canonical representative.
pub fn phi_canonical_map(block_stmts: &[Vec<Stmt>]) -> BTreeMap<VarId, VarId> {
    let mut parent: BTreeMap<VarId, VarId> = BTreeMap::new();

    fn find(parent: &mut BTreeMap<VarId, VarId>, x: VarId) -> VarId {
        let p = parent.get(&x).copied().unwrap_or(x);
        if p != x {
            let root = find(parent, p);
            parent.insert(x, root);
            root
        } else {
            x
        }
    }

    fn union(parent: &mut BTreeMap<VarId, VarId>, a: VarId, b: VarId) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            parent.insert(rb, ra);
        }
    }

    for stmts in block_stmts {
        for s in stmts {
            if let Stmt::Phi { dst, incomings } = s {
                parent.entry(*dst).or_insert(*dst);
                for (_, v) in incomings {
                    parent.entry(*v).or_insert(*v);
                    union(&mut parent, *dst, *v);
                }
            }
        }
    }

    let keys: Vec<VarId> = parent.keys().copied().collect();
    let mut out = BTreeMap::new();
    for k in keys {
        out.insert(k, find(&mut parent, k));
    }
    out
}

/// Strip SSA version suffixes for emission where safe (Ghidra hides internal SSA names).
///
/// Versions are preserved on register uses when the same register is defined again
/// later in the block — otherwise collapsing would make `local_1c = x0_1` look like it
/// uses a later `x0 = local_28` reload.
pub fn collapse_ssa_versions(block_stmts: &mut [Vec<Stmt>]) {
    for stmts in block_stmts.iter_mut() {
        for i in 0..stmts.len() {
            let later = later_reg_defs(&stmts[i + 1..]);
            collapse_stmt_at(&mut stmts[i], &later);
        }
    }
}

fn later_reg_defs(stmts: &[Stmt]) -> alloc::collections::BTreeSet<u32> {
    let mut out = alloc::collections::BTreeSet::new();
    for s in stmts {
        if let Stmt::Assign {
            dst: Place::Reg(v),
            ..
        } = s
        {
            out.insert(v.reg);
        }
    }
    out
}

fn collapse_stmt_at(s: &mut Stmt, later_regs: &alloc::collections::BTreeSet<u32>) {
    match s {
        Stmt::Assign { dst, rhs, .. } => {
            collapse_place(dst);
            *rhs = collapse_expr(rhs.clone(), later_regs);
        }
        Stmt::Store { addr, value, .. } => {
            *addr = collapse_expr(addr.clone(), later_regs);
            *value = collapse_expr(value.clone(), later_regs);
        }
        Stmt::Expr { expr, .. } => *expr = collapse_expr(expr.clone(), later_regs),
        Stmt::Return { value, .. } => {
            if let Some(v) = value {
                *v = collapse_expr(v.clone(), later_regs);
            }
        }
        _ => {}
    }
}

fn collapse_place(p: &mut Place) {
    if let Place::Reg(v) = p {
        v.ver = 0;
    }
}

fn collapse_expr(e: Expr, later_regs: &alloc::collections::BTreeSet<u32>) -> Expr {
    match e {
        Expr::Var(mut v) => {
            if !later_regs.contains(&v.reg) {
                v.ver = 0;
            }
            Expr::Var(v)
        }
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: alloc::boxed::Box::new(collapse_expr(*lhs, later_regs)),
            rhs: alloc::boxed::Box::new(collapse_expr(*rhs, later_regs)),
        },
        Expr::Call { target, args } => Expr::Call {
            target,
            args: args
                .into_iter()
                .map(|a| collapse_expr(a, later_regs))
                .collect(),
        },
        Expr::MsgSend {
            receiver,
            selector,
            args,
            super_call,
        } => Expr::MsgSend {
            receiver: alloc::boxed::Box::new(collapse_expr(*receiver, later_regs)),
            selector,
            args: args
                .into_iter()
                .map(|a| collapse_expr(a, later_regs))
                .collect(),
            super_call,
        },
        other => other,
    }
}

/// Inline known SSA register defs (calls, locals, imms) at use sites for readable emit.
///
/// Only same-block defs are inlined into local stores to avoid duplicating calls that
/// already appear as `x0 = _fn(...)` in a predecessor block.
pub fn inline_ssa_reg_defs(block_stmts: &mut [Vec<Stmt>]) {
    for stmts in block_stmts.iter_mut() {
        let mut defs: BTreeMap<VarId, Expr> = BTreeMap::new();
        for s in stmts.iter_mut() {
            inline_stmt_uses(s, &defs);
            record_ssa_def(s, &mut defs);
        }
    }
}

fn inlineable_def(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Call { .. } | Expr::MsgSend { .. } | Expr::Name(_) | Expr::Imm(_)
    )
}

fn inline_stmt_uses(s: &mut Stmt, defs: &BTreeMap<VarId, Expr>) {
    if let Stmt::Assign {
        dst: Place::Name(_),
        rhs,
        ..
    } = s
    {
        if let Expr::Var(v) = rhs {
            if let Some(d) = defs.get(v).filter(|d| inlineable_def(d)) {
                *rhs = d.clone();
            }
        }
    }
}

fn record_ssa_def(s: &Stmt, defs: &mut BTreeMap<VarId, Expr>) {
    if let Stmt::Assign {
        dst: Place::Reg(v),
        rhs,
        ..
    } = s
    {
        defs.insert(*v, rhs.clone());
    }
}

/// Remove SSA register assigns whose exact version is never used (e.g. dead reload).
pub fn dead_ssa_version_assigns(block_stmts: &mut [Vec<Stmt>]) {
    for stmts in block_stmts.iter_mut() {
        let mut used = BTreeSet::new();
        for s in stmts.iter().rev() {
            collect_varid_uses(s, &mut used);
        }
        stmts.retain(|s| match s {
            Stmt::Assign {
                dst: Place::Reg(v),
                rhs,
                ..
            } => used.contains(v) || expr_has_side_effects(rhs),
            _ => true,
        });
    }
}

fn collect_varid_uses(s: &Stmt, used: &mut BTreeSet<VarId>) {
    match s {
        Stmt::Assign { rhs, .. } => collect_expr_varids(rhs, used),
        Stmt::Store { addr, value, .. } => {
            collect_expr_varids(addr, used);
            collect_expr_varids(value, used);
        }
        Stmt::Return { value: Some(v), .. } | Stmt::Expr { expr: v, .. } => {
            collect_expr_varids(v, used);
        }
        _ => {}
    }
}

fn collect_expr_varids(e: &Expr, used: &mut BTreeSet<VarId>) {
    match e {
        Expr::Var(v) => {
            used.insert(*v);
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_expr_varids(lhs, used);
            collect_expr_varids(rhs, used);
        }
        Expr::Call { args, .. } => {
            for a in args {
                collect_expr_varids(a, used);
            }
        }
        Expr::MsgSend {
            receiver, args, ..
        } => {
            collect_expr_varids(receiver, used);
            for a in args {
                collect_expr_varids(a, used);
            }
        }
        _ => {}
    }
}

fn expr_has_side_effects(e: &Expr) -> bool {
    matches!(e, Expr::Call { .. } | Expr::MsgSend { .. } | Expr::Mem(_))
}

/// Replace `x0_N` with `x0` when `N` is the result of the most recent call assigned to `x0`.
pub fn fold_call_result_refs(block_stmts: &mut [Vec<Stmt>]) {
    let mut defs: BTreeMap<VarId, Expr> = BTreeMap::new();
    let mut last_call: BTreeMap<u32, Expr> = BTreeMap::new();
    for stmts in block_stmts.iter_mut() {
        for s in stmts.iter_mut() {
            fold_stmt_call_results(s, &defs, &last_call);
            if let Stmt::Assign {
                dst: Place::Reg(v),
                rhs,
                ..
            } = s
            {
                if matches!(rhs, Expr::Call { .. } | Expr::MsgSend { .. }) {
                    last_call.insert(v.reg, rhs.clone());
                }
            }
            record_ssa_def(s, &mut defs);
        }
    }
}

fn fold_stmt_call_results(
    s: &mut Stmt,
    defs: &BTreeMap<VarId, Expr>,
    last_call: &BTreeMap<u32, Expr>,
) {
    match s {
        Stmt::Assign { rhs, .. } => {
            *rhs = fold_call_result_expr(rhs.clone(), defs, last_call);
        }
        Stmt::Return { value, .. } => {
            if let Some(v) = value {
                *v = fold_call_result_expr(v.clone(), defs, last_call);
            }
        }
        _ => {}
    }
}

fn fold_call_result_expr(
    expr: Expr,
    defs: &BTreeMap<VarId, Expr>,
    last_call: &BTreeMap<u32, Expr>,
) -> Expr {
    match expr {
        Expr::Var(v) => {
            if let Some(def) = defs.get(&v) {
                if let Some(recent) = last_call.get(&v.reg) {
                    if def == recent
                        && matches!(def, Expr::Call { .. } | Expr::MsgSend { .. })
                    {
                        return Expr::Var(VarId::new(v.reg, 0));
                    }
                }
            }
            Expr::Var(v)
        }
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: alloc::boxed::Box::new(fold_call_result_expr(*lhs, defs, last_call)),
            rhs: alloc::boxed::Box::new(fold_call_result_expr(*rhs, defs, last_call)),
        },
        Expr::Call { target, args } => Expr::Call {
            target,
            args: args
                .into_iter()
                .map(|a| fold_call_result_expr(a, defs, last_call))
                .collect(),
        },
        Expr::MsgSend {
            receiver,
            selector,
            args,
            super_call,
        } => Expr::MsgSend {
            receiver: alloc::boxed::Box::new(fold_call_result_expr(
                *receiver, defs, last_call,
            )),
            selector,
            args: args
                .into_iter()
                .map(|a| fold_call_result_expr(a, defs, last_call))
                .collect(),
            super_call,
        },
        other => other,
    }
}

/// SSA copy propagation: `x8_2 = x8_1; …` → substitute uses when safe.
pub fn ssa_copy_prop(block_stmts: &mut [Vec<Stmt>]) {
    for stmts in block_stmts.iter_mut() {
        let mut copies: BTreeMap<VarId, Expr> = BTreeMap::new();
        for s in stmts.iter_mut() {
            match s {
                Stmt::Assign {
                    dst: Place::Reg(dst),
                    rhs,
                    ..
                } => {
                    *rhs = subst_expr(rhs.clone(), &copies);
                    match rhs {
                        Expr::Call { .. } | Expr::MsgSend { .. } => {
                            copies.remove(dst);
                        }
                        Expr::Var(src) if src.reg != dst.reg => {
                            copies.insert(*dst, rhs.clone());
                        }
                        _ => {
                            copies.remove(dst);
                        }
                    }
                }
                Stmt::Assign {
                    dst: Place::Name(_),
                    rhs,
                    ..
                } => {
                    *rhs = subst_expr(rhs.clone(), &copies);
                }
                Stmt::Store { addr, value, .. } => {
                    *addr = subst_expr(addr.clone(), &copies);
                    *value = subst_expr(value.clone(), &copies);
                }
                Stmt::Return { value, .. } => {
                    if let Some(v) = value {
                        *v = subst_expr(v.clone(), &copies);
                    }
                }
                Stmt::Expr { expr, .. } => {
                    *expr = subst_expr(expr.clone(), &copies);
                }
                _ => {}
            }
        }
    }
}

fn subst_expr(expr: Expr, copies: &BTreeMap<VarId, Expr>) -> Expr {
    match expr {
        Expr::Var(v) => copies.get(&v).cloned().unwrap_or(Expr::Var(v)),
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: alloc::boxed::Box::new(subst_expr(*lhs, copies)),
            rhs: alloc::boxed::Box::new(subst_expr(*rhs, copies)),
        },
        Expr::Call { target, args } => Expr::Call {
            target,
            args: args.into_iter().map(|a| subst_expr(a, copies)).collect(),
        },
        Expr::MsgSend {
            receiver,
            selector,
            args,
            super_call,
        } => Expr::MsgSend {
            receiver: alloc::boxed::Box::new(subst_expr(*receiver, copies)),
            selector,
            args: args.into_iter().map(|a| subst_expr(a, copies)).collect(),
            super_call,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use super::*;
    use crate::cfg::{BlockEnd, CfgBlock, FunctionCfg};
    use crate::ir::Place;

    fn diamond_cfg() -> FunctionCfg {
        FunctionCfg {
            entry: 0,
            blocks: alloc::vec![
                CfgBlock {
                    start_vaddr: 0,
                    end_vaddr: 4,
                    end: BlockEnd::Conditional {
                        condition: String::from("x0 == 0"),
                        branch_target: 1,
                        fall_through: 2,
                    },
                    insn_indices: alloc::vec![0],
                },
                CfgBlock {
                    start_vaddr: 0x10,
                    end_vaddr: 0x14,
                    end: BlockEnd::Goto(3),
                    insn_indices: alloc::vec![1],
                },
                CfgBlock {
                    start_vaddr: 0x20,
                    end_vaddr: 0x24,
                    end: BlockEnd::Goto(3),
                    insn_indices: alloc::vec![2],
                },
                CfgBlock {
                    start_vaddr: 0x30,
                    end_vaddr: 0x34,
                    end: BlockEnd::Exit,
                    insn_indices: alloc::vec![3],
                },
            ],
            block_by_start: alloc::collections::BTreeMap::new(),
            loop_headers: alloc::collections::BTreeSet::new(),
        }
    }

    #[test]
    fn inserts_phi_at_join() {
        let cfg = diamond_cfg();
        let mut blocks = alloc::vec![
            alloc::vec![],
            alloc::vec![Stmt::Assign {
                dst: Place::Reg(VarId::from_x(8)),
                rhs: Expr::Imm(2),
                comment: None,
            }],
            alloc::vec![Stmt::Assign {
                dst: Place::Reg(VarId::from_x(8)),
                rhs: Expr::Imm(3),
                comment: None,
            }],
            alloc::vec![Stmt::Return {
                value: Some(Expr::Var(VarId::from_x(8))),
                comment: None,
            }],
        ];
        construct_ssa(&cfg, &mut blocks);
        let join = &blocks[3];
        assert!(join.iter().any(|s| matches!(s, Stmt::Phi { .. })));
        let v1 = blocks[1]
            .iter()
            .find_map(|s| match s {
                Stmt::Assign {
                    dst: Place::Reg(v),
                    ..
                } => Some(*v),
                _ => None,
            })
            .unwrap();
        let v2 = blocks[2]
            .iter()
            .find_map(|s| match s {
                Stmt::Assign {
                    dst: Place::Reg(v),
                    ..
                } => Some(*v),
                _ => None,
            })
            .unwrap();
        assert_ne!(v1.ver, v2.ver);
    }

    #[test]
    fn collapse_preserves_version_when_reg_redefined_later() {
        let mut blocks = alloc::vec![alloc::vec![
            Stmt::Assign {
                dst: Place::Reg(VarId::new(0, 3)),
                rhs: Expr::Name(String::from("local_28")),
                comment: None,
            },
            Stmt::Assign {
                dst: Place::Name(String::from("local_1c")),
                rhs: Expr::Var(VarId::new(0, 1)),
                comment: None,
            },
            Stmt::Assign {
                dst: Place::Reg(VarId::new(0, 4)),
                rhs: Expr::Call {
                    target: String::from("_add1"),
                    args: alloc::vec![Expr::Name(String::from("local_28"))],
                },
                comment: None,
            },
        ]];
        collapse_ssa_versions(&mut blocks);
        let rhs = match &blocks[0][1] {
            Stmt::Assign { rhs, .. } => rhs,
            _ => panic!("expected assign"),
        };
        assert!(matches!(rhs, Expr::Var(v) if v.reg == 0 && v.ver == 1));
    }
}
