//! Pass framework (dex-decompiler / jadx visitor analogue).

use alloc::vec::Vec;

use crate::ir::{BinOp, Expr, Place, Stmt, VarId};

pub trait Pass {
    fn run(&self, stmts: Vec<Stmt>) -> Vec<Stmt>;
}

#[derive(Default)]
pub struct PassRunner {
    passes: Vec<alloc::boxed::Box<dyn Pass + Send>>,
}

impl PassRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add<P: Pass + Send + 'static>(&mut self, pass: P) {
        self.passes.push(alloc::boxed::Box::new(pass));
    }

    pub fn run(&self, stmts: Vec<Stmt>) -> Vec<Stmt> {
        let mut cur = stmts;
        for p in &self.passes {
            cur = p.run(cur);
        }
        cur
    }

    /// Default iOS pipeline (mirrors dex InvokeChain + simplify + dead).
    pub fn default_pipeline() -> Self {
        let mut r = Self::new();
        r.add(RedundantMovPass);
        r.add(ExprSimplifyPass);
        r.add(LocalCopyPropPass);
        r.add(RedundantArgLoadPass);
        r.add(DeadAssignPass);
        r
    }
}

/// `xN = xN` → remove; `xN = xM; … only copy` kept for now (copy-prop later).
#[derive(Debug, Clone, Copy, Default)]
pub struct RedundantMovPass;

impl Pass for RedundantMovPass {
    fn run(&self, stmts: Vec<Stmt>) -> Vec<Stmt> {
        stmts
            .into_iter()
            .filter(|s| {
                !matches!(
                    s,
                    Stmt::Assign {
                        dst: Place::Reg(dst),
                        rhs: Expr::Var(src),
                        ..
                    } if dst == src
                )
            })
            .collect()
    }
}

/// Fold `x + 0`; keep `x + 1` as BinOp (Ghidra-style, not `x++`).
#[derive(Debug, Clone, Copy, Default)]
pub struct ExprSimplifyPass;

impl Pass for ExprSimplifyPass {
    fn run(&self, stmts: Vec<Stmt>) -> Vec<Stmt> {
        stmts
            .into_iter()
            .map(|s| match s {
                Stmt::Assign { dst, rhs, comment } => Stmt::Assign {
                    dst,
                    rhs: simplify_expr(rhs),
                    comment,
                },
                other => other,
            })
            .collect()
    }
}

fn simplify_expr(expr: Expr) -> Expr {
    match expr {
        Expr::BinOp { op, lhs, rhs } => {
            let lhs = simplify_expr(*lhs);
            let rhs = simplify_expr(*rhs);
            match (&lhs, op, &rhs) {
                (_, BinOp::Add, Expr::Imm(0)) | (Expr::Imm(0), BinOp::Add, _) => lhs,
                _ => Expr::BinOp {
                    op,
                    lhs: alloc::boxed::Box::new(lhs),
                    rhs: alloc::boxed::Box::new(rhs),
                },
            }
        }
        other => other,
    }
}

/// Propagate `xN = local_*/param_*` / imm into later uses; fold `x = expr; local = x`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalCopyPropPass;

impl Pass for LocalCopyPropPass {
    fn run(&self, stmts: Vec<Stmt>) -> Vec<Stmt> {
        // Key by full VarId so SSA versions (x0_1 vs x0_3) do not alias.
        let mut binds: alloc::collections::BTreeMap<crate::ir::VarId, Expr> =
            alloc::collections::BTreeMap::new();
        let mut out = Vec::with_capacity(stmts.len());
        for s in stmts {
            match s {
                Stmt::Assign { dst, rhs, comment } => {
                    let rhs = subst_expr(rhs, &binds);
                    match &dst {
                        Place::Reg(v) => {
                            binds.remove(v);
                            if v.reg != 32 {
                                match &rhs {
                                    Expr::Name(_) | Expr::Imm(_) => {
                                        binds.insert(*v, rhs.clone());
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Place::Name(_) => {}
                    }
                    out.push(Stmt::Assign { dst, rhs, comment });
                }
                Stmt::Store { addr, value, comment } => {
                    out.push(Stmt::Store {
                        addr: subst_expr(addr, &binds),
                        value: subst_expr(value, &binds),
                        comment,
                    });
                }
                Stmt::Return { value, comment } => {
                    out.push(Stmt::Return {
                        value: value.map(|v| subst_expr(v, &binds)),
                        comment,
                    });
                }
                Stmt::Expr { expr, comment } => {
                    out.push(Stmt::Expr {
                        expr: subst_expr(expr, &binds),
                        comment,
                    });
                }
                other => out.push(other),
            }
        }
        fold_temp_into_local(&mut out);
        // Repeat: `x0 = (x8+…); return x0` then `x8 = mul; return (x8+…)`.
        for _ in 0..4 {
            let before = out.len();
            fold_assign_return(&mut out);
            if out.len() == before {
                break;
            }
        }
        out
    }
}

fn subst_expr(expr: Expr, binds: &alloc::collections::BTreeMap<crate::ir::VarId, Expr>) -> Expr {
    match expr {
        Expr::Var(v) => binds.get(&v).cloned().unwrap_or(Expr::Var(v)),
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: alloc::boxed::Box::new(subst_expr(*lhs, binds)),
            rhs: alloc::boxed::Box::new(subst_expr(*rhs, binds)),
        },
        Expr::Call { target, args } => Expr::Call {
            target,
            args: args.into_iter().map(|a| subst_expr(a, binds)).collect(),
        },
        Expr::MsgSend {
            receiver,
            selector,
            args,
            super_call,
        } => Expr::MsgSend {
            receiver: alloc::boxed::Box::new(subst_expr(*receiver, binds)),
            selector,
            args: args.into_iter().map(|a| subst_expr(a, binds)).collect(),
            super_call,
        },
        other => other,
    }
}

/// `x8 = expr; local_c = x8` → `local_c = expr` (Ghidra collapses temps).
fn fold_temp_into_local(stmts: &mut Vec<Stmt>) {
    let mut i = 1;
    while i < stmts.len() {
        let fold = match (&stmts[i - 1], &stmts[i]) {
            (
                Stmt::Assign {
                    dst: Place::Reg(tmp),
                    rhs,
                    ..
                },
                Stmt::Assign {
                    dst: Place::Name(local),
                    rhs: Expr::Var(v),
                    comment,
                },
            ) if tmp == v && tmp.reg != 32 => Some((
                Place::Name(local.clone()),
                rhs.clone(),
                comment.clone(),
            )),
            _ => None,
        };
        if let Some((dst, rhs, comment)) = fold {
            stmts[i] = Stmt::Assign { dst, rhs, comment };
            stmts.remove(i - 1);
            // don't advance i — re-check new pair at this index
        } else {
            i += 1;
        }
    }
}

fn fold_assign_return(stmts: &mut Vec<Stmt>) {
    // `xN = expr; …; return …xN…` — walk back past dead copies.
    let Some(last) = stmts.len().checked_sub(1) else {
        return;
    };
    if last == 0 {
        return;
    }
    let Stmt::Return {
        value: Some(ret_expr),
        comment,
    } = &stmts[last]
    else {
        return;
    };
    let comment = comment.clone();
    let mut ret_expr = ret_expr.clone();

    // Prefer direct `return xN` / `(… xN …)` with defining assign above.
    let mut i = last;
    while i > 0 {
        i -= 1;
        let Stmt::Assign {
            dst: Place::Reg(dst),
            rhs,
            ..
        } = &stmts[i]
        else {
            continue;
        };
        let dst = *dst;
        if dst.reg == 32 {
            continue;
        }
        if !expr_mentions_reg(&ret_expr, dst.reg) {
            continue;
        }
        // Don't cross another def/use of dst between i and last.
        let mut ok = true;
        for s in &stmts[i + 1..last] {
            if stmt_mentions_reg(s, dst.reg) {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }
        let rhs = rhs.clone();
        if matches!(&ret_expr, Expr::Var(v) if v.reg == dst.reg) {
            stmts[last] = Stmt::Return {
                value: Some(rhs),
                comment,
            };
            stmts.remove(i);
            return;
        }
        ret_expr = subst_reg(ret_expr, dst.reg, &rhs);
        stmts[last] = Stmt::Return {
            value: Some(ret_expr.clone()),
            comment: comment.clone(),
        };
        stmts.remove(i);
        // Continue folding other temps in the new return expr.
        return fold_assign_return(stmts);
    }
}

fn stmt_mentions_reg(s: &Stmt, reg: u32) -> bool {
    match s {
        Stmt::Assign { dst: Place::Reg(d), rhs, .. } => {
            d.reg == reg || expr_mentions_reg(rhs, reg)
        }
        Stmt::Assign { rhs, .. } => expr_mentions_reg(rhs, reg),
        Stmt::Store { addr, value, .. } => {
            expr_mentions_reg(addr, reg) || expr_mentions_reg(value, reg)
        }
        Stmt::Return { value: Some(v), .. } | Stmt::Expr { expr: v, .. } => {
            expr_mentions_reg(v, reg)
        }
        _ => false,
    }
}

fn expr_mentions_reg(e: &Expr, reg: u32) -> bool {
    match e {
        Expr::Var(v) => v.reg == reg,
        Expr::BinOp { lhs, rhs, .. } => {
            expr_mentions_reg(lhs, reg) || expr_mentions_reg(rhs, reg)
        }
        Expr::Call { args, .. } => args.iter().any(|a| expr_mentions_reg(a, reg)),
        Expr::MsgSend {
            receiver, args, ..
        } => {
            expr_mentions_reg(receiver, reg) || args.iter().any(|a| expr_mentions_reg(a, reg))
        }
        _ => false,
    }
}

fn subst_reg(expr: Expr, reg: u32, with: &Expr) -> Expr {
    match expr {
        Expr::Var(v) if v.reg == reg => with.clone(),
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: alloc::boxed::Box::new(subst_reg(*lhs, reg, with)),
            rhs: alloc::boxed::Box::new(subst_reg(*rhs, reg, with)),
        },
        Expr::Call { target, args } => Expr::Call {
            target,
            args: args.into_iter().map(|a| subst_reg(a, reg, with)).collect(),
        },
        Expr::MsgSend {
            receiver,
            selector,
            args,
            super_call,
        } => Expr::MsgSend {
            receiver: alloc::boxed::Box::new(subst_reg(*receiver, reg, with)),
            selector,
            args: args.into_iter().map(|a| subst_reg(a, reg, with)).collect(),
            super_call,
        },
        other => other,
    }
}

/// Remove `xN = local` immediately before `xN = call(…, local, …)` (AAPCS64 arg reload).
#[derive(Debug, Clone, Copy, Default)]
pub struct RedundantArgLoadPass;

impl Pass for RedundantArgLoadPass {
    fn run(&self, stmts: Vec<Stmt>) -> Vec<Stmt> {
        let mut out = Vec::with_capacity(stmts.len());
        let mut i = 0;
        while i < stmts.len() {
            if let Some(call_idx) = next_call_assign(&stmts, i + 1) {
                if is_redundant_arg_load(&stmts[i], &stmts[call_idx]) {
                    i += 1;
                    continue;
                }
            }
            out.push(stmts[i].clone());
            i += 1;
        }
        out
    }
}

fn next_call_assign(stmts: &[Stmt], start: usize) -> Option<usize> {
    stmts[start..].iter().position(|s| {
        matches!(
            s,
            Stmt::Assign {
                rhs: Expr::Call { .. },
                ..
            }
        )
    }).map(|p| start + p)
}

fn is_redundant_arg_load(load: &Stmt, call: &Stmt) -> bool {
    let (
        Stmt::Assign {
            dst: Place::Reg(dst),
            rhs,
            ..
        },
        Stmt::Assign {
            dst: Place::Reg(call_dst),
            rhs: Expr::Call { args, .. },
            ..
        },
    ) = (load, call)
    else {
        return false;
    };
    if dst.reg != call_dst.reg {
        return false;
    }
    args.iter().any(|a| a == rhs)
}

/// Remove assigns to registers never read later (local, linear).
#[derive(Debug, Clone, Copy, Default)]
pub struct DeadAssignPass;

impl Pass for DeadAssignPass {
    fn run(&self, stmts: Vec<Stmt>) -> Vec<Stmt> {
        let mut used = alloc::collections::BTreeSet::new();
        for s in stmts.iter().rev() {
            collect_uses(s, &mut used);
        }
        let mut live_regs = alloc::collections::BTreeSet::<u32>::new();
        for s in &stmts {
            force_live_out(s, &mut live_regs);
        }
        let mut keep = alloc::vec![true; stmts.len()];
        for (i, s) in stmts.iter().enumerate().rev() {
            match s {
                Stmt::Assign {
                    dst: Place::Reg(dst),
                    rhs,
                    ..
                } => {
                    let dst_live = live_regs.contains(&dst.reg);
                    if !dst_live && !expr_has_side_effects(rhs) {
                        keep[i] = false;
                    } else {
                        live_regs.remove(&dst.reg);
                        collect_expr_regs(rhs, &mut live_regs);
                    }
                }
                Stmt::Assign {
                    dst: Place::Name(_),
                    rhs,
                    ..
                } => {
                    // Named locals are always kept (Ghidra shows all frame locals).
                    collect_expr_regs(rhs, &mut live_regs);
                }
                Stmt::Store { addr, value, .. } => {
                    collect_expr_regs(addr, &mut live_regs);
                    collect_expr_regs(value, &mut live_regs);
                }
                Stmt::Expr { expr, .. } => collect_expr_regs(expr, &mut live_regs),
                Stmt::Return { value, .. } => {
                    if let Some(v) = value {
                        collect_expr_regs(v, &mut live_regs);
                    }
                }
                _ => {}
            }
        }
        let _ = used;
        stmts
            .into_iter()
            .enumerate()
            .filter_map(|(i, s)| if keep[i] { Some(s) } else { None })
            .collect()
    }
}

fn force_live_out(s: &Stmt, live: &mut alloc::collections::BTreeSet<u32>) {
    match s {
        Stmt::Return { value: Some(v), .. } | Stmt::Expr { expr: v, .. } => {
            collect_expr_regs(v, live);
        }
        Stmt::Store { addr, value, .. } => {
            collect_expr_regs(addr, live);
            collect_expr_regs(value, live);
        }
        Stmt::Assign {
            rhs: Expr::Call { .. },
            ..
        } => {}
        _ => {}
    }
}

fn expr_has_side_effects(e: &Expr) -> bool {
    matches!(e, Expr::Call { .. } | Expr::MsgSend { .. } | Expr::Mem(_))
}

fn collect_uses(s: &Stmt, used: &mut alloc::collections::BTreeSet<VarId>) {
    match s {
        Stmt::Assign { rhs, .. } => collect_expr_vars(rhs, used),
        Stmt::Store { addr, value, .. } => {
            collect_expr_vars(addr, used);
            collect_expr_vars(value, used);
        }
        Stmt::Expr { expr, .. } => collect_expr_vars(expr, used),
        Stmt::Return { value: Some(v), .. } => collect_expr_vars(v, used),
        _ => {}
    }
}

fn collect_expr_vars(e: &Expr, used: &mut alloc::collections::BTreeSet<VarId>) {
    match e {
        Expr::Var(v) => {
            used.insert(*v);
        }
        Expr::Call { args, .. } => {
            for a in args {
                collect_expr_vars(a, used);
            }
        }
        Expr::MsgSend {
            receiver, args, ..
        } => {
            collect_expr_vars(receiver, used);
            for a in args {
                collect_expr_vars(a, used);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_expr_vars(lhs, used);
            collect_expr_vars(rhs, used);
        }
        _ => {}
    }
}

fn collect_expr_regs(e: &Expr, live: &mut alloc::collections::BTreeSet<u32>) {
    match e {
        Expr::Var(v) => {
            live.insert(v.reg);
        }
        Expr::Call { args, .. } => {
            for a in args {
                collect_expr_regs(a, live);
            }
        }
        Expr::MsgSend {
            receiver, args, ..
        } => {
            collect_expr_regs(receiver, live);
            for a in args {
                collect_expr_regs(a, live);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_expr_regs(lhs, live);
            collect_expr_regs(rhs, live);
        }
        _ => {}
    }
}
