//! Swift spill / param folding (G2) — Ghidra Merge-style cleanup.
//!
//! After `local = param_N`, subsequent uses of the AAPCS register that held that
//! param (typically `x0` for arg0) are rewritten to the param name until the
//! register is redefined.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ir::{Expr, Place, Stmt};

/// Fold spilled params back over live argument registers in Swift bodies.
pub fn fold_swift_param_spills(block_stmts: &mut [Vec<Stmt>], params: &[String]) {
    if params.is_empty() {
        return;
    }
    // AAPCS64: param_k ↔ x(k-1) for k>=1, except `self` which may be x0 or x20.
    let mut reg_for_param: BTreeMap<String, u32> = BTreeMap::new();
    for (i, p) in params.iter().enumerate() {
        if p == "self" {
            // Method self is rewritten separately via x20; still allow x0 alias early.
            reg_for_param.insert(p.clone(), 0);
        } else {
            reg_for_param.insert(p.clone(), i as u32);
        }
    }

    for stmts in block_stmts.iter_mut() {
        // reg → param name currently aliased into that reg.
        let mut live: BTreeMap<u32, String> = BTreeMap::new();
        // Seed: assume params start in their argument registers.
        for (p, &r) in &reg_for_param {
            live.insert(r, p.clone());
        }

        for s in stmts.iter_mut() {
            match s {
                Stmt::Assign { dst, rhs, .. } => {
                    *rhs = subst_regs(rhs.clone(), &live);
                    match dst {
                        Place::Name(n) => {
                            // `local = param` keeps reg→param; also `local = xN` binds local.
                            if let Expr::Name(p) = rhs {
                                if let Some(&r) = reg_for_param.get(p) {
                                    live.insert(r, p.clone());
                                }
                            }
                            if let Expr::Var(v) = rhs {
                                if let Some(p) = live.get(&v.reg) {
                                    // Strengthen: rewrite rhs to param name.
                                    *rhs = Expr::Name(p.clone());
                                    let _ = n;
                                }
                            }
                        }
                        Place::Reg(v) => {
                            // Register redefined — drop alias unless rhs is a known param.
                            match rhs {
                                Expr::Name(p) if reg_for_param.contains_key(p) => {
                                    live.insert(v.reg, p.clone());
                                }
                                _ => {
                                    live.remove(&v.reg);
                                }
                            }
                        }
                    }
                }
                Stmt::Store { addr, value, .. } => {
                    *addr = subst_regs(addr.clone(), &live);
                    *value = subst_regs(value.clone(), &live);
                }
                Stmt::Expr { expr, .. } => {
                    *expr = subst_regs(expr.clone(), &live);
                }
                Stmt::Return {
                    value: Some(v), ..
                } => {
                    *v = subst_regs(v.clone(), &live);
                }
                _ => {}
            }
        }
    }
}

fn subst_regs(expr: Expr, live: &BTreeMap<u32, String>) -> Expr {
    match expr {
        Expr::Var(v) => {
            if let Some(name) = live.get(&v.reg) {
                Expr::Name(name.clone())
            } else {
                Expr::Var(v)
            }
        }
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: alloc::boxed::Box::new(subst_regs(*lhs, live)),
            rhs: alloc::boxed::Box::new(subst_regs(*rhs, live)),
        },
        Expr::Call { target, args } => Expr::Call {
            target,
            args: args.into_iter().map(|a| subst_regs(a, live)).collect(),
        },
        Expr::MsgSend {
            receiver,
            selector,
            args,
            super_call,
        } => Expr::MsgSend {
            receiver: alloc::boxed::Box::new(subst_regs(*receiver, live)),
            selector,
            args: args.into_iter().map(|a| subst_regs(a, live)).collect(),
            super_call,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::VarId;
    use alloc::vec;

    #[test]
    fn folds_x0_to_param_after_spill() {
        let mut blocks = vec![vec![
            Stmt::Assign {
                dst: Place::Name(String::from("local_8")),
                rhs: Expr::Name(String::from("param_1")),
                comment: None,
            },
            Stmt::Assign {
                dst: Place::Name(String::from("local_10")),
                rhs: Expr::BinOp {
                    op: crate::ir::BinOp::Add,
                    lhs: alloc::boxed::Box::new(Expr::Var(VarId::from_x(0))),
                    rhs: alloc::boxed::Box::new(Expr::Imm(1)),
                },
                comment: None,
            },
        ]];
        fold_swift_param_spills(&mut blocks, &[String::from("param_1")]);
        match &blocks[0][1] {
            Stmt::Assign {
                rhs: Expr::BinOp { lhs, .. },
                ..
            } => assert_eq!(lhs.to_c(), "param_1"),
            other => panic!("{other:?}"),
        }
    }
}
