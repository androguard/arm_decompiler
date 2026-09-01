//! Swift runtime call recognition / elision (Phase 6 / S2).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::ir::{Expr, Place, Stmt};
use crate::swift::{demangle_swift, is_swift_mangled};

/// Drop retain/release / bridge ARC noise from Swift bodies.
pub fn strip_swift_runtime_noise(block_stmts: &mut [Vec<Stmt>]) {
    for stmts in block_stmts.iter_mut() {
        stmts.retain(|s| !is_swift_runtime_noise(s));
    }
}

/// Demangle Swift callee names in `Expr::Call` targets.
pub fn rewrite_swift_call_names(block_stmts: &mut [Vec<Stmt>]) {
    for stmts in block_stmts.iter_mut() {
        for s in stmts.iter_mut() {
            rewrite_stmt_calls(s);
        }
    }
}

fn rewrite_stmt_calls(s: &mut Stmt) {
    match s {
        Stmt::Assign { rhs, .. } => rewrite_expr_calls(rhs),
        Stmt::Store { addr, value, .. } => {
            rewrite_expr_calls(addr);
            rewrite_expr_calls(value);
        }
        Stmt::Expr { expr, .. } => rewrite_expr_calls(expr),
        Stmt::Return {
            value: Some(v), ..
        } => rewrite_expr_calls(v),
        _ => {}
    }
}

fn rewrite_expr_calls(expr: &mut Expr) {
    match expr {
        Expr::Call { target, args } => {
            if is_swift_mangled(target) {
                if let Some(d) = demangle_swift(target) {
                    // Use qualified name without full signature for call sites.
                    let name = d
                        .split('(')
                        .next()
                        .unwrap_or(d.as_str())
                        .to_string();
                    *target = name;
                }
            } else if let Some(pretty) = pretty_runtime_name(target) {
                *target = pretty;
            }
            for a in args.iter_mut() {
                rewrite_expr_calls(a);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            rewrite_expr_calls(lhs);
            rewrite_expr_calls(rhs);
        }
        Expr::MsgSend {
            receiver, args, ..
        } => {
            rewrite_expr_calls(receiver);
            for a in args.iter_mut() {
                rewrite_expr_calls(a);
            }
        }
        _ => {}
    }
}

fn pretty_runtime_name(target: &str) -> Option<String> {
    let n = target.trim_start_matches('_');
    match n {
        "swift_allocObject" => Some(String::from("/* swift_allocObject */ _")),
        _ => None,
    }
}

fn is_swift_runtime_noise(s: &Stmt) -> bool {
    match s {
        Stmt::Assign {
            rhs: Expr::Call { target, .. },
            ..
        }
        | Stmt::Expr {
            expr: Expr::Call { target, .. },
            ..
        } => is_swift_runtime_target(target),
        // Swift `-Onone` overflow traps / condition materialization.
        Stmt::Raw(t) if t.contains("brk ") || is_cset_noise(t) => true,
        Stmt::Expr {
            expr: Expr::Raw(t),
            ..
        } if t.contains("brk ") || is_cset_noise(t) => true,
        Stmt::Assign {
            rhs: Expr::Raw(t),
            ..
        } if is_cset_noise(t) => true,
        _ => false,
    }
}

fn is_cset_noise(t: &str) -> bool {
    let t = t.trim();
    t.starts_with("cset ") || t.starts_with("csetm ")
}

fn is_swift_runtime_target(target: &str) -> bool {
    let n = target.trim_start_matches('_');
    matches!(
        n,
        "swift_retain"
            | "swift_release"
            | "swift_retain_n"
            | "swift_release_n"
            | "swift_retainUnowned"
            | "swift_unownedRetain"
            | "swift_unownedRelease"
            | "swift_bridgeObjectRetain"
            | "swift_bridgeObjectRelease"
            | "swift_bridgeObjectRetain_n"
            | "swift_bridgeObjectRelease_n"
            | "swift_willThrow"
            | "swift_errorRetain"
            | "swift_errorRelease"
            | "swift_unknownObjectRetain"
            | "swift_unknownObjectRelease"
            | "swift_nonatomic_unknownObjectRetain"
            | "swift_nonatomic_unknownObjectRelease"
            | "swift_nonatomic_retain"
            | "swift_nonatomic_release"
    ) || n.starts_with("swift_retain")
        || n.starts_with("swift_release")
        || n.starts_with("swift_bridgeObject")
}

/// Drop leftover overflow-check assigns (`cset …`) after retain strip.
pub fn strip_swift_overflow_noise(block_stmts: &mut [Vec<Stmt>]) {
    for stmts in block_stmts.iter_mut() {
        stmts.retain(|s| !is_swift_runtime_noise(s));
    }
}

/// True when a branch condition is a Swift integer-overflow check.
pub fn is_swift_overflow_condition(cond: &str) -> bool {
    let c = cond.trim();
    c.contains(".vs")
        || c.contains(".vc")
        || c.contains("cmp(") && (c.contains(".vs") || c.contains(".vc"))
        || (c.contains(">> 0") && c.contains("& 1"))
        || c.contains("flags.vs")
        || c.contains("flags.vc")
}

/// Map Swift method `self` (often live in `x20` / `x0`) onto the `self` name.
pub fn rewrite_swift_self(block_stmts: &mut [Vec<Stmt>], is_method: bool) {
    if !is_method {
        return;
    }
    for stmts in block_stmts.iter_mut() {
        for s in stmts.iter_mut() {
            rewrite_self_in_stmt(s);
        }
    }
}

fn rewrite_self_in_stmt(s: &mut Stmt) {
    match s {
        Stmt::Assign { dst, rhs, .. } => {
            *rhs = rewrite_self_in_expr(core::mem::replace(
                rhs,
                Expr::Imm(0),
            ));
            if let Place::Reg(v) = dst {
                if is_swift_self_reg(v.reg) {
                    *dst = Place::Name(String::from("self"));
                }
            }
        }
        Stmt::Store { addr, value, .. } => {
            *addr = rewrite_self_in_expr(core::mem::replace(addr, Expr::Imm(0)));
            *value = rewrite_self_in_expr(core::mem::replace(value, Expr::Imm(0)));
        }
        Stmt::Expr { expr, .. } => {
            *expr = rewrite_self_in_expr(core::mem::replace(expr, Expr::Imm(0)));
        }
        Stmt::Return {
            value: Some(v), ..
        } => {
            *v = rewrite_self_in_expr(core::mem::replace(v, Expr::Imm(0)));
        }
        _ => {}
    }
}

fn rewrite_self_in_expr(expr: Expr) -> Expr {
    match expr {
        Expr::Var(v) if is_swift_self_reg(v.reg) => Expr::Name(String::from("self")),
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: alloc::boxed::Box::new(rewrite_self_in_expr(*lhs)),
            rhs: alloc::boxed::Box::new(rewrite_self_in_expr(*rhs)),
        },
        Expr::Call { target, args } => Expr::Call {
            target,
            args: args.into_iter().map(rewrite_self_in_expr).collect(),
        },
        Expr::MsgSend {
            receiver,
            selector,
            args,
            super_call,
        } => Expr::MsgSend {
            receiver: alloc::boxed::Box::new(rewrite_self_in_expr(*receiver)),
            selector,
            args: args.into_iter().map(rewrite_self_in_expr).collect(),
            super_call,
        },
        Expr::Mem(s) => {
            // `*(x20)` → `*(self)`
            let s = s.replace("x20", "self");
            Expr::Mem(s)
        }
        other => other,
    }
}

fn is_swift_self_reg(reg: u32) -> bool {
    // Swift instance methods typically keep `self` in x20; free funcs use x0 for arg0.
    // Only rewrite x20 here — x0 is often the return / scratch after the prologue.
    reg == 20
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Place, VarId};
    use alloc::vec;

    #[test]
    fn detects_overflow_conds() {
        assert!(is_swift_overflow_condition("((x8 >> 0) & 1) != 0"));
        assert!(is_swift_overflow_condition("cmp(x0, 1).vs"));
        assert!(!is_swift_overflow_condition("param_1 > 0"));
    }

    #[test]
    fn rewrites_x20_to_self() {
        let mut blocks = vec![vec![Stmt::Assign {
            dst: Place::Name(String::from("local_8")),
            rhs: Expr::Var(VarId::from_x(20)),
            comment: None,
        }]];
        rewrite_swift_self(&mut blocks, true);
        match &blocks[0][0] {
            Stmt::Assign {
                rhs: Expr::Name(n),
                ..
            } => assert_eq!(n, "self"),
            other => panic!("{other:?}"),
        }
    }
}
