//! ObjC / Clang block literal invoke recovery (P3-3).
//!
//! Recognizes the ABI pattern `invoke = *(block + 0x10); invoke(block, …)` and
//! direct `___foo_block_invoke` calls, rewriting them to `block(args…)`.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::ir::{BinOp, Expr, Stmt};

const BLOCK_INVOKE_OFF: u64 = 0x10;

/// Rewrite block invokes in-place; drop leftover `*(block+0x10)` loads when folded.
pub fn rewrite_block_invokes(block_stmts: &mut [Vec<Stmt>]) {
    for stmts in block_stmts.iter_mut() {
        rewrite_stmts(stmts);
    }
}

fn rewrite_stmts(stmts: &mut Vec<Stmt>) {
    // temp name / reg key → block pointer expression
    let mut invoke_slot: BTreeMap<String, Expr> = BTreeMap::new();
    let mut used_slots: Vec<String> = Vec::new();

    for s in stmts.iter_mut() {
        match s {
            Stmt::Assign { dst, rhs, comment } => {
                if let Some(block) = invoke_load_base(rhs) {
                    invoke_slot.insert(dst.to_c(), block);
                    continue;
                }
                if let Expr::Call { target, args } = rhs {
                    if let Some(new_rhs) =
                        try_rewrite_call(target, args, &invoke_slot, &mut used_slots)
                    {
                        *rhs = new_rhs;
                        *comment = Some(String::from("Block invoke"));
                    }
                }
            }
            Stmt::Expr { expr, comment } => {
                if let Expr::Call { target, args } = expr {
                    if let Some(new_expr) =
                        try_rewrite_call(target, args, &invoke_slot, &mut used_slots)
                    {
                        *expr = new_expr;
                        *comment = Some(String::from("Block invoke"));
                    }
                }
            }
            Stmt::Return {
                value: Some(v),
                comment,
            } => {
                if let Expr::Call { target, args } = v {
                    if let Some(new_expr) =
                        try_rewrite_call(target, args, &invoke_slot, &mut used_slots)
                    {
                        *v = new_expr;
                        *comment = Some(String::from("Block invoke"));
                    }
                }
            }
            _ => {}
        }
    }

    // Drop assigns that only materialised the invoke function pointer.
    if !used_slots.is_empty() {
        stmts.retain(|s| match s {
            Stmt::Assign { dst, rhs, .. } => {
                let key = dst.to_c();
                !(used_slots.iter().any(|u| u == &key) && invoke_load_base(rhs).is_some())
            }
            _ => true,
        });
    }
}

fn try_rewrite_call(
    target: &str,
    args: &[Expr],
    invoke_slot: &BTreeMap<String, Expr>,
    used_slots: &mut Vec<String>,
) -> Option<Expr> {
    if let Some(_block) = invoke_slot.get(target) {
        used_slots.push(target.to_string());
        let callee = args.first().cloned().unwrap_or_else(|| _block.clone());
        let user_args = strip_leading_block_arg(args, &callee);
        return Some(Expr::Call {
            target: format_block_callee(&callee),
            args: user_args,
        });
    }
    if is_block_invoke_symbol(target) {
        let block = args.first()?.clone();
        let user_args = args.get(1..).unwrap_or(&[]).to_vec();
        return Some(Expr::Call {
            target: format_block_callee(&block),
            args: user_args,
        });
    }
    None
}

fn strip_leading_block_arg(args: &[Expr], block: &Expr) -> Vec<Expr> {
    if let Some(first) = args.first() {
        if expr_same_name(first, block) {
            return args[1..].to_vec();
        }
    }
    // Common: invoke(block_local, user_args…) even if names differ after copy.
    if args.len() >= 2 {
        return args[1..].to_vec();
    }
    args.to_vec()
}

fn expr_same_name(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (Expr::Name(x), Expr::Name(y)) => x == y,
        (Expr::Var(x), Expr::Var(y)) => x == y,
        _ => a.to_c() == b.to_c(),
    }
}

fn format_block_callee(block: &Expr) -> String {
    // Emit as `block(…)` — looks like a direct call through the block pointer.
    block.to_c()
}

/// True for Clang `___foo_block_invoke` / `___foo_block_invoke_0` symbols.
pub fn is_block_invoke_symbol(name: &str) -> bool {
    let n = name.trim_start_matches('_');
    n.contains("_block_invoke")
}

/// `*(base + 0x10)` / `(base + 0x10)` load of the invoke field.
fn invoke_load_base(expr: &Expr) -> Option<Expr> {
    match expr {
        Expr::Mem(s) | Expr::Raw(s) => parse_star_plus_off(s, BLOCK_INVOKE_OFF),
        Expr::BinOp {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            if matches!(rhs.as_ref(), Expr::Imm(n) if *n == BLOCK_INVOKE_OFF) {
                // Bare address of invoke field — uncommon as a call target source.
                Some(lhs.as_ref().clone())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_star_plus_off(s: &str, off: u64) -> Option<Expr> {
    let t = s.trim();
    // *((base + 0x10))  or  *(base + 0x10)
    let inner = t
        .strip_prefix('*')?
        .trim()
        .strip_prefix('(')?
        .strip_suffix(')')?
        .trim();
    let inner = inner
        .strip_prefix('(')
        .and_then(|x| x.strip_suffix(')'))
        .unwrap_or(inner)
        .trim();
    let (base, rhs) = inner.rsplit_once('+')?;
    let rhs = rhs.trim();
    let ok = rhs == format!("0x{off:x}")
        || rhs == format!("{off}")
        || (off == 16 && (rhs == "0x10" || rhs == "16"));
    if !ok {
        return None;
    }
    let base = base.trim();
    if base.is_empty() {
        return None;
    }
    Some(Expr::Name(base.to_string()))
}

/// Extract a rough signature hint from Clang descriptor symbol names when present.
pub fn signature_hint_from_descriptor_symbol(sym: &str) -> Option<String> {
    // e.g. ___block_descriptor_32_e8_i12?0i8l → i12@?0i8 (best-effort)
    let n = sym.trim_start_matches('_');
    let rest = n.strip_prefix("block_descriptor_")?;
    let enc = rest.split("_e").nth(1)?;
    let cleaned: String = enc
        .chars()
        .map(|c| if c == '\u{1}' { '@' } else { c })
        .filter(|c| c.is_ascii_graphic() || *c == '@' || *c == '?' || *c == ' ')
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Place;
    use alloc::vec;

    #[test]
    fn parses_invoke_mem() {
        let e = Expr::Mem(String::from("*((local_40 + 0x10))"));
        let b = invoke_load_base(&e).unwrap();
        assert_eq!(b, Expr::Name(String::from("local_40")));
    }

    #[test]
    fn rewrites_indirect_invoke() {
        let mut blocks = vec![vec![
            Stmt::Assign {
                dst: Place::Name(String::from("x8")),
                rhs: Expr::Mem(String::from("*((local_40 + 0x10))")),
                comment: None,
            },
            Stmt::Assign {
                dst: Place::Name(String::from("x0")),
                rhs: Expr::Call {
                    target: String::from("x8"),
                    args: vec![
                        Expr::Name(String::from("local_40")),
                        Expr::Name(String::from("local_1c")),
                    ],
                },
                comment: None,
            },
        ]];
        rewrite_block_invokes(&mut blocks);
        match &blocks[0][..] {
            [Stmt::Assign {
                rhs: Expr::Call { target, args },
                comment: Some(c),
                ..
            }] => {
                assert_eq!(target, "local_40");
                assert_eq!(args.len(), 1);
                assert_eq!(c, "Block invoke");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn detect_invoke_symbol() {
        assert!(is_block_invoke_symbol("___make_and_run_block_invoke"));
        assert!(!is_block_invoke_symbol("_make_and_run"));
    }
}
