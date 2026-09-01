//! Lightweight type lattice for locals / params (M5 / P4-1 / P1-6).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ir::{BinOp, Expr, Place, Stmt};

/// Coarse C / ObjC types for recovered names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ty {
    /// Unknown / untyped (`undefined4` / `undefined8` style).
    #[default]
    Undefined,
    Int32,
    Int64,
    Float,
    Double,
    Ptr,
    ObjCId,
}

impl Ty {
    pub fn as_c_str(self) -> &'static str {
        match self {
            Ty::Undefined => "undefined4",
            Ty::Int32 => "int",
            Ty::Int64 => "long long",
            Ty::Float => "float",
            Ty::Double => "double",
            Ty::Ptr => "void *",
            Ty::ObjCId => "id",
        }
    }

    /// Swift type spelling for locals / params.
    pub fn as_swift_str(self) -> &'static str {
        match self {
            Ty::Undefined => "Any",
            Ty::Int32 | Ty::Int64 => "Int",
            Ty::Float => "Float",
            Ty::Double => "Double",
            Ty::Ptr => "UnsafeMutableRawPointer",
            Ty::ObjCId => "AnyObject",
        }
    }

    /// Prototype / return spelling: prefer `undefined8` when still unknown.
    pub fn as_proto_str(self) -> &'static str {
        match self {
            Ty::Undefined => "undefined8",
            other => other.as_c_str(),
        }
    }

    fn merge(self, other: Ty) -> Ty {
        use Ty::*;
        match (self, other) {
            (a, b) if a == b => a,
            (Undefined, t) | (t, Undefined) => t,
            (ObjCId, _) | (_, ObjCId) => ObjCId,
            (Ptr, _) | (_, Ptr) => Ptr,
            (Double, _) | (_, Double) => Double,
            (Float, Float) => Float,
            (Float, Int32 | Int64) | (Int32 | Int64, Float) => Float,
            (Int64, _) | (_, Int64) => Int64,
            (Int32, Int32) => Int32,
        }
    }
}

fn bump(types: &mut BTreeMap<String, Ty>, name: &str, ty: Ty) {
    let e = types.entry(name.into()).or_insert(Ty::Undefined);
    *e = e.merge(ty);
}

/// Infer local/param types from IR uses (MsgSend receiver → `id`, address-of → ptr, …).
pub fn infer_name_types(block_stmts: &[Vec<Stmt>]) -> BTreeMap<String, Ty> {
    let mut types: BTreeMap<String, Ty> = BTreeMap::new();

    for stmts in block_stmts {
        for s in stmts {
            match s {
                Stmt::Assign {
                    dst: Place::Name(n),
                    rhs,
                    ..
                } => {
                    let mut ty = ty_from_expr(rhs, &types);
                    if let Expr::Name(src) = rhs {
                        if src == "self" || types.get(src) == Some(&Ty::ObjCId) {
                            ty = Ty::ObjCId;
                        }
                    }
                    bump(&mut types, n, ty);
                    mark_expr_uses(rhs, &mut types);
                }
                Stmt::Assign { rhs, .. } => mark_expr_uses(rhs, &mut types),
                Stmt::Store { addr, value, .. } => {
                    mark_expr_uses(addr, &mut types);
                    mark_expr_uses(value, &mut types);
                }
                Stmt::Expr { expr, .. } => mark_expr_uses(expr, &mut types),
                Stmt::Return {
                    value: Some(v), ..
                } => {
                    mark_expr_uses(v, &mut types);
                    // Returning an arithmetic expression marks involved names as int.
                    if matches!(v, Expr::BinOp { .. } | Expr::Imm(_)) {
                        if let Expr::BinOp { lhs, rhs, .. } = v {
                            bump_name_int(lhs, &mut types);
                            bump_name_int(rhs, &mut types);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Fixpoint: propagate through `a = b` copies (param → local and reverse).
    for _ in 0..8 {
        let before = types.clone();
        for stmts in block_stmts {
            for s in stmts {
                if let Stmt::Assign {
                    dst: Place::Name(dst),
                    rhs: Expr::Name(src),
                    ..
                } = s
                {
                    let t = types
                        .get(dst)
                        .copied()
                        .unwrap_or(Ty::Undefined)
                        .merge(types.get(src).copied().unwrap_or(Ty::Undefined));
                    if t != Ty::Undefined {
                        bump(&mut types, dst, t);
                        bump(&mut types, src, t);
                    }
                }
            }
        }
        if types == before {
            break;
        }
    }

    types
}

fn bump_name_int(expr: &Expr, types: &mut BTreeMap<String, Ty>) {
    if let Expr::Name(n) = expr {
        bump(types, n, Ty::Int32);
    }
}

/// Return type from `return` statements + known name types.
pub fn infer_return_type(block_stmts: &[Vec<Stmt>], types: &BTreeMap<String, Ty>) -> Ty {
    let mut ret = Ty::Undefined;
    let mut saw = false;
    for stmts in block_stmts {
        for s in stmts {
            if let Stmt::Return {
                value: Some(v), ..
            } = s
            {
                saw = true;
                ret = ret.merge(ty_from_expr(v, types));
            }
        }
    }
    if saw {
        ret
    } else {
        Ty::Undefined
    }
}

fn ty_from_expr(expr: &Expr, types: &BTreeMap<String, Ty>) -> Ty {
    match expr {
        Expr::Imm(n) if *n <= u32::MAX as u64 => Ty::Int32,
        Expr::Imm(_) => Ty::Int64,
        Expr::MsgSend { .. } => Ty::ObjCId,
        Expr::Name(n) => types.get(n).copied().unwrap_or(Ty::Undefined),
        Expr::Var(v) if (64..96).contains(&v.reg) => Ty::Double,
        Expr::BinOp {
            lhs,
            ..
        } if matches!(lhs.as_ref(), Expr::Var(v) if v.reg == 29 || v.reg == 32) => Ty::Ptr,
        // Float arithmetic when either side is an FP register / float-typed name.
        Expr::BinOp { op: BinOp::Div, lhs, rhs } => {
            let l = ty_from_expr(lhs, types);
            let r = ty_from_expr(rhs, types);
            if matches!(l, Ty::Float | Ty::Double) || matches!(r, Ty::Float | Ty::Double) {
                l.merge(r).merge(Ty::Double)
            } else {
                Ty::Int32
            }
        }
        Expr::BinOp { lhs, rhs, .. }
            if matches!(lhs.as_ref(), Expr::Var(v) if (64..96).contains(&v.reg))
                || matches!(rhs.as_ref(), Expr::Var(v) if (64..96).contains(&v.reg)) =>
        {
            Ty::Double
        }
        // Integer arithmetic defaults to `int` (clang -O0 W-reg traffic).
        Expr::BinOp { .. } => Ty::Int32,
        Expr::Var(_) | Expr::Call { .. } | Expr::Mem(_) | Expr::Raw(_) => Ty::Undefined,
    }
}

fn mark_expr_uses(expr: &Expr, types: &mut BTreeMap<String, Ty>) {
    match expr {
        Expr::MsgSend {
            receiver, args, ..
        } => {
            if let Expr::Name(n) = receiver.as_ref() {
                bump(types, n, Ty::ObjCId);
            } else {
                mark_expr_uses(receiver, types);
            }
            for a in args {
                mark_expr_uses(a, types);
            }
        }
        Expr::Call { args, .. } => {
            for a in args {
                mark_expr_uses(a, types);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            mark_expr_uses(lhs, types);
            mark_expr_uses(rhs, types);
            // Names participating in arithmetic are ints (unless already ptr/id/float).
            let floatish = matches!(lhs.as_ref(), Expr::Var(v) if (64..96).contains(&v.reg))
                || matches!(rhs.as_ref(), Expr::Var(v) if (64..96).contains(&v.reg))
                || matches!(
                    lhs.as_ref(),
                    Expr::Name(n) if matches!(types.get(n.as_str()), Some(Ty::Float | Ty::Double))
                )
                || matches!(
                    rhs.as_ref(),
                    Expr::Name(n) if matches!(types.get(n.as_str()), Some(Ty::Float | Ty::Double))
                );
            if floatish {
                if let Expr::Name(n) = lhs.as_ref() {
                    bump(types, n, Ty::Double);
                }
                if let Expr::Name(n) = rhs.as_ref() {
                    bump(types, n, Ty::Double);
                }
            } else {
                bump_name_int(lhs, types);
                bump_name_int(rhs, types);
            }
        }
        _ => {}
    }
}

/// Prefer `int` for names that appear in CFG branch conditions (cmp/branch folds).
pub fn infer_types_from_conditions(
    conditions: impl IntoIterator<Item = impl AsRef<str>>,
    types: &mut BTreeMap<String, Ty>,
) {
    for cond in conditions {
        for tok in cond.as_ref().split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
            if tok.starts_with("param_") || tok.starts_with("local_") || tok == "self" {
                if types.get(tok).copied().unwrap_or(Ty::Undefined) == Ty::Undefined {
                    bump(types, tok, Ty::Int32);
                }
            }
        }
    }
}

/// Prefer `void *` for names that hold `(fp/sp ± imm)` address expressions.
pub fn mark_address_temps(block_stmts: &[Vec<Stmt>], types: &mut BTreeMap<String, Ty>) {
    for stmts in block_stmts {
        for s in stmts {
            if let Stmt::Assign {
                dst: Place::Name(n),
                rhs: Expr::BinOp { lhs, .. },
                ..
            } = s
            {
                if matches!(lhs.as_ref(), Expr::Var(v) if v.reg == 29 || v.reg == 32) {
                    bump(types, n.as_str(), Ty::Ptr);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BinOp, VarId};
    use alloc::boxed::Box;
    use alloc::vec;

    #[test]
    fn msgsend_receiver_is_id() {
        let blocks = vec![vec![Stmt::Assign {
            dst: Place::Reg(VarId::from_x(0)),
            rhs: Expr::MsgSend {
                receiver: Box::new(Expr::Name(String::from("self"))),
                selector: String::from("hello:"),
                args: vec![Expr::Imm(1)],
                super_call: false,
            },
            comment: None,
        }]];
        let t = infer_name_types(&blocks);
        assert_eq!(t.get("self"), Some(&Ty::ObjCId));
    }

    #[test]
    fn arithmetic_and_copy_yield_int_params() {
        let blocks = vec![vec![
            Stmt::Assign {
                dst: Place::Name(String::from("local_4")),
                rhs: Expr::Name(String::from("param_1")),
                comment: None,
            },
            Stmt::Return {
                value: Some(Expr::BinOp {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Name(String::from("local_4"))),
                    rhs: Box::new(Expr::Imm(1)),
                }),
                comment: None,
            },
        ]];
        let t = infer_name_types(&blocks);
        assert_eq!(t.get("local_4"), Some(&Ty::Int32));
        assert_eq!(t.get("param_1"), Some(&Ty::Int32));
        assert_eq!(infer_return_type(&blocks, &t), Ty::Int32);
    }
}
