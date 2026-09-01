//! Stack-frame recovery and Ghidra-like local / parameter naming.
//!
//! Maps `[sp, #off]` after a prologue `sub sp, sp, #frame` to `local_<hex>`,
//! where `<hex>` is the distance from the *incoming* SP (Ghidra stack naming).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::cfg::{BlockEnd, FunctionCfg};
use crate::ir::{BinOp, Expr, Place, Stmt};
use crate::types::Ty;

/// Recovered AAPCS64-ish prototype + stack locals (Ghidra Merge lite).
#[derive(Debug, Clone, Default)]
pub struct FrameRecovery {
    pub frame_size: u64,
    /// Prologue `add x29, sp, #fp_off` (distance from SP to FP), if detected.
    pub fp_off: Option<u64>,
    /// Optional ObjC method prototype (`- (int)hello:(int)param_2`) from class-dump types.
    pub objc_method_proto: Option<String>,
    /// Optional Swift `func` prototype from mangling (Phase 6).
    pub swift_proto: Option<String>,
    /// Emit Swift dialect (var/func) instead of C.
    pub swift_dialect: bool,
    /// Declared locals in stable order (`local_4`, `local_8`, …).
    pub locals: Vec<String>,
    /// Inferred C types for locals / params (M5).
    pub local_types: BTreeMap<String, Ty>,
    /// `param_1` … from first stores of `x0`… into stack slots.
    pub params: Vec<String>,
    /// True when the function returns a value in `x0`.
    pub returns_value: bool,
    /// Inferred return type (`void` when `!returns_value`).
    pub return_ty: Ty,
}

/// Detect frame size, rewrite stack traffic to named locals/params, and tidy returns.
pub fn recover_frame(cfg: &mut FunctionCfg, block_stmts: &mut [Vec<Stmt>]) -> FrameRecovery {
    let frame_size = detect_frame_size(block_stmts);
    let fp_off = detect_fp_offset(block_stmts);
    let mut slot_names: BTreeMap<u64, String> = BTreeMap::new();
    collect_slots(block_stmts, frame_size, fp_off, &mut slot_names);

    let mut params = Vec::new();
    let mut param_for_slot: BTreeMap<u64, String> = BTreeMap::new();
    if let Some(entry) = block_stmts.first() {
        recover_params(
            entry,
            frame_size,
            fp_off,
            &mut params,
            &mut param_for_slot,
            &mut slot_names,
        );
    }

    let locals: Vec<String> = slot_names
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    for stmts in block_stmts.iter_mut() {
        *stmts = rewrite_stmts(stmts, frame_size, fp_off, &slot_names, &param_for_slot);
    }

    rewrite_cfg_conditions(cfg, block_stmts);

    let returns_value = block_stmts.iter().any(|b| {
        b.iter()
            .any(|s| matches!(s, Stmt::Return { value: Some(_), .. }))
    });

    for stmts in block_stmts.iter_mut() {
        fold_return_local(stmts);
    }

    FrameRecovery {
        frame_size,
        fp_off,
        objc_method_proto: None,
        swift_proto: None,
        swift_dialect: false,
        locals,
        local_types: BTreeMap::new(),
        params,
        returns_value,
        return_ty: Ty::Undefined,
    }
}

fn detect_frame_size(block_stmts: &[Vec<Stmt>]) -> u64 {
    for stmts in block_stmts {
        for s in stmts {
            if let Stmt::Assign {
                dst: Place::Reg(dst),
                rhs: Expr::BinOp {
                    op: BinOp::Sub,
                    lhs,
                    rhs,
                },
                ..
            } = s
            {
                if dst.reg == 32 {
                    if let (Expr::Var(sp), Expr::Imm(n)) = (lhs.as_ref(), rhs.as_ref()) {
                        if sp.reg == 32 {
                            return *n;
                        }
                    }
                }
            }
        }
    }
    0
}

fn detect_fp_offset(block_stmts: &[Vec<Stmt>]) -> Option<u64> {
    for stmts in block_stmts {
        for s in stmts {
            // add x29, sp, #imm
            if let Stmt::Assign {
                dst: Place::Reg(dst),
                rhs: Expr::BinOp {
                    op: BinOp::Add,
                    lhs,
                    rhs,
                },
                ..
            } = s
            {
                if dst.reg == 29 {
                    if let (Expr::Var(sp), Expr::Imm(n)) = (lhs.as_ref(), rhs.as_ref()) {
                        if sp.reg == 32 {
                            return Some(*n);
                        }
                    }
                }
            }
        }
    }
    None
}

fn collect_slots(
    block_stmts: &[Vec<Stmt>],
    frame_size: u64,
    fp_off: Option<u64>,
    slots: &mut BTreeMap<u64, String>,
) {
    for stmts in block_stmts {
        for s in stmts {
            match s {
                Stmt::Store { addr, .. } => {
                    if let Some(off) = addr_to_sp_off(addr, fp_off) {
                        ensure_slot(slots, frame_size, off);
                    }
                }
                Stmt::Assign {
                    rhs: Expr::Mem(m), ..
                } => {
                    if let Some(off) = parse_mem_frame_offset(m, fp_off) {
                        ensure_slot(slots, frame_size, off);
                    }
                }
                _ => {}
            }
        }
    }
}

fn ensure_slot(slots: &mut BTreeMap<u64, String>, frame_size: u64, sp_off: u64) {
    let ghidra_off = if frame_size > sp_off {
        frame_size - sp_off
    } else {
        sp_off
    };
    slots
        .entry(sp_off)
        .or_insert_with(|| format!("local_{ghidra_off:x}"));
}

fn recover_params(
    entry: &[Stmt],
    frame_size: u64,
    fp_off: Option<u64>,
    params: &mut Vec<String>,
    param_for_slot: &mut BTreeMap<u64, String>,
    slots: &mut BTreeMap<u64, String>,
) {
    for s in entry {
        match s {
            Stmt::Assign {
                dst: Place::Reg(dst),
                rhs: Expr::BinOp { op: BinOp::Sub | BinOp::Add, .. },
                ..
            } if dst.reg == 32 || dst.reg == 29 => continue,
            Stmt::Store {
                addr,
                value: Expr::Var(v),
                ..
            } if v.reg <= 7 => {
                let Some(off) = addr_to_sp_off(addr, fp_off) else {
                    if params.is_empty() {
                        continue;
                    }
                    break;
                };
                if param_for_slot.contains_key(&off) {
                    continue;
                }
                ensure_slot(slots, frame_size, off);
                let name = format!("param_{}", params.len() + 1);
                params.push(name.clone());
                param_for_slot.insert(off, name);
            }
            Stmt::Store { .. } => {
                if !params.is_empty() {
                    break;
                }
            }
            Stmt::Assign {
                dst: Place::Reg(dst),
                ..
            } if dst.reg == 29 || dst.reg == 32 => continue,
            Stmt::Assign { .. } | Stmt::Return { .. } | Stmt::Expr { .. } | Stmt::Raw(_) => {
                if !params.is_empty() {
                    break;
                }
            }
            _ => {}
        }
    }
}

fn rewrite_stmts(
    stmts: &[Stmt],
    frame_size: u64,
    fp_off: Option<u64>,
    slots: &BTreeMap<u64, String>,
    param_for_slot: &BTreeMap<u64, String>,
) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(stmts.len());
    for s in stmts {
        match s {
            Stmt::Assign {
                dst: Place::Reg(dst),
                rhs: Expr::BinOp {
                    op: BinOp::Sub | BinOp::Add,
                    lhs,
                    rhs,
                },
                ..
            } if (dst.reg == 32 || dst.reg == 29)
                && matches!(lhs.as_ref(), Expr::Var(v) if v.reg == 32 || v.reg == 29)
                && matches!(rhs.as_ref(), Expr::Imm(_)) =>
            {
                continue;
            }
            Stmt::Store { addr, value, comment } => {
                if let Some(off) = addr_to_sp_off(addr, fp_off) {
                    let local = slots
                        .get(&off)
                        .cloned()
                        .unwrap_or_else(|| fallback_local(frame_size, off));
                    let rhs = match (param_for_slot.get(&off), value) {
                        (Some(p), Expr::Var(v)) if params_index(p) == Some(v.reg as usize) => {
                            Expr::Name(p.clone())
                        }
                        _ => rewrite_expr(value, slots, frame_size, fp_off),
                    };
                    out.push(Stmt::Assign {
                        dst: Place::Name(local),
                        rhs,
                        comment: comment.clone(),
                    });
                } else {
                    out.push(Stmt::Store {
                        addr: rewrite_expr(addr, slots, frame_size, fp_off),
                        value: rewrite_expr(value, slots, frame_size, fp_off),
                        comment: comment.clone(),
                    });
                }
            }
            Stmt::Assign { dst, rhs, comment } => {
                out.push(Stmt::Assign {
                    dst: dst.clone(),
                    rhs: rewrite_expr(rhs, slots, frame_size, fp_off),
                    comment: comment.clone(),
                });
            }
            Stmt::Return { value, comment } => {
                out.push(Stmt::Return {
                    value: value
                        .as_ref()
                        .map(|v| rewrite_expr(v, slots, frame_size, fp_off)),
                    comment: comment.clone(),
                });
            }
            Stmt::Expr { expr, comment } => {
                out.push(Stmt::Expr {
                    expr: rewrite_expr(expr, slots, frame_size, fp_off),
                    comment: comment.clone(),
                });
            }
            other => out.push(other.clone()),
        }
    }
    out
}

fn rewrite_expr(
    expr: &Expr,
    slots: &BTreeMap<u64, String>,
    frame_size: u64,
    fp_off: Option<u64>,
) -> Expr {
    match expr {
        Expr::Mem(m) => {
            if let Some(off) = parse_mem_frame_offset(m, fp_off) {
                let name = slots
                    .get(&off)
                    .cloned()
                    .unwrap_or_else(|| fallback_local(frame_size, off));
                Expr::Name(name)
            } else {
                Expr::Mem(m.clone())
            }
        }
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op: *op,
            lhs: alloc::boxed::Box::new(rewrite_expr(lhs, slots, frame_size, fp_off)),
            rhs: alloc::boxed::Box::new(rewrite_expr(rhs, slots, frame_size, fp_off)),
        },
        Expr::Call { target, args } => Expr::Call {
            target: target.clone(),
            args: args
                .iter()
                .map(|a| rewrite_expr(a, slots, frame_size, fp_off))
                .collect(),
        },
        Expr::MsgSend {
            receiver,
            selector,
            args,
            super_call,
        } => Expr::MsgSend {
            receiver: alloc::boxed::Box::new(rewrite_expr(
                receiver,
                slots,
                frame_size,
                fp_off,
            )),
            selector: selector.clone(),
            args: args
                .iter()
                .map(|a| rewrite_expr(a, slots, frame_size, fp_off))
                .collect(),
            super_call: *super_call,
        },
        Expr::Var(v) => Expr::Var(*v),
        Expr::Imm(n) => Expr::Imm(*n),
        Expr::Name(n) => Expr::Name(n.clone()),
        Expr::Raw(s) => Expr::Raw(s.clone()),
    }
}

fn fold_return_local(stmts: &mut Vec<Stmt>) {
    let Some(last_ret) = stmts.iter().rposition(|s| matches!(s, Stmt::Return { .. })) else {
        return;
    };
    if last_ret == 0 {
        return;
    }
    let prev = &stmts[last_ret - 1];
    let Stmt::Assign {
        dst: Place::Reg(dst),
        rhs: Expr::Name(local),
        ..
    } = prev
    else {
        return;
    };
    if dst.reg != 0 {
        return;
    }
    let local = local.clone();
    if let Stmt::Return {
        value: Some(Expr::Var(v)),
        comment,
    } = &stmts[last_ret]
    {
        if v.reg == 0 {
            let comment = comment.clone();
            stmts[last_ret] = Stmt::Return {
                value: Some(Expr::Name(local)),
                comment,
            };
            stmts.remove(last_ret - 1);
        }
    }
}

/// Rewrite CFG condition strings using last register→local binds in each block.
pub fn rewrite_cfg_conditions(cfg: &mut FunctionCfg, block_stmts: &[Vec<Stmt>]) {
    for (id, block) in cfg.blocks.iter_mut().enumerate() {
        let Some(stmts) = block_stmts.get(id) else {
            continue;
        };
        let map = reg_to_name_map(stmts);
        if let BlockEnd::Conditional { condition, .. } = &mut block.end {
            *condition = substitute_regs(condition, &map);
        }
    }
}

fn reg_to_name_map(stmts: &[Stmt]) -> BTreeMap<u32, String> {
    let mut map = BTreeMap::new();
    for s in stmts {
        if let Stmt::Assign {
            dst: Place::Reg(v),
            rhs: Expr::Name(n),
            ..
        } = s
        {
            map.insert(v.reg, n.clone());
        }
    }
    map
}

fn substitute_regs(cond: &str, map: &BTreeMap<u32, String>) -> String {
    let mut out = cond.to_string();
    let mut regs: Vec<_> = map.iter().collect();
    regs.sort_by(|a, b| b.0.cmp(a.0));
    for (reg, name) in regs {
        for prefix in ["x", "w"] {
            let tok = format!("{prefix}{reg}");
            out = replace_word(&out, &tok, name);
        }
    }
    out
}

fn replace_word(hay: &str, word: &str, with: &str) -> String {
    let bytes = hay.as_bytes();
    let w = word.as_bytes();
    let mut out = String::with_capacity(hay.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + w.len() <= bytes.len() && &bytes[i..i + w.len()] == w {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after_ok = i + w.len() >= bytes.len() || !is_ident_byte(bytes[i + w.len()]);
            if before_ok && after_ok {
                out.push_str(with);
                i += w.len();
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn addr_to_sp_off(addr: &Expr, fp_off: Option<u64>) -> Option<u64> {
    match addr {
        Expr::Var(v) if v.reg == 32 => Some(0),
        Expr::Var(v) if v.reg == 29 => fp_off,
        Expr::BinOp {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Var(v), Expr::Imm(n)) | (Expr::Imm(n), Expr::Var(v)) if v.reg == 32 => Some(*n),
            (Expr::Var(v), Expr::Imm(n)) | (Expr::Imm(n), Expr::Var(v)) if v.reg == 29 => {
                fp_off.map(|f| f.saturating_add(*n))
            }
            _ => None,
        },
        Expr::BinOp {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Var(v), Expr::Imm(n)) if v.reg == 29 => {
                fp_off.and_then(|f| f.checked_sub(*n))
            }
            (Expr::Var(v), Expr::Imm(n)) if v.reg == 32 => None,
            _ => None,
        },
        _ => None,
    }
}

fn parse_mem_frame_offset(mem: &str, fp_off: Option<u64>) -> Option<u64> {
    let s = mem.trim();
    let inner = s.strip_prefix("*(")?.strip_suffix(')')?;
    let inner = inner.trim().trim_start_matches('(').trim_end_matches(')');
    if inner == "sp" {
        return Some(0);
    }
    if inner == "x29" {
        return fp_off;
    }
    if let Some(rest) = inner.strip_prefix("sp + ").or_else(|| inner.strip_prefix("sp+")) {
        return parse_imm(rest.trim());
    }
    if let Some(rest) = inner.strip_prefix("x29 + ").or_else(|| inner.strip_prefix("x29+")) {
        let n = parse_imm(rest.trim())?;
        return fp_off.map(|f| f.saturating_add(n));
    }
    if let Some(rest) = inner.strip_prefix("x29 - ").or_else(|| inner.strip_prefix("x29-")) {
        let n = parse_imm(rest.trim())?;
        return fp_off.and_then(|f| f.checked_sub(n));
    }
    None
}

fn parse_imm(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn fallback_local(frame_size: u64, sp_off: u64) -> String {
    let g = if frame_size > sp_off {
        frame_size - sp_off
    } else {
        sp_off
    };
    format!("local_{g:x}")
}

fn params_index(name: &str) -> Option<usize> {
    name.strip_prefix("param_")?
        .parse::<usize>()
        .ok()
        .map(|n| n - 1)
}

/// Format a Ghidra-like prototype line (without trailing `{`).
pub fn format_prototype(name: &str, frame: &FrameRecovery) -> String {
    if let Some(proto) = &frame.swift_proto {
        return proto.clone();
    }
    if let Some(proto) = &frame.objc_method_proto {
        return proto.clone();
    }
    let ret = if frame.returns_value {
        frame.return_ty.as_proto_str()
    } else {
        "void"
    };
    if frame.params.is_empty() {
        format!("{ret} {name}(void)")
    } else {
        let args: Vec<String> = frame
            .params
            .iter()
            .map(|p| {
                let ty = frame
                    .local_types
                    .get(p)
                    .copied()
                    .unwrap_or(Ty::Undefined);
                format!("{} {p}", ty.as_proto_str())
            })
            .collect();
        format!("{ret} {name}({})", args.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghidra_local_offset_from_frame() {
        let mut slots = BTreeMap::new();
        ensure_slot(&mut slots, 0x10, 0xc);
        assert_eq!(slots.get(&0xc).map(String::as_str), Some("local_4"));
        ensure_slot(&mut slots, 0x10, 0x8);
        assert_eq!(slots.get(&0x8).map(String::as_str), Some("local_8"));
    }

    #[test]
    fn substitute_w_regs() {
        let mut map = BTreeMap::new();
        map.insert(8, String::from("local_8"));
        map.insert(9, String::from("local_4"));
        assert_eq!(substitute_regs("w8 <= w9", &map), "local_8 <= local_4");
    }

    #[test]
    fn parse_mem_forms() {
        assert_eq!(parse_mem_frame_offset("*(sp)", None), Some(0));
        assert_eq!(parse_mem_frame_offset("*((sp + 0xc))", None), Some(0xc));
        assert_eq!(parse_mem_frame_offset("*(sp + 8)", None), Some(8));
        assert_eq!(
            parse_mem_frame_offset("*((x29 - 4))", Some(0x10)),
            Some(0xc)
        );
    }

    #[test]
    fn fp_relative_slot() {
        let addr = Expr::BinOp {
            op: BinOp::Sub,
            lhs: alloc::boxed::Box::new(Expr::Var(crate::ir::VarId::new(29, 0))),
            rhs: alloc::boxed::Box::new(Expr::Imm(4)),
        };
        assert_eq!(addr_to_sp_off(&addr, Some(0x10)), Some(0xc));
    }
}
