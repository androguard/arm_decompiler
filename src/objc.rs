//! ObjC message-send recognition (M4 / P3).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use apple_metadata::{ObjcRefs, SymbolTable};

use crate::ir::{BinOp, Expr, Place, Stmt};
use crate::locals::FrameRecovery;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgSendKind {
    Normal,
    Super,
}

/// Classification of an `objc_msgSend*` call target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsgSendClass {
    pub kind: MsgSendKind,
    /// Selector baked into optimized stubs (`_objc_msgSend$hello:`).
    pub fixed_selector: Option<String>,
}

/// Classify `bl` targets: `_objc_msgSend`, `_objc_msgSend$sel:`, Super, stret, …
pub fn classify_msg_send(target: &str) -> Option<MsgSendClass> {
    let n = target
        .trim()
        .trim_matches('"')
        .trim_start_matches('_');
    if let Some(sel) = n.strip_prefix("objc_msgSendSuper2$") {
        return Some(MsgSendClass {
            kind: MsgSendKind::Super,
            fixed_selector: Some(sel.into()),
        });
    }
    if let Some(sel) = n.strip_prefix("objc_msgSendSuper$") {
        return Some(MsgSendClass {
            kind: MsgSendKind::Super,
            fixed_selector: Some(sel.into()),
        });
    }
    if n.starts_with("objc_msgSendSuper") {
        return Some(MsgSendClass {
            kind: MsgSendKind::Super,
            fixed_selector: None,
        });
    }
    if let Some(sel) = n.strip_prefix("objc_msgSend$") {
        return Some(MsgSendClass {
            kind: MsgSendKind::Normal,
            fixed_selector: Some(sel.into()),
        });
    }
    if n.starts_with("objc_msgSend") {
        return Some(MsgSendClass {
            kind: MsgSendKind::Normal,
            fixed_selector: None,
        });
    }
    None
}

/// Format `[recv sel]` / `[recv foo:a bar:b]`.
pub fn format_objc_message(recv: &str, sel: &str, args: &[String]) -> String {
    if !sel.contains(':') {
        return format!("[{recv} {sel}]");
    }
    let mut out = format!("[{recv}");
    let mut arg_i = 0;
    let mut rest = sel;
    while let Some(idx) = rest.find(':') {
        let kw = &rest[..idx];
        out.push(' ');
        out.push_str(kw);
        out.push(':');
        if arg_i < args.len() {
            out.push_str(&args[arg_i]);
            arg_i += 1;
        }
        rest = &rest[idx + 1..];
    }
    out.push(']');
    out
}

/// Look up a selector name by selref slot or methname vaddr.
///
/// Order: local `ObjcRefs`, optional external/DSC map, then `SymbolTable`
/// (`__objc_methname` indexed by VA).
pub fn resolve_selector_name(
    refs: Option<&ObjcRefs>,
    symbols: Option<&SymbolTable>,
    sel_map: Option<&[(u64, alloc::string::String)]>,
    va: u64,
) -> Option<String> {
    if let Some(refs) = refs {
        for r in &refs.sel_refs {
            if r.slot_vaddr == va || r.target_vaddr == Some(va) {
                if !r.name.is_empty() && r.name != "?" && !r.name.starts_with("sel_") {
                    return Some(r.name.clone());
                }
                // Placeholder — try map below, else keep placeholder as last resort.
                if let Some(map) = sel_map {
                    if let Some((_, n)) = map.iter().find(|(a, _)| *a == va || r.target_vaddr == Some(*a))
                    {
                        return Some(n.clone());
                    }
                }
                return Some(r.name.clone());
            }
        }
    }
    if let Some(map) = sel_map {
        if let Some((_, n)) = map.iter().find(|(a, _)| *a == va) {
            return Some(n.clone());
        }
    }
    if let Some(syms) = symbols {
        if let Some(n) = syms.get_symbol_str_at_vaddr(va) {
            // Prefer methname-like strings (contain ':' or look like selectors).
            if n.contains(':') || n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
            {
                return Some(n.trim_start_matches('_').to_string());
            }
        }
    }
    None
}

fn selector_from_expr(
    expr: &Expr,
    refs: Option<&ObjcRefs>,
    symbols: Option<&SymbolTable>,
    sel_map: Option<&[(u64, alloc::string::String)]>,
) -> String {
    match expr {
        Expr::Imm(va) => resolve_selector_name(refs, symbols, sel_map, *va)
            .unwrap_or_else(|| format!("sel_{va:x}")),
        Expr::Name(n) => n.clone(),
        other => other.to_c(),
    }
}

/// Lower `objc_storeStrong(&slot, val)` to `slot = val` using frame naming.
pub fn lower_objc_store_strong(block_stmts: &mut [Vec<Stmt>], frame: &FrameRecovery) {
    let Some(fp_off) = frame.fp_off else {
        return;
    };
    let frame_size = frame.frame_size;
    if frame_size == 0 {
        return;
    }

    for stmts in block_stmts.iter_mut() {
        let mut name_fp: BTreeMap<String, u64> = BTreeMap::new();
        let mut reg_fp: BTreeMap<u32, u64> = BTreeMap::new();
        let mut last_addr_delta: Option<u64> = None;
        let mut out = Vec::with_capacity(stmts.len());

        for s in stmts.iter() {
            match s {
                Stmt::Assign {
                    dst: Place::Name(dst),
                    rhs,
                    ..
                } => {
                    if let Some(d) = fp_delta(rhs) {
                        name_fp.insert(dst.clone(), d);
                        last_addr_delta = Some(d);
                    }
                    out.push(s.clone());
                }
                Stmt::Assign {
                    dst: Place::Reg(v),
                    rhs,
                    comment,
                } => {
                    if let Some(d) = fp_delta(rhs) {
                        reg_fp.insert(v.reg, d);
                        last_addr_delta = Some(d);
                        out.push(s.clone());
                    } else if let Expr::Name(n) = rhs {
                        if let Some(&d) = name_fp.get(n) {
                            reg_fp.insert(v.reg, d);
                            last_addr_delta = Some(d);
                        }
                        out.push(s.clone());
                    } else if let Expr::Call { target, args } = rhs {
                        if is_store_strong(target) && args.len() >= 2 {
                            if let Some(local) = resolve_strong_slot(
                                &args[0],
                                &name_fp,
                                &reg_fp,
                                last_addr_delta,
                                frame_size,
                                fp_off,
                            ) {
                                out.push(Stmt::Assign {
                                    dst: Place::Name(local),
                                    rhs: args[1].clone(),
                                    comment: comment.clone(),
                                });
                            }
                            // Drop unresolved storeStrong (ARC noise).
                            // x0 result of storeStrong is void — clear reg_fp for x0.
                            reg_fp.remove(&v.reg);
                        } else {
                            reg_fp.remove(&v.reg);
                            out.push(s.clone());
                        }
                    } else {
                        reg_fp.remove(&v.reg);
                        out.push(s.clone());
                    }
                }
                Stmt::Expr {
                    expr: Expr::Call { target, args },
                    comment,
                } if is_store_strong(target) && args.len() >= 2 => {
                    if let Some(local) = resolve_strong_slot(
                        &args[0],
                        &name_fp,
                        &reg_fp,
                        last_addr_delta,
                        frame_size,
                        fp_off,
                    ) {
                        out.push(Stmt::Assign {
                            dst: Place::Name(local),
                            rhs: args[1].clone(),
                            comment: comment.clone(),
                        });
                    }
                }
                other => out.push(other.clone()),
            }
        }
        *stmts = out;
    }
}

fn is_store_strong(target: &str) -> bool {
    let n = target.trim().trim_matches('"').trim_start_matches('_');
    n.starts_with("objc_storeStrong")
}

fn fp_delta(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::BinOp {
            op: BinOp::Sub,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Var(v) if v.reg == 29) => match rhs.as_ref() {
            Expr::Imm(n) => Some(*n),
            _ => None,
        },
        Expr::BinOp {
            op: BinOp::Add,
            lhs,
            rhs,
        } if matches!(lhs.as_ref(), Expr::Var(v) if v.reg == 29) => match rhs.as_ref() {
            Expr::Imm(n) => {
                let i = *n as i64;
                if i < 0 {
                    Some((-i) as u64)
                } else {
                    None
                }
            }
            _ => None,
        },
        _ => None,
    }
}

fn local_name_for_fp_delta(frame_size: u64, fp_off: u64, delta: u64) -> Option<String> {
    let sp_off = fp_off.checked_sub(delta)?;
    let g = if frame_size > sp_off {
        frame_size - sp_off
    } else {
        sp_off
    };
    Some(format!("local_{g:x}"))
}

fn resolve_strong_slot(
    addr: &Expr,
    name_fp: &BTreeMap<String, u64>,
    reg_fp: &BTreeMap<u32, u64>,
    last_addr_delta: Option<u64>,
    frame_size: u64,
    fp_off: u64,
) -> Option<String> {
    let delta = match addr {
        Expr::Name(n) => name_fp.get(n).copied(),
        Expr::Var(v) => reg_fp.get(&v.reg).copied().or(last_addr_delta),
        other => fp_delta(other),
    }?;
    local_name_for_fp_delta(frame_size, fp_off, delta)
}

/// Prefer `self` for ObjC instance methods when `param_1` is the receiver.
pub fn rename_objc_self(block_stmts: &mut [Vec<Stmt>], frame: &mut FrameRecovery) {
    if frame.params.first().map(String::as_str) != Some("param_1") {
        return;
    }
    // Only when the body looks ObjC-ish (msgSend or storeStrong already lowered).
    let has_objc = block_stmts.iter().flatten().any(|s| match s {
        Stmt::Assign {
            rhs: Expr::MsgSend { .. },
            ..
        }
        | Stmt::Expr {
            expr: Expr::MsgSend { .. },
            ..
        } => true,
        Stmt::Assign {
            rhs: Expr::Call { target, .. },
            ..
        }
        | Stmt::Expr {
            expr: Expr::Call { target, .. },
            ..
        } => classify_msg_send(target).is_some() || is_store_strong(target),
        _ => false,
    });
    if !has_objc {
        return;
    }
    frame.params[0] = String::from("self");
    rename_names_in_blocks(block_stmts, "param_1", "self");
}

/// Rename all `from` name occurrences in IR to `to`.
pub fn rename_names_in_blocks(block_stmts: &mut [Vec<Stmt>], from: &str, to: &str) {
    for stmts in block_stmts.iter_mut() {
        for s in stmts.iter_mut() {
            rename_name_in_stmt(s, from, to);
        }
    }
}

fn rename_name_in_stmt(s: &mut Stmt, from: &str, to: &str) {
    match s {
        Stmt::Assign { dst, rhs, .. } => {
            if let Place::Name(n) = dst {
                if n == from {
                    *n = to.into();
                }
            }
            *rhs = rename_name_in_expr(rhs.clone(), from, to);
        }
        Stmt::Store { addr, value, .. } => {
            *addr = rename_name_in_expr(addr.clone(), from, to);
            *value = rename_name_in_expr(value.clone(), from, to);
        }
        Stmt::Expr { expr, .. } => {
            *expr = rename_name_in_expr(expr.clone(), from, to);
        }
        Stmt::Return { value: Some(v), .. } => {
            *v = rename_name_in_expr(v.clone(), from, to);
        }
        _ => {}
    }
}

fn rename_name_in_expr(expr: Expr, from: &str, to: &str) -> Expr {
    match expr {
        Expr::Name(n) if n == from => Expr::Name(to.into()),
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: alloc::boxed::Box::new(rename_name_in_expr(*lhs, from, to)),
            rhs: alloc::boxed::Box::new(rename_name_in_expr(*rhs, from, to)),
        },
        Expr::Call { target, args } => Expr::Call {
            target,
            args: args
                .into_iter()
                .map(|a| rename_name_in_expr(a, from, to))
                .collect(),
        },
        Expr::MsgSend {
            receiver,
            selector,
            args,
            super_call,
        } => Expr::MsgSend {
            receiver: alloc::boxed::Box::new(rename_name_in_expr(*receiver, from, to)),
            selector,
            args: args
                .into_iter()
                .map(|a| rename_name_in_expr(a, from, to))
                .collect(),
            super_call,
        },
        other => other,
    }
}

/// If `local = self` (transitively) then `[local sel:…]` → `[self sel:…]`.
pub fn fold_objc_self_receiver(block_stmts: &mut [Vec<Stmt>]) {
    // Track across blocks: ARC slot init and the message send often land in
    // different CFG nodes after splitting.
    let mut self_names: BTreeMap<String, ()> = BTreeMap::new();
    self_names.insert(String::from("self"), ());
    for stmts in block_stmts.iter_mut() {
        for s in stmts.iter_mut() {
            let rewrite_to_self = match s {
                Stmt::Assign {
                    dst: Place::Name(dst),
                    rhs: Expr::Name(src),
                    ..
                } if self_names.contains_key(src) => {
                    self_names.insert(dst.clone(), ());
                    src != "self"
                }
                Stmt::Assign {
                    dst: Place::Name(dst),
                    ..
                } => {
                    self_names.remove(dst);
                    false
                }
                _ => false,
            };
            if rewrite_to_self {
                if let Stmt::Assign { rhs, .. } = s {
                    *rhs = Expr::Name(String::from("self"));
                }
            }
            if let Stmt::Assign {
                rhs: Expr::MsgSend { receiver, .. },
                ..
            }
            | Stmt::Expr {
                expr: Expr::MsgSend { receiver, .. },
                ..
            } = s
            {
                if let Expr::Name(n) = receiver.as_ref() {
                    if n != "self" && self_names.contains_key(n) {
                        *receiver = alloc::boxed::Box::new(Expr::Name(String::from("self")));
                    }
                }
            }
        }
    }
}

/// Drop ARC runtime helpers that obscure message sends (`objc_storeStrong`, …).
pub fn strip_objc_runtime_noise(block_stmts: &mut [Vec<Stmt>]) {
    for stmts in block_stmts.iter_mut() {
        stmts.retain(|s| !is_runtime_noise(s));
    }
}

fn is_runtime_noise(s: &Stmt) -> bool {
    match s {
        Stmt::Assign {
            rhs: Expr::Call { target, .. },
            ..
        }
        | Stmt::Expr {
            expr: Expr::Call { target, .. },
            ..
        } => {
            let n = target.trim_start_matches('_');
            n.starts_with("objc_storeStrong")
                || n.starts_with("objc_retain")
                || n.starts_with("objc_release")
                || n.starts_with("objc_autorelease")
                || n.starts_with("objc_loadWeak")
                || n.starts_with("objc_destroyWeak")
                || n == "objc_retainBlock"
                || n == "Block_copy"
                || n == "Block_release"
                || n == "Block_object_assign"
                || n == "Block_object_dispose"
        }
        _ => false,
    }
}

/// Context for selector name resolution (local refs + optional DSC map + symbols).
#[derive(Clone, Copy, Default)]
pub struct SelResolveCtx<'a> {
    pub refs: Option<&'a ObjcRefs>,
    pub symbols: Option<&'a SymbolTable>,
    pub sel_map: Option<&'a [(u64, String)]>,
}

/// Rewrite `objc_msgSend(recv, sel, …)` / `objc_msgSend$sel:(recv, …)` into [`Expr::MsgSend`].
pub fn rewrite_msg_sends(block_stmts: &mut [Vec<Stmt>], ctx: SelResolveCtx<'_>) {
    for stmts in block_stmts.iter_mut() {
        for s in stmts.iter_mut() {
            rewrite_stmt(s, ctx);
        }
    }
}

fn rewrite_stmt(s: &mut Stmt, ctx: SelResolveCtx<'_>) {
    match s {
        Stmt::Assign { rhs, .. } => {
            *rhs = rewrite_expr(rhs.clone(), ctx);
        }
        Stmt::Store { addr, value, .. } => {
            *addr = rewrite_expr(addr.clone(), ctx);
            *value = rewrite_expr(value.clone(), ctx);
        }
        Stmt::Expr { expr, .. } => {
            *expr = rewrite_expr(expr.clone(), ctx);
        }
        Stmt::Return { value, .. } => {
            if let Some(v) = value {
                *v = rewrite_expr(v.clone(), ctx);
            }
        }
        _ => {}
    }
}

fn rewrite_expr(expr: Expr, ctx: SelResolveCtx<'_>) -> Expr {
    match expr {
        Expr::Call { target, args } => {
            if let Some(class) = classify_msg_send(&target) {
                if let Some(sel) = class.fixed_selector {
                    // Optimized stub: x0 = recv; message args follow (no _cmd).
                    // clang -O0 may leave dead values in mid regs — keep last N by arity.
                    if !args.is_empty() {
                        let mut args = args;
                        let receiver = alloc::boxed::Box::new(args.remove(0));
                        let n = sel.matches(':').count();
                        let msg_args = if n > 0 && args.len() > n {
                            args.split_off(args.len() - n)
                        } else {
                            args
                        };
                        return Expr::MsgSend {
                            receiver,
                            selector: sel,
                            args: msg_args,
                            super_call: class.kind == MsgSendKind::Super,
                        };
                    }
                } else if args.len() >= 2 {
                    let mut args = args;
                    let receiver = alloc::boxed::Box::new(args.remove(0));
                    let sel_expr = args.remove(0);
                    let selector = selector_from_expr(
                        &sel_expr,
                        ctx.refs,
                        ctx.symbols,
                        ctx.sel_map,
                    );
                    return Expr::MsgSend {
                        receiver,
                        selector,
                        args,
                        super_call: class.kind == MsgSendKind::Super,
                    };
                }
            }
            Expr::Call {
                target,
                args: args
                    .into_iter()
                    .map(|a| rewrite_expr(a, ctx))
                    .collect(),
            }
        }
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: alloc::boxed::Box::new(rewrite_expr(*lhs, ctx)),
            rhs: alloc::boxed::Box::new(rewrite_expr(*rhs, ctx)),
        },
        Expr::MsgSend {
            receiver,
            selector,
            args,
            super_call,
        } => Expr::MsgSend {
            receiver: alloc::boxed::Box::new(rewrite_expr(*receiver, ctx)),
            selector,
            args: args
                .into_iter()
                .map(|a| rewrite_expr(a, ctx))
                .collect(),
            super_call,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::VarId;

    #[test]
    fn classifies_msgsend_variants() {
        assert_eq!(
            classify_msg_send("_objc_msgSend").map(|c| c.kind),
            Some(MsgSendKind::Normal)
        );
        let tagged = classify_msg_send("_objc_msgSend$hello:").unwrap();
        assert_eq!(tagged.kind, MsgSendKind::Normal);
        assert_eq!(tagged.fixed_selector.as_deref(), Some("hello:"));
        assert_eq!(
            classify_msg_send("_objc_msgSendSuper2").map(|c| c.kind),
            Some(MsgSendKind::Super)
        );
        assert_eq!(classify_msg_send("_printf"), None);
    }

    #[test]
    fn formats_bracket_messages() {
        assert_eq!(format_objc_message("self", "hello", &[]), "[self hello]");
        assert_eq!(
            format_objc_message("self", "hello:", &["x".into()]),
            "[self hello:x]"
        );
        assert_eq!(
            format_objc_message("self", "sum:with:", &["a".into(), "b".into()]),
            "[self sum:a with:b]"
        );
    }

    #[test]
    fn lowers_store_strong_to_local_assign() {
        let frame = FrameRecovery {
            frame_size: 0x50,
            fp_off: Some(0x40),
            objc_method_proto: None,
            swift_proto: None,
            swift_dialect: false,
            locals: alloc::vec![String::from("local_18")],
            local_types: alloc::collections::BTreeMap::new(),
            params: alloc::vec![String::from("param_1")],
            returns_value: true,
            return_ty: crate::types::Ty::Undefined,
        };
        // fp-8 → sp 0x38 → ghidra local_18
        let mut blocks = alloc::vec![alloc::vec![
            Stmt::Assign {
                dst: Place::Name(String::from("local_28")),
                rhs: Expr::BinOp {
                    op: BinOp::Sub,
                    lhs: alloc::boxed::Box::new(Expr::Var(VarId::from_x(29))),
                    rhs: alloc::boxed::Box::new(Expr::Imm(8)),
                },
                comment: None,
            },
            Stmt::Assign {
                dst: Place::Name(String::from("local_18")),
                rhs: Expr::Imm(0),
                comment: None,
            },
            Stmt::Assign {
                dst: Place::Reg(VarId::from_x(0)),
                rhs: Expr::Call {
                    target: String::from("_objc_storeStrong"),
                    args: alloc::vec![
                        Expr::Name(String::from("local_28")),
                        Expr::Name(String::from("param_1")),
                    ],
                },
                comment: None,
            },
        ]];
        lower_objc_store_strong(&mut blocks, &frame);
        assert_eq!(blocks[0].len(), 3);
        match &blocks[0][2] {
            Stmt::Assign {
                dst: Place::Name(n),
                rhs: Expr::Name(v),
                ..
            } => {
                assert_eq!(n, "local_18");
                assert_eq!(v, "param_1");
            }
            other => panic!("expected local_18 = param_1, got {other:?}"),
        }
    }

    #[test]
    fn lowers_store_strong_when_addr_still_in_x0() {
        let frame = FrameRecovery {
            frame_size: 0x50,
            fp_off: Some(0x40),
            objc_method_proto: None,
            swift_proto: None,
            swift_dialect: false,
            locals: alloc::vec![String::from("local_18")],
            local_types: alloc::collections::BTreeMap::new(),
            params: alloc::vec![String::from("param_1")],
            returns_value: true,
            return_ty: crate::types::Ty::Undefined,
        };
        let mut blocks = alloc::vec![alloc::vec![
            Stmt::Assign {
                dst: Place::Name(String::from("local_28")),
                rhs: Expr::BinOp {
                    op: BinOp::Sub,
                    lhs: alloc::boxed::Box::new(Expr::Var(VarId::from_x(29))),
                    rhs: alloc::boxed::Box::new(Expr::Imm(8)),
                },
                comment: None,
            },
            Stmt::Assign {
                dst: Place::Reg(VarId::from_x(0)),
                rhs: Expr::Call {
                    target: String::from("_objc_storeStrong"),
                    args: alloc::vec![
                        Expr::Var(VarId::from_x(0)),
                        Expr::Name(String::from("param_1")),
                    ],
                },
                comment: None,
            },
        ]];
        lower_objc_store_strong(&mut blocks, &frame);
        match &blocks[0][1] {
            Stmt::Assign {
                dst: Place::Name(n),
                rhs: Expr::Name(v),
                ..
            } => {
                assert_eq!(n, "local_18");
                assert_eq!(v, "param_1");
            }
            other => panic!("expected local_18 = param_1, got {other:?}"),
        }
    }

    #[test]
    fn rewrites_tagged_stub() {
        let mut blocks = alloc::vec![alloc::vec![Stmt::Assign {
            dst: Place::Reg(VarId::from_x(0)),
            rhs: Expr::Call {
                target: String::from("_objc_msgSend$hello:"),
                args: alloc::vec![
                    Expr::Name(String::from("self")),
                    Expr::Name(String::from("dead")),
                    Expr::Imm(3),
                ],
            },
            comment: None,
        }]];
        rewrite_msg_sends(&mut blocks, SelResolveCtx::default());
        match &blocks[0][0] {
            Stmt::Assign {
                rhs:
                    Expr::MsgSend {
                        receiver,
                        selector,
                        args,
                        ..
                    },
                ..
            } => {
                assert_eq!(receiver.to_c(), "self");
                assert_eq!(selector, "hello:");
                assert_eq!(args.len(), 1);
                assert_eq!(args[0], Expr::Imm(3));
            }
            other => panic!("expected MsgSend, got {other:?}"),
        }
    }

    #[test]
    fn folds_self_through_local_alias() {
        let mut blocks = alloc::vec![alloc::vec![
            Stmt::Assign {
                dst: Place::Name(String::from("local_48")),
                rhs: Expr::Name(String::from("self")),
                comment: None,
            },
            Stmt::Assign {
                dst: Place::Name(String::from("local_18")),
                rhs: Expr::Imm(0),
                comment: None,
            },
            Stmt::Assign {
                dst: Place::Name(String::from("local_18")),
                rhs: Expr::Name(String::from("self")),
                comment: None,
            },
            Stmt::Assign {
                dst: Place::Reg(VarId::from_x(0)),
                rhs: Expr::MsgSend {
                    receiver: alloc::boxed::Box::new(Expr::Name(String::from("local_18"))),
                    selector: String::from("hello:"),
                    args: alloc::vec![Expr::Imm(1)],
                    super_call: false,
                },
                comment: None,
            },
        ]];
        fold_objc_self_receiver(&mut blocks);
        match &blocks[0][3] {
            Stmt::Assign {
                rhs: Expr::MsgSend { receiver, .. },
                ..
            } => assert_eq!(receiver.to_c(), "self"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn resolve_uses_sel_map_for_placeholder() {
        let refs = ObjcRefs {
            sel_refs: alloc::vec![apple_metadata::ObjcRef {
                slot_vaddr: 0x1000,
                target_vaddr: Some(0x2000),
                name: String::from("sel_0x2000"),
            }],
            ..Default::default()
        };
        let map = [(0x2000u64, String::from("description"))];
        assert_eq!(
            resolve_selector_name(Some(&refs), None, Some(&map), 0x1000).as_deref(),
            Some("description")
        );
        assert_eq!(
            resolve_selector_name(None, None, Some(&map), 0x2000).as_deref(),
            Some("description")
        );
    }
}
