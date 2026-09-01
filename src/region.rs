//! Region maker: structured control flow from CFG (dex-decompiler analogue).

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::cfg::{BlockEnd, BlockId, FunctionCfg};
use crate::ir::Stmt;

#[derive(Debug, Clone)]
pub enum Region {
    Block(BlockId),
    Seq(Vec<Region>),
    If {
        condition: String,
        then_branch: Box<Region>,
        else_branch: Box<Region>,
    },
    Loop {
        header: BlockId,
        body: Box<Region>,
        /// When set, emit `while (cond)` instead of `while (true)`.
        condition: Option<String>,
    },
    /// `do { body } while (cond);`
    DoWhile {
        body: Box<Region>,
        condition: String,
    },
    Break,
    Continue,
}

/// Build a region tree. Heuristic SESE-style: diamond if/else with join, back-edge loops.
pub fn build_regions(cfg: &FunctionCfg, block_stmts: &[Vec<Stmt>]) -> Region {
    if cfg.blocks.is_empty() {
        return Region::Seq(Vec::new());
    }
    let mut visited = alloc::vec![false; cfg.blocks.len()];
    let mut parts = Vec::new();
    build_from(cfg, block_stmts, cfg.entry, &mut visited, &mut parts, None);
    // Append any unvisited blocks linearly (fallback).
    for i in 0..visited.len() {
        if !visited[i] {
            parts.push(Region::Block(i));
            visited[i] = true;
        }
    }
    if parts.len() == 1 {
        parts.pop().unwrap()
    } else {
        Region::Seq(parts)
    }
}

fn build_from(
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    id: BlockId,
    visited: &mut [bool],
    parts: &mut Vec<Region>,
    stop_at: Option<BlockId>,
) {
    build_from_loop(cfg, block_stmts, id, visited, parts, stop_at, None);
}

#[derive(Clone, Copy)]
struct LoopCtx {
    header: BlockId,
    exit: BlockId,
}

fn build_from_loop(
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    mut id: BlockId,
    visited: &mut [bool],
    parts: &mut Vec<Region>,
    stop_at: Option<BlockId>,
    loop_ctx: Option<LoopCtx>,
) {
    while id < cfg.blocks.len() && !visited[id] {
        if stop_at == Some(id) {
            return;
        }
        if let Some(lc) = loop_ctx {
            if id == lc.exit {
                return;
            }
            if id == lc.header {
                // back-edge absorbed by while/do
                return;
            }
        }
        visited[id] = true;

        if is_trivial_goto(cfg, block_stmts, id) {
            if let BlockEnd::Goto(t) = cfg.blocks[id].end {
                if let Some(lc) = loop_ctx {
                    if t == lc.exit {
                        parts.push(Region::Break);
                        return;
                    }
                    if t == lc.header {
                        parts.push(Region::Continue);
                        return;
                    }
                }
                id = t;
                continue;
            }
        }

        match &cfg.blocks[id].end {
            BlockEnd::Conditional {
                condition,
                branch_target,
                fall_through,
            } => {
                let cond = condition.clone();
                let then_id = *branch_target;
                let else_id = *fall_through;

                // Nested break/continue inside loop body (before treating as new while).
                if let Some(lc) = loop_ctx {
                    if !cfg.loop_headers.contains(&id) {
                        let then_start = skip_trivial(cfg, block_stmts, then_id);
                        let else_start = skip_trivial(cfg, block_stmts, else_id);
                        let join = find_join_in_loop(cfg, then_start, else_start, lc);
                        parts.push(Region::Block(id));
                        // Stop each arm at the join so shared tails (e.g. i++) emit once.
                        let then_r = build_branch_in_loop(
                            cfg,
                            block_stmts,
                            then_start,
                            join,
                            visited,
                            lc,
                        );
                        let else_r = build_branch_in_loop(
                            cfg,
                            block_stmts,
                            else_start,
                            join,
                            visited,
                            lc,
                        );
                        mark_path_stubs(cfg, block_stmts, then_id, then_start, visited);
                        mark_path_stubs(cfg, block_stmts, else_id, else_start, visited);
                        parts.push(Region::If {
                            condition: cond,
                            then_branch: Box::new(then_r),
                            else_branch: Box::new(else_r),
                        });
                        match join {
                            Some(j) => {
                                id = j;
                                continue;
                            }
                            None => return,
                        }
                    }
                }

                if cfg.loop_headers.contains(&id) {
                    let then_loops = path_returns_to(cfg, then_id, id);
                    let else_loops = path_returns_to(cfg, else_id, id);
                    let (body_id, exit_id, loop_cond) = if then_loops && !else_loops {
                        (then_id, else_id, Some(cond.clone()))
                    } else if else_loops && !then_loops {
                        (else_id, then_id, Some(invert_cond(&cond)))
                    } else if else_id <= id {
                        (then_id, else_id, Some(cond.clone()))
                    } else if then_id <= id {
                        (else_id, then_id, Some(invert_cond(&cond)))
                    } else {
                        (else_id, then_id, Some(invert_cond(&cond)))
                    };
                    let mut body_parts = Vec::new();
                    let mut body_visited = visited.to_vec();
                    let lc = LoopCtx {
                        header: id,
                        exit: exit_id,
                    };
                    build_from_loop(
                        cfg,
                        block_stmts,
                        body_id,
                        &mut body_visited,
                        &mut body_parts,
                        Some(exit_id),
                        Some(lc),
                    );
                    for (i, v) in body_visited.iter().enumerate() {
                        if *v && i != id && i != exit_id {
                            visited[i] = true;
                        }
                    }
                    let body = if body_parts.len() == 1 {
                        body_parts.pop().unwrap()
                    } else {
                        Region::Seq(body_parts)
                    };
                    parts.push(Region::Loop {
                        header: id,
                        body: Box::new(body),
                        condition: loop_cond,
                    });
                    id = exit_id;
                    continue;
                }

                let then_start = skip_trivial(cfg, block_stmts, then_id);
                let else_start = skip_trivial(cfg, block_stmts, else_id);
                let join = find_join(cfg, then_start, else_start);

                parts.push(Region::Block(id));

                let then_r = build_branch(cfg, block_stmts, then_start, join, visited);
                let else_r = build_branch(cfg, block_stmts, else_start, join, visited);
                mark_path_stubs(cfg, block_stmts, then_id, then_start, visited);
                mark_path_stubs(cfg, block_stmts, else_id, else_start, visited);

                parts.push(Region::If {
                    condition: cond,
                    then_branch: Box::new(then_r),
                    else_branch: Box::new(else_r),
                });

                match join {
                    Some(j) => id = j,
                    None => break,
                }
            }
            BlockEnd::Goto(t) if cfg.loop_headers.contains(t) && *t <= id => {
                if let Some(lc) = loop_ctx {
                    if *t == lc.header {
                        parts.push(Region::Block(id));
                        return;
                    }
                }
                parts.push(Region::Block(id));
                break;
            }
            BlockEnd::Goto(t) => {
                if let Some(lc) = loop_ctx {
                    if *t == lc.exit {
                        if !block_stmts.get(id).map(|s| s.is_empty()).unwrap_or(true) {
                            parts.push(Region::Block(id));
                        }
                        parts.push(Region::Break);
                        return;
                    }
                    if *t == lc.header {
                        if !block_stmts.get(id).map(|s| s.is_empty()).unwrap_or(true) {
                            parts.push(Region::Block(id));
                        }
                        // continue is implicit at end of while body
                        return;
                    }
                }
                if let Some((latch, cond, exit)) = do_while_info(cfg, *t) {
                    if !block_stmts.get(id).map(|s| s.is_empty()).unwrap_or(true) {
                        parts.push(Region::Block(id));
                    }
                    let mut body_parts = Vec::new();
                    let mut ids = loop_body_blocks(cfg, *t, Some(*t), Some(exit));
                    if !ids.contains(&latch) {
                        ids.push(latch);
                        ids.sort_unstable();
                    }
                    for &bid in &ids {
                        if bid == exit {
                            continue;
                        }
                        if is_trivial_goto(cfg, block_stmts, bid) {
                            visited[bid] = true;
                            continue;
                        }
                        visited[bid] = true;
                        body_parts.push(Region::Block(bid));
                    }
                    let body = if body_parts.len() == 1 {
                        body_parts.pop().unwrap()
                    } else {
                        Region::Seq(body_parts)
                    };
                    parts.push(Region::DoWhile {
                        body: Box::new(body),
                        condition: cond,
                    });
                    id = exit;
                    continue;
                }
                parts.push(Region::Block(id));
                if stop_at == Some(*t) {
                    return;
                }
                id = *t;
            }
            BlockEnd::Exit | BlockEnd::FallThrough => {
                parts.push(Region::Block(id));
                break;
            }
        }
    }
}

/// Like [`build_branch`], but recognizes `break`/`continue` against `lc`.
fn build_branch_in_loop(
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    start: BlockId,
    join: Option<BlockId>,
    visited: &mut [bool],
    lc: LoopCtx,
) -> Region {
    if join == Some(start) {
        return Region::Seq(Vec::new());
    }
    if start == lc.exit || skip_trivial(cfg, block_stmts, start) == lc.exit {
        return Region::Break;
    }
    if start == lc.header {
        return Region::Continue;
    }
    if is_trivial_goto(cfg, block_stmts, start) {
        if let BlockEnd::Goto(t) = cfg.blocks[start].end {
            if t == lc.exit {
                visited[start] = true;
                return Region::Break;
            }
            if t == lc.header {
                visited[start] = true;
                return Region::Continue;
            }
            if join == Some(t) {
                visited[start] = true;
                return Region::Seq(Vec::new());
            }
        }
    }
    if visited.get(start).copied().unwrap_or(false) {
        if block_stmts.get(start).is_some_and(|s| !s.is_empty()) {
            return Region::Block(start);
        }
        return Region::Seq(Vec::new());
    }
    let mut parts = Vec::new();
    let stop = join.or(Some(lc.exit));
    build_from_loop(
        cfg,
        block_stmts,
        start,
        visited,
        &mut parts,
        stop,
        Some(lc),
    );
    if parts.is_empty() {
        Region::Seq(Vec::new())
    } else if parts.len() == 1 {
        parts.pop().unwrap()
    } else {
        Region::Seq(parts)
    }
}

fn find_join_in_loop(
    cfg: &FunctionCfg,
    a: BlockId,
    b: BlockId,
    lc: LoopCtx,
) -> Option<BlockId> {
    if a == b {
        return Some(a);
    }
    // Prefer forward join that is not the loop exit/header.
    let join = find_join(cfg, a, b)?;
    if join == lc.exit || join == lc.header {
        // Fall back: the non-break path's continuation after the if.
        if a != lc.exit && a != lc.header && path_returns_to(cfg, a, lc.header) {
            return Some(a);
        }
        if b != lc.exit && b != lc.header && path_returns_to(cfg, b, lc.header) {
            return Some(b);
        }
        return None;
    }
    Some(join)
}

fn loop_body_blocks(
    cfg: &FunctionCfg,
    start: BlockId,
    back_to: Option<BlockId>,
    stop_at: Option<BlockId>,
) -> Vec<BlockId> {
    let mut seen = BTreeSet::new();
    let mut stack = alloc::vec![start];
    while let Some(n) = stack.pop() {
        // Don't re-enter the header via a back-edge, and don't walk the exit.
        if stop_at == Some(n) {
            continue;
        }
        if back_to == Some(n) && n != start && seen.contains(&start) {
            continue;
        }
        if !seen.insert(n) {
            continue;
        }
        for s in successors(cfg, n) {
            if back_to == Some(s) {
                continue;
            }
            if stop_at == Some(s) {
                continue;
            }
            stack.push(s);
        }
    }
    let mut ids: Vec<_> = seen.into_iter().collect();
    ids.sort_unstable();
    ids
}

fn build_branch(
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    start: BlockId,
    join: Option<BlockId>,
    visited: &mut [bool],
) -> Region {
    if join == Some(start) {
        return Region::Seq(Vec::new());
    }
    // Shared sink already claimed by another branch — still surface its stmts.
    if visited.get(start).copied().unwrap_or(false) {
        if block_stmts.get(start).is_some_and(|s| !s.is_empty()) {
            return Region::Block(start);
        }
        return Region::Seq(Vec::new());
    }
    let mut parts = Vec::new();
    build_from(cfg, block_stmts, start, visited, &mut parts, join);
    if parts.is_empty() {
        Region::Seq(Vec::new())
    } else if parts.len() == 1 {
        parts.pop().unwrap()
    } else {
        Region::Seq(parts)
    }
}

fn do_while_info(cfg: &FunctionCfg, header: BlockId) -> Option<(BlockId, String, BlockId)> {
    // Top-tested while: header itself is a conditional loop header.
    if cfg.loop_headers.contains(&header) {
        if matches!(cfg.blocks.get(header).map(|b| &b.end), Some(BlockEnd::Conditional { .. })) {
            return None;
        }
    }
    // Latch: conditional with a back-edge to `header`.
    for (id, b) in cfg.blocks.iter().enumerate() {
        if let BlockEnd::Conditional {
            condition,
            branch_target,
            fall_through,
        } = &b.end
        {
            if *branch_target == header {
                return Some((id, condition.clone(), *fall_through));
            }
            if *fall_through == header {
                return Some((id, invert_cond(condition), *branch_target));
            }
        }
    }
    None
}

fn mark_path_stubs(
    cfg: &FunctionCfg,
    block_stmts: &[Vec<Stmt>],
    from: BlockId,
    to: BlockId,
    visited: &mut [bool],
) {
    let mut id = from;
    let mut guard = 0;
    while id != to && guard < 8 {
        guard += 1;
        visited[id] = true;
        if is_trivial_goto(cfg, block_stmts, id) {
            if let BlockEnd::Goto(t) = cfg.blocks[id].end {
                id = t;
                continue;
            }
        }
        break;
    }
}

fn skip_trivial(cfg: &FunctionCfg, block_stmts: &[Vec<Stmt>], mut id: BlockId) -> BlockId {
    let mut guard = 0;
    while guard < 8 && is_trivial_goto(cfg, block_stmts, id) {
        guard += 1;
        if let BlockEnd::Goto(t) = cfg.blocks[id].end {
            id = t;
        } else {
            break;
        }
    }
    id
}

fn is_trivial_goto(cfg: &FunctionCfg, block_stmts: &[Vec<Stmt>], id: BlockId) -> bool {
    matches!(cfg.blocks.get(id).map(|b| &b.end), Some(BlockEnd::Goto(_)))
        && block_stmts.get(id).map(|s| s.is_empty()).unwrap_or(true)
}

fn find_join(cfg: &FunctionCfg, a: BlockId, b: BlockId) -> Option<BlockId> {
    if a == b {
        return Some(a);
    }
    let reach_a = reachable(cfg, a);
    let reach_b = reachable(cfg, b);
    // One arm is empty / falls straight into the other's entry — that entry is the join.
    if reach_a.contains(&b) {
        return Some(b);
    }
    if reach_b.contains(&a) {
        return Some(a);
    }
    let mut common: Vec<BlockId> = reach_a.intersection(&reach_b).copied().collect();
    common.sort_unstable();
    // Prefer the earliest common block that is a forward join (not either arm start).
    common.into_iter().find(|&j| j != a && j != b)
}

fn reachable(cfg: &FunctionCfg, start: BlockId) -> BTreeSet<BlockId> {
    let mut seen = BTreeSet::new();
    let mut stack = alloc::vec![start];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        for s in successors(cfg, id) {
            // Don't follow back-edges when hunting joins.
            if s > id || s == id {
                stack.push(s);
            } else if !cfg.loop_headers.contains(&s) {
                stack.push(s);
            }
        }
    }
    seen
}

fn successors(cfg: &FunctionCfg, id: BlockId) -> Vec<BlockId> {
    match cfg.blocks.get(id).map(|b| &b.end) {
        Some(BlockEnd::Goto(t)) => alloc::vec![*t],
        Some(BlockEnd::Conditional {
            branch_target,
            fall_through,
            ..
        }) => alloc::vec![*branch_target, *fall_through],
        _ => Vec::new(),
    }
}

fn path_returns_to(cfg: &FunctionCfg, start: BlockId, header: BlockId) -> bool {
    let mut seen = BTreeSet::new();
    let mut stack = alloc::vec![start];
    while let Some(n) = stack.pop() {
        if n == header {
            return true;
        }
        if !seen.insert(n) {
            continue;
        }
        if seen.len() > cfg.blocks.len() + 2 {
            break;
        }
        for s in successors(cfg, n) {
            stack.push(s);
        }
    }
    false
}

fn invert_cond(cond: &str) -> String {
    // Best-effort for folded compares.
    for (a, b) in [
        (" <= ", " > "),
        (" >= ", " < "),
        (" < ", " >= "),
        (" > ", " <= "),
        (" == ", " != "),
        (" != ", " == "),
    ] {
        if cond.contains(a) {
            return cond.replacen(a, b, 1);
        }
    }
    format!("!({cond})")
}

    #[allow(dead_code)]
pub fn region_is_empty(region: &Region) -> bool {
    match region {
        Region::Seq(c) => c.is_empty() || c.iter().all(region_is_empty),
        _ => false,
    }
}
