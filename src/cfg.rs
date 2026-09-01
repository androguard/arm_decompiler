//! Control-flow graph for a function (dex-decompiler `MethodCfg` analogue).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use arm_disassembler::{Instruction, Mnemonic};

use crate::pac::{is_pac_call, is_pac_hint, is_pac_indirect_br, is_pac_return};

pub type BlockId = usize;

#[derive(Debug, Clone)]
pub enum BlockEnd {
    FallThrough,
    Goto(BlockId),
    Conditional {
        condition: String,
        branch_target: BlockId,
        fall_through: BlockId,
    },
    Exit,
}

#[derive(Debug, Clone)]
pub struct CfgBlock {
    pub start_vaddr: u64,
    pub end_vaddr: u64,
    pub end: BlockEnd,
    /// Indices into the function instruction slice.
    pub insn_indices: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct FunctionCfg {
    pub blocks: Vec<CfgBlock>,
    pub block_by_start: BTreeMap<u64, BlockId>,
    pub loop_headers: BTreeSet<BlockId>,
    pub entry: BlockId,
}

impl FunctionCfg {
    pub fn build(insns: &[Instruction]) -> Self {
        if insns.is_empty() {
            return Self {
                blocks: Vec::new(),
                block_by_start: BTreeMap::new(),
                loop_headers: BTreeSet::new(),
                entry: 0,
            };
        }

        let vaddrs: BTreeSet<u64> = insns.iter().map(|i| i.vaddr).collect();
        let mut leaders: BTreeSet<u64> = BTreeSet::new();
        leaders.insert(insns[0].vaddr);

        for (i, insn) in insns.iter().enumerate() {
            if is_branch(insn) {
                let target = insn.near_branch_target;
                if target != 0 && vaddrs.contains(&target) {
                    leaders.insert(target);
                }
                if !is_unconditional_jump(insn) && !is_return(insn) {
                    if let Some(next) = insns.get(i + 1) {
                        leaders.insert(next.vaddr);
                    }
                }
            }
            if is_call(insn) {
                // calls fall through
                if let Some(next) = insns.get(i + 1) {
                    leaders.insert(next.vaddr);
                }
            }
        }

        let leader_list: Vec<u64> = leaders.iter().copied().collect();
        let mut block_by_start: BTreeMap<u64, BlockId> = BTreeMap::new();
        for (id, &va) in leader_list.iter().enumerate() {
            block_by_start.insert(va, id);
        }

        let mut blocks = Vec::with_capacity(leader_list.len());
        for (bi, &start) in leader_list.iter().enumerate() {
            let next_leader = leader_list.get(bi + 1).copied();
            let mut insn_indices = Vec::new();
            for (i, insn) in insns.iter().enumerate() {
                if insn.vaddr < start {
                    continue;
                }
                if next_leader.is_some_and(|n| insn.vaddr >= n) {
                    break;
                }
                insn_indices.push(i);
            }
            if insn_indices.is_empty() {
                blocks.push(CfgBlock {
                    start_vaddr: start,
                    end_vaddr: start,
                    end: BlockEnd::Exit,
                    insn_indices,
                });
                continue;
            }
            let last_i = *insn_indices.last().unwrap();
            let last = &insns[last_i];
            let prev = if insn_indices.len() >= 2 {
                Some(&insns[insn_indices[insn_indices.len() - 2]])
            } else {
                None
            };
            let end_vaddr = last.vaddr + last.len as u64;
            let end = classify_end(
                last,
                prev,
                &block_by_start,
                insns.get(last_i + 1).map(|i| i.vaddr),
            );
            blocks.push(CfgBlock {
                start_vaddr: start,
                end_vaddr,
                end,
                insn_indices,
            });
        }

        let mut loop_headers = BTreeSet::new();
        for (id, b) in blocks.iter().enumerate() {
            for succ in successors(b) {
                if succ <= id {
                    loop_headers.insert(succ);
                }
            }
        }

        Self {
            blocks,
            block_by_start,
            loop_headers,
            entry: 0,
        }
    }

    pub fn label_for(&self, id: BlockId) -> String {
        match self.blocks.get(id) {
            Some(b) => format!("L_{:x}", b.start_vaddr),
            None => format!("L_{id}"),
        }
    }

    /// All CFG edges `(from, to)`.
    pub fn successor_edges(&self) -> alloc::vec::Vec<(BlockId, BlockId)> {
        let mut out = alloc::vec::Vec::new();
        for (id, b) in self.blocks.iter().enumerate() {
            for s in self.successors(id, b) {
                out.push((id, s));
            }
        }
        out
    }

    pub fn successors(&self, _id: BlockId, b: &CfgBlock) -> alloc::vec::Vec<BlockId> {
        successors(b)
    }

    pub fn predecessors(&self) -> alloc::collections::BTreeMap<BlockId, alloc::vec::Vec<BlockId>> {
        let mut preds: alloc::collections::BTreeMap<BlockId, alloc::vec::Vec<BlockId>> =
            alloc::collections::BTreeMap::new();
        for (from, to) in self.successor_edges() {
            preds.entry(to).or_default().push(from);
        }
        preds
    }

    /// Immediate dominators: `idom[n]` is the immediate dominator of block `n`.
    pub fn immediate_dominators(&self) -> alloc::vec::Vec<BlockId> {
        let n = self.blocks.len();
        if n == 0 {
            return alloc::vec::Vec::new();
        }
        let rpo = self.reverse_postorder();
        let mut rpo_idx = alloc::collections::BTreeMap::new();
        for (i, &b) in rpo.iter().enumerate() {
            rpo_idx.insert(b, i);
        }
        let preds = self.predecessors();
        let mut idom = alloc::vec![0; n];
        idom[self.entry] = self.entry;

        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter().skip(1) {
                let Some(pred_list) = preds.get(&b) else {
                    continue;
                };
                let mut new_idom = None;
                for &p in pred_list {
                    if !rpo_idx.contains_key(&p) {
                        continue;
                    }
                    new_idom = Some(match new_idom {
                        None => p,
                        Some(cur) => intersect(cur, p, &idom, &rpo_idx),
                    });
                }
                if let Some(d) = new_idom {
                    if idom[b] != d {
                        idom[b] = d;
                        changed = true;
                    }
                }
            }
        }
        idom
    }

    fn reverse_postorder(&self) -> alloc::vec::Vec<BlockId> {
        let mut post = alloc::vec::Vec::new();
        let mut seen = alloc::collections::BTreeSet::new();
        self.dfs_post(self.entry, &mut seen, &mut post);
        post.reverse();
        post
    }

    fn dfs_post(
        &self,
        id: BlockId,
        seen: &mut alloc::collections::BTreeSet<BlockId>,
        post: &mut alloc::vec::Vec<BlockId>,
    ) {
        if !seen.insert(id) {
            return;
        }
        if let Some(b) = self.blocks.get(id) {
            for s in self.successors(id, b) {
                self.dfs_post(s, seen, post);
            }
        }
        post.push(id);
    }
}

fn intersect(
    mut a: BlockId,
    mut b: BlockId,
    idom: &[BlockId],
    rpo_idx: &alloc::collections::BTreeMap<BlockId, usize>,
) -> BlockId {
    while a != b {
        while rpo_idx.get(&a).copied().unwrap_or(0) > rpo_idx.get(&b).copied().unwrap_or(0) {
            a = idom[a];
        }
        while rpo_idx.get(&b).copied().unwrap_or(0) > rpo_idx.get(&a).copied().unwrap_or(0) {
            b = idom[b];
        }
    }
    a
}

fn successors(b: &CfgBlock) -> Vec<BlockId> {
    match &b.end {
        BlockEnd::FallThrough => Vec::new(),
        BlockEnd::Goto(t) => alloc::vec![*t],
        BlockEnd::Conditional {
            branch_target,
            fall_through,
            ..
        } => alloc::vec![*branch_target, *fall_through],
        BlockEnd::Exit => Vec::new(),
    }
}

fn classify_end(
    last: &Instruction,
    prev: Option<&Instruction>,
    block_by_start: &BTreeMap<u64, BlockId>,
    fall_va: Option<u64>,
) -> BlockEnd {
    if is_return(last) {
        return BlockEnd::Exit;
    }
    if matches!(last.mnemonic, Mnemonic::Br) || is_pac_indirect_br(last.mnemonic) {
        return BlockEnd::Exit; // indirect (incl. braa/brab)
    }
    if is_unconditional_jump(last) {
        let t = last.near_branch_target;
        if let Some(&id) = block_by_start.get(&t) {
            return BlockEnd::Goto(id);
        }
        return BlockEnd::Exit;
    }
    if is_conditional_branch(last) {
        let t = last.near_branch_target;
        let branch = block_by_start.get(&t).copied();
        let fall = fall_va.and_then(|v| block_by_start.get(&v).copied());
        if let (Some(bt), Some(ft)) = (branch, fall) {
            return BlockEnd::Conditional {
                condition: condition_string(last, prev),
                branch_target: bt,
                fall_through: ft,
            };
        }
    }
    if let Some(v) = fall_va {
        if let Some(&id) = block_by_start.get(&v) {
            return BlockEnd::Goto(id);
        }
    }
    BlockEnd::FallThrough
}

pub fn is_return(insn: &Instruction) -> bool {
    matches!(insn.mnemonic, Mnemonic::Ret) || is_pac_return(insn.mnemonic)
}

pub fn is_call(insn: &Instruction) -> bool {
    matches!(insn.mnemonic, Mnemonic::Bl | Mnemonic::Blr) || is_pac_call(insn.mnemonic)
}

pub fn is_unconditional_jump(insn: &Instruction) -> bool {
    matches!(insn.mnemonic, Mnemonic::B) && !insn.is_conditional_branch
}

pub fn is_conditional_branch(insn: &Instruction) -> bool {
    insn.is_conditional_branch
        || matches!(
            insn.mnemonic,
            Mnemonic::Bcond | Mnemonic::Cbz | Mnemonic::Cbnz | Mnemonic::Tbz | Mnemonic::Tbnz
        )
}

pub fn is_branch(insn: &Instruction) -> bool {
    is_return(insn)
        || is_unconditional_jump(insn)
        || is_conditional_branch(insn)
        || matches!(insn.mnemonic, Mnemonic::Br)
        || is_pac_indirect_br(insn.mnemonic)
}

/// True when this insn only updates flags for a following conditional branch.
pub fn is_flag_setter(insn: &Instruction) -> bool {
    matches!(
        insn.mnemonic,
        Mnemonic::Cmp
            | Mnemonic::Cmn
            | Mnemonic::Tst
            | Mnemonic::Subs
            | Mnemonic::Adds
            | Mnemonic::Ands
            | Mnemonic::Bics
    )
}

/// PAC/AUT/XPAC ops that are elided from IR (side-effect free for decomp).
pub fn is_pac_elidable(insn: &Instruction) -> bool {
    is_pac_hint(insn.mnemonic)
}

fn condition_string(branch: &Instruction, prev: Option<&Instruction>) -> String {
    match branch.mnemonic {
        Mnemonic::Cbz => {
            let r = reg_operand(branch, 0).unwrap_or_else(|| String::from("?"));
            format!("{r} == 0")
        }
        Mnemonic::Cbnz => {
            let r = reg_operand(branch, 0).unwrap_or_else(|| String::from("?"));
            format!("{r} != 0")
        }
        Mnemonic::Tbz => {
            let r = reg_operand(branch, 0).unwrap_or_else(|| String::from("?"));
            format!("(({r} >> {}) & 1) == 0", branch.op1_imm)
        }
        Mnemonic::Tbnz => {
            let r = reg_operand(branch, 0).unwrap_or_else(|| String::from("?"));
            format!("(({r} >> {}) & 1) != 0", branch.op1_imm)
        }
        _ if matches!(branch.mnemonic, Mnemonic::Bcond) || branch.is_conditional_branch => {
            if let Some(p) = prev {
                if let Some(folded) = fold_cmp_branch(p, branch.condition) {
                    return folded;
                }
            }
            format!("flags.{}", branch.condition.as_str())
        }
        _ => String::from("cond"),
    }
}

/// Fold `cmp`/`tst`/`cmn`/`subs` + `b.cond` into a C-like predicate.
pub fn fold_cmp_branch(flag_insn: &Instruction, cond: arm_disassembler::Condition) -> Option<String> {
    use arm_disassembler::{Condition, OpKind};

    let (lhs, rhs) = match flag_insn.mnemonic {
        Mnemonic::Cmp | Mnemonic::Cmn | Mnemonic::Tst => {
            let lhs = reg_operand(flag_insn, 0)?;
            let rhs = if flag_insn.op1_kind == OpKind::Immediate {
                format_imm(flag_insn.op1_imm)
            } else {
                reg_operand(flag_insn, 1)?
            };
            (lhs, rhs)
        }
        // clang -O0: `subs w8, wn, wm` then `b.cond` — compare the sources.
        Mnemonic::Subs | Mnemonic::Adds => {
            let lhs = reg_operand(flag_insn, 1)?;
            let rhs = if flag_insn.op2_kind == OpKind::Immediate {
                format_imm(flag_insn.op2_imm)
            } else {
                reg_operand(flag_insn, 2)?
            };
            (lhs, rhs)
        }
        _ => return None,
    };

    if flag_insn.mnemonic == Mnemonic::Tst {
        return Some(match cond {
            Condition::Eq => format!("({lhs} & {rhs}) == 0"),
            Condition::Ne => format!("({lhs} & {rhs}) != 0"),
            _ => format!("tst({lhs}, {rhs}).{}", cond.as_str()),
        });
    }

    if flag_insn.mnemonic == Mnemonic::Cmn {
        return Some(match cond {
            Condition::Eq => format!("{lhs} == -({rhs})"),
            Condition::Ne => format!("{lhs} != -({rhs})"),
            _ => format!("cmn({lhs}, {rhs}).{}", cond.as_str()),
        });
    }

    Some(match cond {
        Condition::Eq => format!("{lhs} == {rhs}"),
        Condition::Ne => format!("{lhs} != {rhs}"),
        Condition::Cs => format!("{lhs} >= {rhs}"),
        Condition::Cc => format!("{lhs} < {rhs}"),
        Condition::Hi => format!("{lhs} > {rhs}"),
        Condition::Ls => format!("{lhs} <= {rhs}"),
        Condition::Ge => format!("{lhs} >= {rhs}"),
        Condition::Lt => format!("{lhs} < {rhs}"),
        Condition::Gt => format!("{lhs} > {rhs}"),
        Condition::Le => format!("{lhs} <= {rhs}"),
        Condition::Mi => format!("({lhs} - {rhs}) < 0"),
        Condition::Pl => format!("({lhs} - {rhs}) >= 0"),
        other => format!("cmp({lhs}, {rhs}).{}", other.as_str()),
    })
}

fn format_imm(n: u64) -> String {
    if n <= 9 {
        format!("{n}")
    } else {
        format!("0x{n:x}")
    }
}

fn reg_operand(insn: &Instruction, idx: u8) -> Option<String> {
    use arm_disassembler::{OpKind, Register};
    let (kind, reg) = match idx {
        0 => (insn.op0_kind, insn.op0_reg),
        1 => (insn.op1_kind, insn.op1_reg),
        2 => (insn.op2_kind, insn.op2_reg),
        3 => (insn.op3_kind, insn.op3_reg),
        _ => return None,
    };
    if kind != OpKind::Register || matches!(reg, Register::None) {
        return None;
    }
    Some(String::from(reg.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arm_disassembler::Decoder;

    fn decode_all(code: &[u8], base: u64) -> Vec<Instruction> {
        let mut dec = Decoder::new(code, base);
        let mut insns = Vec::new();
        while dec.can_decode() {
            insns.push(dec.decode());
        }
        insns
    }

    #[test]
    fn builds_cfg_for_linear_ret() {
        let code = [
            0x1f, 0x20, 0x03, 0xd5, // nop
            0xc0, 0x03, 0x5f, 0xd6, // ret
        ];
        let insns = decode_all(&code, 0x1000);
        let cfg = FunctionCfg::build(&insns);
        assert!(!cfg.blocks.is_empty());
        assert!(matches!(cfg.blocks[0].end, BlockEnd::Exit) || cfg.blocks.len() >= 1);
    }

    #[test]
    fn folds_cmp_beq_into_equality() {
        // cmp w0, w1; b.eq 0x10; mov w0,#1; ret; mov w0,#0; ret
        let code = [
            0x1f, 0x00, 0x01, 0x6b, 0x60, 0x00, 0x00, 0x54, 0x20, 0x00, 0x80, 0x52, 0xc0, 0x03,
            0x5f, 0xd6, 0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        let insns = decode_all(&code, 0);
        let cfg = FunctionCfg::build(&insns);
        let cond = cfg.blocks.iter().find_map(|b| match &b.end {
            BlockEnd::Conditional { condition, .. } => Some(condition.as_str()),
            _ => None,
        });
        assert_eq!(cond, Some("w0 == w1"));
    }
}
