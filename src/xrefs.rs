//! Cross-references and call-graph construction for ARM64 code.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use arm_disassembler::{decode_raw, Code, Instruction, OpKind, Register};
use macho_core::MachoFile;

use crate::error::{Error, Result};

/// Kind of cross-reference edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    /// `bl` / `blr` (call).
    Call,
    /// Unconditional / conditional `b`.
    Branch,
    /// ADRP+ADD / literal pool / memory address.
    Data,
    /// Data xref that resolves to a C-string.
    String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
}

/// Indexed xrefs for fast to/from queries.
#[derive(Debug, Clone, Default)]
pub struct XrefIndex {
    by_from: BTreeMap<u64, Vec<Xref>>,
    by_to: BTreeMap<u64, Vec<Xref>>,
}

impl XrefIndex {
    pub fn push(&mut self, xref: Xref) {
        self.by_from
            .entry(xref.from)
            .or_default()
            .push(xref.clone());
        self.by_to.entry(xref.to).or_default().push(xref);
    }

    pub fn xrefs_from(&self, addr: u64) -> &[Xref] {
        self.by_from.get(&addr).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn xrefs_to(&self, addr: u64) -> &[Xref] {
        self.by_to.get(&addr).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// All xrefs whose `from` falls in `[start, end)`.
    pub fn xrefs_from_range(&self, start: u64, end: u64) -> Vec<&Xref> {
        let mut out = Vec::new();
        for (_, xs) in self.by_from.range(start..end) {
            for x in xs {
                out.push(x);
            }
        }
        out
    }

    /// All xrefs whose `to` falls in `[start, end)`.
    pub fn xrefs_to_range(&self, start: u64, end: u64) -> Vec<&Xref> {
        let mut out = Vec::new();
        for (_, xs) in self.by_to.range(start..end) {
            for x in xs {
                out.push(x);
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.by_from.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn all(&self) -> Vec<&Xref> {
        self.by_from.values().flat_map(|v| v.iter()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct CallEdge {
    pub caller: u64,
    pub callee: u64,
    pub site: u64,
}

#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    pub edges: Vec<CallEdge>,
}

impl CallGraph {
    pub fn callees_of(&self, caller: u64) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .edges
            .iter()
            .filter(|e| e.caller == caller)
            .map(|e| e.callee)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    pub fn callers_of(&self, callee: u64) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .edges
            .iter()
            .filter(|e| e.callee == callee)
            .map(|e| e.caller)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// Scan a contiguous ARM64 code buffer starting at `base_vaddr`.
pub fn scan_code_xrefs(code: &[u8], base_vaddr: u64) -> XrefIndex {
    let mut index = XrefIndex::default();
    // Pending ADRP/ADR: rd -> (insn_va, page_or_abs)
    let mut pending_adrp: BTreeMap<u8, (u64, u64)> = BTreeMap::new();

    let mut off = 0usize;
    while off + 4 <= code.len() {
        let raw = u32::from_le_bytes([code[off], code[off + 1], code[off + 2], code[off + 3]]);
        let vaddr = base_vaddr.wrapping_add(off as u64);
        let insn = decode_raw(vaddr, raw);
        collect_insn_xrefs(&insn, &mut index, &mut pending_adrp);
        off += 4;
    }
    index
}

fn reg_num(r: Register) -> Option<u8> {
    let d = r as u16;
    if (1..=31).contains(&d) {
        Some((d - 1) as u8) // X0..X30
    } else if (34..=64).contains(&d) {
        Some((d - 34) as u8) // W0..W30
    } else {
        None
    }
}

fn collect_insn_xrefs(
    insn: &Instruction,
    index: &mut XrefIndex,
    pending_adrp: &mut BTreeMap<u8, (u64, u64)>,
) {
    match insn.code {
        Code::Bl => {
            if insn.near_branch_target != 0 {
                index.push(Xref {
                    from: insn.vaddr,
                    to: insn.near_branch_target,
                    kind: XrefKind::Call,
                });
            }
        }
        Code::B | Code::B_cond => {
            if insn.near_branch_target != 0 {
                index.push(Xref {
                    from: insn.vaddr,
                    to: insn.near_branch_target,
                    kind: XrefKind::Branch,
                });
            }
        }
        Code::Blr => {}
        Code::Adr | Code::Adrp => {
            let page = insn.near_branch_target;
            if page != 0 {
                if let Some(rd) = reg_num(insn.op0_reg) {
                    pending_adrp.insert(rd, (insn.vaddr, page));
                }
                if insn.code == Code::Adr {
                    index.push(Xref {
                        from: insn.vaddr,
                        to: page,
                        kind: XrefKind::Data,
                    });
                }
            }
        }
        Code::Add_imm | Code::Sub_imm => {
            if let (Some(_rd), Some(rn)) = (reg_num(insn.op0_reg), reg_num(insn.op1_reg)) {
                if let Some(&(adrp_ip, page)) = pending_adrp.get(&rn) {
                    let imm = insn.op2_imm;
                    let target = if insn.code == Code::Add_imm {
                        page.wrapping_add(imm)
                    } else {
                        page.wrapping_sub(imm)
                    };
                    index.push(Xref {
                        from: adrp_ip,
                        to: target,
                        kind: XrefKind::Data,
                    });
                    index.push(Xref {
                        from: insn.vaddr,
                        to: target,
                        kind: XrefKind::Data,
                    });
                    pending_adrp.remove(&rn);
                }
            }
        }
        Code::Ldr_uimm | Code::Ldr_imm | Code::Ldrsw_uimm => {
            if insn.near_branch_target != 0
                && insn.near_branch_target != insn.vaddr
                && matches!(insn.op1_kind, OpKind::NearBranch | OpKind::Immediate)
            {
                index.push(Xref {
                    from: insn.vaddr,
                    to: insn.near_branch_target,
                    kind: XrefKind::Data,
                });
            }
        }
        _ => {}
    }

    // Clear stale ADRP if destination overwritten without matching ADD
    if !matches!(insn.code, Code::Adr | Code::Adrp) {
        if let Some(rd) = reg_num(insn.op0_reg) {
            if matches!(
                insn.code,
                Code::Movz | Code::Movk | Code::Movn | Code::Orr_imm | Code::And_imm
            ) {
                pending_adrp.remove(&rd);
            }
        }
    }
}

/// Build xrefs for Mach-O `__TEXT.__text`, classifying string targets when possible.
pub fn build_macho_xrefs(file: &MachoFile<'_>) -> Result<XrefIndex> {
    let text = file
        .find_section("__TEXT", "__text")?
        .ok_or(Error::NoCode)?;
    let code = file.section_data(&text)?;
    let mut index = scan_code_xrefs(code, text.addr);

    let mut promoted = Vec::new();
    for x in index.all() {
        if x.kind != XrefKind::Data {
            continue;
        }
        if looks_like_cstring(file, x.to) {
            promoted.push(Xref {
                from: x.from,
                to: x.to,
                kind: XrefKind::String,
            });
        }
    }
    for x in promoted {
        index.push(x);
    }
    Ok(index)
}

fn looks_like_cstring(file: &MachoFile<'_>, vaddr: u64) -> bool {
    let Ok(s) = file.read_cstr_vaddr(vaddr) else {
        return false;
    };
    if s.is_empty() || s.len() > 512 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_graphic() || c == ' ' || c == '\t')
}

/// Xrefs targeting `addr` (exact).
pub fn xrefs_to(index: &XrefIndex, addr: u64) -> Vec<&Xref> {
    index.xrefs_to(addr).iter().collect()
}

/// Xrefs originating at `addr` (exact instruction VA).
pub fn xrefs_from(index: &XrefIndex, addr: u64) -> Vec<&Xref> {
    index.xrefs_from(addr).iter().collect()
}

/// Call graph from an xref index, using function starts to attribute callers.
///
/// `func_starts` must be sorted ascending. Each call site is attributed to the
/// greatest function start `<= site`.
pub fn call_graph(index: &XrefIndex, func_starts: &[u64]) -> CallGraph {
    let mut edges = Vec::new();
    for xs in index.by_from.values() {
        for x in xs {
            if x.kind != XrefKind::Call {
                continue;
            }
            let caller = enclosing_func(func_starts, x.from).unwrap_or(x.from);
            edges.push(CallEdge {
                caller,
                callee: x.to,
                site: x.from,
            });
        }
    }
    CallGraph { edges }
}

fn enclosing_func(starts: &[u64], addr: u64) -> Option<u64> {
    let idx = starts.partition_point(|&s| s <= addr);
    if idx == 0 {
        None
    } else {
        Some(starts[idx - 1])
    }
}

/// Human-readable kind label.
pub fn xref_kind_name(k: XrefKind) -> &'static str {
    match k {
        XrefKind::Call => "call",
        XrefKind::Branch => "branch",
        XrefKind::Data => "data",
        XrefKind::String => "string",
    }
}

/// Serialize one xref for JSON APIs.
pub fn xref_summary(x: &Xref) -> (u64, u64, String) {
    (x.from, x.to, String::from(xref_kind_name(x.kind)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_bl_target() {
        // bl #+8 at 0x1000 → target 0x1008
        // encoding: imm26 = 2, link=1 → 0x94000002
        let code = [0x02u8, 0x00, 0x00, 0x94];
        let idx = scan_code_xrefs(&code, 0x1000);
        let xs = idx.xrefs_from(0x1000);
        assert_eq!(xs.len(), 1);
        assert_eq!(xs[0].to, 0x1008);
        assert_eq!(xs[0].kind, XrefKind::Call);
    }

    #[test]
    fn call_graph_attributes_caller() {
        let mut idx = XrefIndex::default();
        idx.push(Xref {
            from: 0x1100,
            to: 0x2000,
            kind: XrefKind::Call,
        });
        let g = call_graph(&idx, &[0x1000, 0x1800]);
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.edges[0].caller, 0x1000);
        assert_eq!(g.edges[0].callee, 0x2000);
    }
}
