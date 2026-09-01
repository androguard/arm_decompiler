//! ARM64 jump-table recovery (P2-4).
//!
//! Recognizes the common clang/LLVM pattern:
//! ```text
//!   cmp  wn, #max
//!   b.hi default
//!   adrp xT, page / add xT, #off     ; table base
//!   adr  xA, #imm                    ; branch-island base
//!   ldrb wt, [xT, xn]                ; or ldrsw …
//!   add  xA, xA, xt, lsl #2
//!   br   xA
//!   ; island: b case0; b case1; …
//! ```

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use arm_disassembler::{Condition, Instruction, Mnemonic, OpKind, Register};

use macho_core::MachoFile;

use crate::error::{Error, Result};
use crate::ir::{var_from_reg, Stmt};

/// One recovered jump table inside a function.
#[derive(Clone, Debug)]
pub struct JumpTable {
    /// Discriminant register number (W/X encoding 0–31).
    pub index_reg: u32,
    /// Inclusive max index (`cmp` immediate); cases `0..=max`.
    pub max_index: u64,
    /// Default target VA (`b.hi` / out-of-range).
    pub default_va: u64,
    /// Case index → target VA (resolved branch island entry).
    pub cases: BTreeMap<u64, u64>,
    /// VA of the `br` instruction.
    pub br_va: u64,
    /// Asm text for dispatch-window ops (used to strip Raw noise from the body).
    pub dispatch_noise: Vec<String>,
    /// Human summary for comments / JSON.
    pub summary: String,
}

/// Scan a function’s instructions for a jump-table dispatch.
pub fn recover_jump_tables(
    file: &MachoFile<'_>,
    insns: &[Instruction],
) -> Result<Vec<JumpTable>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < insns.len() {
        if let Some((jt, consumed)) = try_recover_at(file, insns, i)? {
            i += consumed.max(1);
            out.push(jt);
        } else {
            i += 1;
        }
    }
    Ok(out)
}

fn try_recover_at(
    file: &MachoFile<'_>,
    insns: &[Instruction],
    start: usize,
) -> Result<Option<(JumpTable, usize)>> {
    let Some(cmp_i) = insns[start..]
        .iter()
        .take(12)
        .position(|ins| matches!(ins.mnemonic, Mnemonic::Cmp))
        .map(|p| start + p)
    else {
        return Ok(None);
    };
    let cmp = &insns[cmp_i];
    if cmp.op1_kind != OpKind::Immediate {
        return Ok(None);
    }
    let max_index = cmp.op1_imm;
    let Some(index_reg) = reg_num(cmp.op0_reg) else {
        return Ok(None);
    };

    let Some(bhi_i) = insns[cmp_i + 1..]
        .iter()
        .take(4)
        .position(|ins| is_hi_cond_branch(ins))
        .map(|p| cmp_i + 1 + p)
    else {
        return Ok(None);
    };
    let default_va = insns[bhi_i].near_branch_target;
    if default_va == 0 {
        return Ok(None);
    }

    let Some(br_i) = insns[bhi_i + 1..]
        .iter()
        .take(16)
        .position(|ins| matches!(ins.mnemonic, Mnemonic::Br))
        .map(|p| bhi_i + 1 + p)
    else {
        return Ok(None);
    };

    let window = &insns[bhi_i + 1..=br_i];
    let mut island_base: Option<u64> = None;
    let mut table_va: Option<u64> = None;
    let mut entry_size: u32 = 1;
    let mut adrp_page: Option<(u32, u64)> = None;

    for ins in window {
        match ins.mnemonic {
            Mnemonic::Adrp => {
                if let Some(r) = reg_num(ins.op0_reg) {
                    let page = if ins.near_branch_target != 0 {
                        ins.near_branch_target
                    } else {
                        ins.op1_imm
                    };
                    adrp_page = Some((r, page));
                }
            }
            Mnemonic::Add => {
                if let Some((r, page)) = adrp_page {
                    if reg_num(ins.op0_reg) == Some(r)
                        && reg_num(ins.op1_reg) == Some(r)
                        && ins.op2_kind == OpKind::Immediate
                    {
                        table_va = Some(page.wrapping_add(ins.op2_imm));
                    }
                }
            }
            Mnemonic::Adr => {
                let target = if ins.near_branch_target != 0 {
                    ins.near_branch_target
                } else {
                    ins.op1_imm
                };
                if target != 0 {
                    island_base = Some(target);
                }
            }
            Mnemonic::Ldrb | Mnemonic::Ldrh => entry_size = 1,
            Mnemonic::Ldrsw | Mnemonic::Ldr => entry_size = 4,
            _ => {}
        }
    }

    let Some(table_va) = table_va else {
        return Ok(None);
    };
    let count = (max_index as usize).saturating_add(1);
    let table_bytes = read_va_bytes(file, table_va, count * entry_size as usize)?;

    let mut cases = BTreeMap::new();
    if let Some(island) = island_base {
        for i in 0..count {
            let idx = match entry_size {
                1 => *table_bytes.get(i).unwrap_or(&0) as u64,
                2 => {
                    let o = i * 2;
                    if o + 2 > table_bytes.len() {
                        0
                    } else {
                        u16::from_le_bytes([table_bytes[o], table_bytes[o + 1]]) as u64
                    }
                }
                _ => {
                    let o = i * 4;
                    if o + 4 > table_bytes.len() {
                        0
                    } else {
                        u32::from_le_bytes([
                            table_bytes[o],
                            table_bytes[o + 1],
                            table_bytes[o + 2],
                            table_bytes[o + 3],
                        ]) as u64
                    }
                }
            };
            let slot_va = island.wrapping_add(idx.wrapping_mul(4));
            let target = resolve_branch_at(file, slot_va).unwrap_or(slot_va);
            cases.insert(i as u64, target);
        }
    } else {
        for i in 0..count {
            let o = i * 4;
            if o + 4 > table_bytes.len() {
                break;
            }
            let rel = i32::from_le_bytes([
                table_bytes[o],
                table_bytes[o + 1],
                table_bytes[o + 2],
                table_bytes[o + 3],
            ]);
            let target = (table_va as i64)
                .wrapping_add(i as i64 * 4)
                .wrapping_add(rel as i64) as u64;
            cases.insert(i as u64, target);
        }
    }

    if cases.is_empty() {
        return Ok(None);
    }

    let mut dispatch_noise = Vec::new();
    let fmt = arm_disassembler::Formatter::default();
    for ins in &insns[cmp_i..=br_i] {
        if matches!(
            ins.mnemonic,
            Mnemonic::Cmp
                | Mnemonic::Adrp
                | Mnemonic::Adr
                | Mnemonic::Add
                | Mnemonic::Ldrb
                | Mnemonic::Ldrh
                | Mnemonic::Ldrsw
                | Mnemonic::Ldr
                | Mnemonic::Lsl
        ) {
            dispatch_noise.push(fmt.format_simple(ins));
        }
    }

    let jt = JumpTable {
        index_reg,
        max_index,
        default_va,
        cases,
        br_va: insns[br_i].vaddr,
        dispatch_noise,
        summary: format!(
            "jumptable x{index_reg} 0..={max_index} → {count} cases, default={default_va:#x}"
        ),
    };
    Ok(Some((jt, br_i - start + 1)))
}

fn is_hi_cond_branch(ins: &Instruction) -> bool {
    ins.is_conditional_branch
        && matches!(ins.condition, Condition::Hi | Condition::Ls)
        && ins.near_branch_target != 0
}

fn reg_num(r: Register) -> Option<u32> {
    var_from_reg(r).map(|v| v.reg)
}

fn read_va_bytes(file: &MachoFile<'_>, va: u64, len: usize) -> Result<Vec<u8>> {
    for item in file.sections()? {
        let (sect, _) = item?;
        if va >= sect.addr && va < sect.addr.saturating_add(sect.size) {
            let off = (va - sect.addr) as usize;
            let data = file.section_data(sect)?;
            let end = off.saturating_add(len).min(data.len());
            if off >= data.len() {
                return Err(Error::Other(format!("jumptable va {va:#x} past section")));
            }
            return Ok(data[off..end].to_vec());
        }
    }
    Err(Error::Other(format!(
        "jumptable va {va:#x} not in any section"
    )))
}

fn resolve_branch_at(file: &MachoFile<'_>, va: u64) -> Option<u64> {
    let bytes = read_va_bytes(file, va, 4).ok()?;
    if bytes.len() < 4 {
        return None;
    }
    let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    // Unconditional B: 0001_01 imm26
    if raw & 0xFC00_0000 == 0x1400_0000 {
        let imm26 = (raw & 0x03FF_FFFF) as i32;
        let imm = (imm26 << 6) >> 6;
        let offset = (imm as i64) * 4;
        return Some((va as i64).wrapping_add(offset) as u64);
    }
    None
}

/// Format a C-like switch skeleton from a recovered jump table.
pub fn format_jump_table_switch(jt: &JumpTable, disc: &str) -> String {
    let mut out = format!("switch ({disc}) {{\n");
    for (k, va) in &jt.cases {
        out.push_str(&format!("    case {k}: goto lab_{va:x};\n"));
    }
    out.push_str(&format!(
        "    default: goto lab_{:x};\n",
        jt.default_va
    ));
    out.push_str("}\n");
    out
}

/// Drop Raw IR that mirrors the jump-table dispatch window (kept as `switch` annotation).
pub fn strip_jump_table_dispatch_noise(block_stmts: &mut [Vec<Stmt>], tables: &[JumpTable]) {
    if tables.is_empty() {
        return;
    }
    let noise: Vec<&str> = tables
        .iter()
        .flat_map(|t| t.dispatch_noise.iter().map(String::as_str))
        .collect();
    if noise.is_empty() {
        return;
    }
    for stmts in block_stmts.iter_mut() {
        stmts.retain(|s| match s {
            Stmt::Raw(t) => {
                let bare = t.trim().trim_start_matches("/* ").trim_end_matches(" */");
                !noise.iter().any(|n| bare == *n || bare.contains(n) || n.contains(bare))
            }
            _ => true,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_switch_text() {
        let mut cases = BTreeMap::new();
        cases.insert(0, 0x1000);
        cases.insert(1, 0x1004);
        let jt = JumpTable {
            index_reg: 0,
            max_index: 1,
            default_va: 0x2000,
            cases,
            br_va: 0x3000,
            dispatch_noise: Vec::new(),
            summary: String::from("test"),
        };
        let s = format_jump_table_switch(&jt, "x");
        assert!(s.contains("case 0:"));
        assert!(s.contains("default:"));
    }
}
