//! DWARF debug-name recovery for Mach-O `__DWARF` sections (P4-2).
//!
//! Linked Apple executables often strip DWARF into a dSYM; object files (and
//! some `-g` embeds) still carry `__debug_info`. When present we recover
//! subprogram + formal-parameter names for nicer prototypes.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gimli::{
    DW_TAG_formal_parameter, DW_TAG_subprogram, DebuggingInformationEntry, Dwarf, EndianSlice,
    LittleEndian, Reader, Unit,
};
use macho_core::MachoFile;

/// One DWARF `DW_TAG_subprogram` with parameter names (best-effort).
#[derive(Clone, Debug, Default)]
pub struct DwarfSubprogram {
    pub name: String,
    pub low_pc: u64,
    pub high_pc: Option<u64>,
    pub params: Vec<String>,
}

/// Compact-unwind / unwind_info presence (not full parsing).
#[derive(Clone, Debug, Default)]
pub struct UnwindHints {
    pub has_unwind_info: bool,
    pub has_compact_unwind: bool,
    pub has_eh_frame: bool,
    pub has_dwarf_debug_info: bool,
    /// Mach-O CPU subtype is arm64e (PAC-capable ABI).
    pub is_arm64e: bool,
}

/// Scan Mach-O for unwind / DWARF section presence.
pub fn detect_unwind_hints(file: &MachoFile<'_>) -> UnwindHints {
    let mut h = UnwindHints::default();
    h.has_unwind_info = file
        .find_section("__TEXT", "__unwind_info")
        .ok()
        .flatten()
        .is_some();
    h.has_compact_unwind = file
        .find_section("__LD", "__compact_unwind")
        .ok()
        .flatten()
        .is_some();
    h.has_eh_frame = file
        .find_section("__TEXT", "__eh_frame")
        .ok()
        .flatten()
        .is_some();
    h.has_dwarf_debug_info = file
        .find_section("__DWARF", "__debug_info")
        .ok()
        .flatten()
        .is_some();
    h.is_arm64e = macho_core::arch_name(file.header.cputype, file.header.cpusubtype) == "arm64e";
    h
}

/// Load subprograms from `__DWARF` when the sections exist; empty Vec if absent.
pub fn load_dwarf_subprograms(file: &MachoFile<'_>) -> Vec<DwarfSubprogram> {
    let Ok(Some(dwarf)) = load_gimli_dwarf(file) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut iter = dwarf.units();
    while let Ok(Some(header)) = iter.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let Ok(mut tree) = unit.entries_tree(None) else {
            continue;
        };
        let Ok(root) = tree.root() else {
            continue;
        };
        walk_tree(&dwarf, &unit, root, &mut out);
    }
    out
}

fn walk_tree<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    node: gimli::read::EntriesTreeNode<'_, '_, '_, R>,
    out: &mut Vec<DwarfSubprogram>,
) {
    let entry = node.entry();
    if entry.tag() == DW_TAG_subprogram {
        if let Some(mut sp) = read_subprogram(dwarf, unit, entry) {
            let mut children = node.children();
            while let Ok(Some(child)) = children.next() {
                let ce = child.entry();
                if ce.tag() == DW_TAG_formal_parameter {
                    if let Some(n) = attr_name(dwarf, unit, ce) {
                        if !n.is_empty() {
                            sp.params.push(n);
                        }
                    }
                } else {
                    walk_tree(dwarf, unit, child, out);
                }
            }
            out.push(sp);
            return;
        }
    }
    let mut children = node.children();
    while let Ok(Some(child)) = children.next() {
        walk_tree(dwarf, unit, child, out);
    }
}

fn load_gimli_dwarf<'a>(
    file: &'a MachoFile<'a>,
) -> Result<Option<Dwarf<EndianSlice<'a, LittleEndian>>>, ()> {
    let info = match file.find_section("__DWARF", "__debug_info").ok().flatten() {
        Some(s) => file.section_data(s).map_err(|_| ())?,
        None => return Ok(None),
    };
    let abbrev = section_or_empty(file, "__debug_abbrev");
    let str_ = section_or_empty(file, "__debug_str");
    let line = section_or_empty(file, "__debug_line");
    let line_str = section_or_empty(file, "__debug_line_str");
    let str_offsets = section_or_empty(file, "__debug_str_offs");
    let addr = section_or_empty(file, "__debug_addr");
    let ranges = section_or_empty(file, "__debug_ranges");
    let rnglists = section_or_empty(file, "__debug_rnglists");
    let loclists = section_or_empty(file, "__debug_loclists");

    let dwarf = Dwarf::load(|id| -> Result<EndianSlice<'a, LittleEndian>, ()> {
        let data = match id {
            gimli::SectionId::DebugInfo => info,
            gimli::SectionId::DebugAbbrev => abbrev,
            gimli::SectionId::DebugStr => str_,
            gimli::SectionId::DebugLine => line,
            gimli::SectionId::DebugLineStr => line_str,
            gimli::SectionId::DebugStrOffsets => str_offsets,
            gimli::SectionId::DebugAddr => addr,
            gimli::SectionId::DebugRanges => ranges,
            gimli::SectionId::DebugRngLists => rnglists,
            gimli::SectionId::DebugLocLists => loclists,
            _ => &[][..],
        };
        Ok(EndianSlice::new(data, LittleEndian))
    })?;
    Ok(Some(dwarf))
}

fn section_or_empty<'a>(file: &'a MachoFile<'a>, sect: &str) -> &'a [u8] {
    file.find_section("__DWARF", sect)
        .ok()
        .flatten()
        .and_then(|s| file.section_data(s).ok())
        .unwrap_or(&[])
}

fn read_subprogram<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<'_, '_, R>,
) -> Option<DwarfSubprogram> {
    let name = attr_name(dwarf, unit, entry)?;
    let low_pc = attr_low_pc(dwarf, unit, entry).unwrap_or(0);
    let high_pc = attr_high_pc(entry);
    Some(DwarfSubprogram {
        name,
        low_pc,
        high_pc,
        params: Vec::new(),
    })
}

fn attr_name<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<'_, '_, R>,
) -> Option<String> {
    let val = entry.attr_value(gimli::DW_AT_name).ok()??;
    let s = dwarf.attr_string(unit, val).ok()?;
    let cow = s.to_string_lossy().ok()?;
    Some(cow.into_owned())
}

fn attr_low_pc<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<'_, '_, R>,
) -> Option<u64> {
    let val = entry.attr_value(gimli::DW_AT_low_pc).ok()??;
    match val {
        gimli::AttributeValue::Addr(a) => Some(a),
        gimli::AttributeValue::DebugAddrIndex(index) => dwarf.address(unit, index).ok(),
        _ => None,
    }
}

fn attr_high_pc<R: Reader>(entry: &DebuggingInformationEntry<'_, '_, R>) -> Option<u64> {
    let val = entry.attr_value(gimli::DW_AT_high_pc).ok()??;
    match val {
        gimli::AttributeValue::Addr(a) => Some(a),
        gimli::AttributeValue::Udata(u) => Some(u),
        _ => None,
    }
}

/// Match a subprogram by low_pc or by symbol / DWARF name.
pub fn find_subprogram<'a>(
    subs: &'a [DwarfSubprogram],
    vaddr: u64,
    symbol: &str,
) -> Option<&'a DwarfSubprogram> {
    if let Some(s) = subs.iter().find(|s| s.low_pc == vaddr) {
        return Some(s);
    }
    let bare = symbol.trim_start_matches('_');
    subs.iter().find(|s| {
        s.name == bare || s.name == symbol || format_underscore(&s.name) == symbol
    })
}

fn format_underscore(name: &str) -> String {
    if name.starts_with('_') || name.starts_with("-[") || name.starts_with("+[") {
        name.to_string()
    } else {
        alloc::format!("_{name}")
    }
}

/// Build `param_N` → DWARF name pairs (skips `self` slots).
pub fn dwarf_param_renames(
    frame_params: &[String],
    dwarf_params: &[String],
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut di = 0usize;
    for fp in frame_params {
        if fp == "self" {
            continue;
        }
        if let Some(dn) = dwarf_params.get(di) {
            if is_c_ident(dn) && dn.as_str() != fp {
                out.push((fp.clone(), dn.clone()));
            }
            di += 1;
        }
    }
    out
}

fn is_c_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_rename_skips_self() {
        let frame = alloc::vec![
            String::from("self"),
            String::from("param_2"),
            String::from("param_3"),
        ];
        let dwarf = alloc::vec![String::from("x"), String::from("y")];
        let r = dwarf_param_renames(&frame, &dwarf);
        assert_eq!(
            r,
            alloc::vec![
                ("param_2".into(), "x".into()),
                ("param_3".into(), "y".into())
            ]
        );
    }
}
