//! Function extent recovery (M1): symbols + `LC_FUNCTION_STARTS`.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use apple_metadata::SymbolTable;
use macho_core::{cstr16, MachoFile};

use crate::error::{Error, Result};

/// Inclusive-start, exclusive-end virtual address range for one function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionBounds {
    pub start: u64,
    /// First byte *after* the function (next function start or end of `__text`).
    pub end: u64,
}

impl FunctionBounds {
    pub fn len_bytes(self) -> usize {
        self.end.saturating_sub(self.start) as usize
    }
}

/// Resolve `[start, end)` for a function at `start_vaddr`.
///
/// End is the minimum of:
/// - next `LC_FUNCTION_STARTS` entry after `start`
/// - next symbol address in `__TEXT.__text` after `start`
/// - end of `__TEXT.__text`
/// - `start + max_bytes` (safety cap)
pub fn resolve_function_bounds(
    file: &MachoFile<'_>,
    symbols: &SymbolTable,
    start_vaddr: u64,
    max_bytes: usize,
) -> Result<FunctionBounds> {
    let text = file
        .find_section("__TEXT", "__text")?
        .ok_or(Error::NoCode)?;
    let text_end = text.addr.saturating_add(text.size);
    if start_vaddr < text.addr || start_vaddr >= text_end {
        return Err(Error::Other(alloc::format!(
            "function start {start_vaddr:#x} outside __text"
        )));
    }

    let mut ends = BTreeSet::new();
    ends.insert(text_end);
    ends.insert(start_vaddr.saturating_add(max_bytes as u64));

    for va in function_start_vaddrs(file)? {
        if va > start_vaddr {
            ends.insert(va);
        }
    }
    for (va, name) in symbols.iter() {
        if va <= start_vaddr || va >= text_end {
            continue;
        }
        if name == "__mh_execute_header" || name.starts_with("l_") {
            continue;
        }
        ends.insert(va);
    }

    let end = ends.iter().copied().next().unwrap_or(text_end);
    if end <= start_vaddr {
        return Err(Error::EmptyFunction);
    }
    Ok(FunctionBounds {
        start: start_vaddr,
        end,
    })
}

/// `LC_FUNCTION_STARTS` as virtual addresses.
pub fn function_start_vaddrs(file: &MachoFile<'_>) -> Result<Vec<u64>> {
    let file_offs = file.function_starts()?;
    if file_offs.is_empty() {
        return Ok(Vec::new());
    }
    let text_seg = file.segments()?.find_map(|s| match s {
        Ok((seg, _)) if cstr16(&seg.segname) == "__TEXT" => Some(seg),
        _ => None,
    });
    let Some(text_seg) = text_seg else {
        return Ok(Vec::new());
    };
    // Parser yields file offsets (base = __TEXT.fileoff + ULEB deltas).
    Ok(file_offs
        .into_iter()
        .map(|fo| {
            if fo >= text_seg.fileoff {
                text_seg
                    .vmaddr
                    .saturating_add(fo.saturating_sub(text_seg.fileoff))
            } else {
                text_seg.vmaddr.saturating_add(fo)
            }
        })
        .collect())
}

/// Read `__TEXT.__text` bytes for `[bounds.start, bounds.end)`.
pub fn read_function_bytes(file: &MachoFile<'_>, bounds: FunctionBounds) -> Result<Vec<u8>> {
    let text = file
        .find_section("__TEXT", "__text")?
        .ok_or(Error::NoCode)?;
    let data = file.section_data(text)?;
    if bounds.start < text.addr {
        return Err(Error::Other(alloc::format!(
            "bounds start {:#x} before __text",
            bounds.start
        )));
    }
    let rel = (bounds.start - text.addr) as usize;
    let len = bounds.len_bytes();
    if rel >= data.len() {
        return Err(Error::EmptyFunction);
    }
    let end = (rel + len).min(data.len());
    Ok(data[rel..end].to_vec())
}
