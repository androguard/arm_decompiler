//! JSON export of decompilation results (M5 / P4-5).
//!
//! Hand-rolled (no serde) so the crate stays `no_std` + `alloc`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::cfg::{BlockEnd, FunctionCfg};
use crate::decompile::FunctionDecompile;
use crate::ir::Stmt;
use crate::locals::FrameRecovery;

/// Serialize a decompilation to a compact JSON object.
pub fn function_to_json(f: &FunctionDecompile) -> String {
    let mut out = String::new();
    out.push('{');
    field_str(&mut out, "name", &f.name, true);
    if let Some(d) = &f.demangled_name {
        field_str(&mut out, "demangled", d, false);
    }
    field_str(&mut out, "mode", crate::modes::mode_name(f.mode_used), false);
    out.push_str(",\"unwind\":{");
    out.push_str("\"unwind_info\":");
    out.push_str(if f.unwind_hints.has_unwind_info {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"compact_unwind\":");
    out.push_str(if f.unwind_hints.has_compact_unwind {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"dwarf\":");
    out.push_str(if f.unwind_hints.has_dwarf_debug_info {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"arm64e\":");
    out.push_str(if f.unwind_hints.is_arm64e {
        "true"
    } else {
        "false"
    });
    out.push('}');
    field_hex(&mut out, "start_vaddr", f.start_vaddr, false);
    field_hex(&mut out, "end_vaddr", f.end_vaddr, false);
    out.push_str(",\"frame\":");
    frame_to_json(&mut out, &f.frame);
    out.push_str(",\"cfg\":");
    cfg_to_json(&mut out, &f.cfg);
    out.push_str(",\"blocks\":");
    blocks_to_json(&mut out, &f.block_stmts);
    out.push_str(",\"source\":");
    push_json_string(&mut out, &f.source);
    out.push_str(",\"tokens\":");
    out.push_str(&crate::tokens::tokens_to_json(&f.tokens));
    out.push_str(",\"findings\":[");
    for (i, finding) in f.findings.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        field_str(&mut out, "source_kind", finding.source_kind.as_str(), true);
        field_str(&mut out, "sink_kind", finding.sink_kind.as_str(), false);
        field_str(&mut out, "source", &finding.source_label, false);
        field_str(&mut out, "sink", &finding.sink_label, false);
        field_str(&mut out, "name", &finding.tainted_name, false);
        field_str(&mut out, "detail", &finding.detail, false);
        out.push('}');
    }
    out.push_str("],\"jump_tables\":[");
    for (i, jt) in f.jump_tables.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        field_str(&mut out, "summary", &jt.summary, true);
        field_u64(&mut out, "max_index", jt.max_index, false);
        field_u64(&mut out, "cases", jt.cases.len() as u64, false);
        out.push('}');
    }
    out.push_str("]}");
    out
}

fn frame_to_json(out: &mut String, frame: &FrameRecovery) {
    out.push('{');
    field_u64(out, "frame_size", frame.frame_size, true);
    out.push_str(",\"fp_off\":");
    match frame.fp_off {
        Some(n) => out.push_str(&format!("{n}")),
        None => out.push_str("null"),
    }
    out.push_str(",\"params\":");
    string_array(out, &frame.params);
    out.push_str(",\"locals\":");
    string_array(out, &frame.locals);
    out.push_str(",\"local_types\":{");
    let mut first = true;
    for (name, ty) in &frame.local_types {
        if !first {
            out.push(',');
        }
        first = false;
        push_json_string(out, name);
        out.push(':');
        push_json_string(out, ty.as_c_str());
    }
    out.push_str("},\"returns_value\":");
    out.push_str(if frame.returns_value { "true" } else { "false" });
    out.push_str(",\"return_ty\":");
    push_json_string(out, frame.return_ty.as_proto_str());
    out.push('}');
}

fn cfg_to_json(out: &mut String, cfg: &FunctionCfg) {
    out.push('{');
    field_u64(out, "entry", cfg.entry as u64, true);
    out.push_str(",\"loop_headers\":[");
    for (i, id) in cfg.loop_headers.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{id}"));
    }
    out.push_str("],\"blocks\":[");
    for (i, b) in cfg.blocks.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        field_u64(out, "id", i as u64, true);
        field_hex(out, "start", b.start_vaddr, false);
        field_hex(out, "end", b.end_vaddr, false);
        out.push_str(",\"end\":");
        block_end_to_json(out, &b.end);
        out.push('}');
    }
    out.push_str("]}");
}

fn block_end_to_json(out: &mut String, end: &BlockEnd) {
    match end {
        BlockEnd::FallThrough => out.push_str("{\"kind\":\"fallthrough\"}"),
        BlockEnd::Goto(t) => {
            out.push_str(&format!("{{\"kind\":\"goto\",\"target\":{t}}}"));
        }
        BlockEnd::Conditional {
            condition,
            branch_target,
            fall_through,
        } => {
            out.push_str("{\"kind\":\"conditional\",\"condition\":");
            push_json_string(out, condition);
            out.push_str(&format!(
                ",\"branch\":{branch_target},\"fallthrough\":{fall_through}}}"
            ));
        }
        BlockEnd::Exit => out.push_str("{\"kind\":\"exit\"}"),
    }
}

fn blocks_to_json(out: &mut String, blocks: &[Vec<Stmt>]) {
    out.push('[');
    for (i, stmts) in blocks.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('[');
        for (j, s) in stmts.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            let line = s.to_c_line();
            if line.is_empty() {
                push_json_string(out, "/* phi */");
            } else {
                push_json_string(out, &line);
            }
        }
        out.push(']');
    }
    out.push(']');
}

fn string_array(out: &mut String, items: &[String]) {
    out.push('[');
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_string(out, s);
    }
    out.push(']');
}

fn field_str(out: &mut String, key: &str, val: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    push_json_string(out, val);
}

fn field_hex(out: &mut String, key: &str, val: u64, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    out.push_str(&format!("0x{val:x}"));
    out.push('"');
}

fn field_u64(out: &mut String, key: &str, val: u64, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(&format!("{val}"));
}

fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Stable filename stem for a symbol (`_main` → `_main`, `-[Foo bar:]` → `Foo_bar_`).
pub fn symbol_to_filename(symbol: &str) -> String {
    let mut out = String::new();
    for ch in symbol.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '.' => out.push(ch),
            _ => out.push('_'),
        }
    }
    if out.is_empty() {
        String::from("fn")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::FunctionBounds;
    use crate::cfg::FunctionCfg;
    use alloc::collections::BTreeMap;

    #[test]
    fn escapes_source_newlines() {
        let f = FunctionDecompile {
            name: String::from("_add1"),
            start_vaddr: 0x1000,
            end_vaddr: 0x1010,
            bounds: FunctionBounds {
                start: 0x1000,
                end: 0x1010,
            },
            cfg: FunctionCfg {
                blocks: Vec::new(),
                block_by_start: BTreeMap::new(),
                loop_headers: Default::default(),
                entry: 0,
            },
            block_stmts: Vec::new(),
            frame: FrameRecovery::default(),
            source: String::from("int _add1(void) {\n    return 1;\n}\n"),
            mode_used: crate::DecompilationMode::Restructure,
            unwind_hints: crate::dwarf::UnwindHints::default(),
            tokens: Vec::new(),
            demangled_name: None,
            findings: Vec::new(),
            jump_tables: Vec::new(),
        };
        let j = function_to_json(&f);
        assert!(j.contains("\\n"));
        assert!(j.contains("\"name\":\"_add1\""));
        assert!(j.contains("0x1000"));
    }

    #[test]
    fn filename_sanitizes_objc() {
        assert_eq!(symbol_to_filename("-[Foo bar:]"), "-_Foo_bar__");
        assert_eq!(symbol_to_filename("_main"), "_main");
    }
}
