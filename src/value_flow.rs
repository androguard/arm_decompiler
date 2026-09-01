//! Intra-procedural value-flow / taint hooks (M6 / P5-4).
//!
//! Tracks tainted names through assignments and reports source→sink flows.
//! Modeled after dex-decompiler’s value-flow spirit, kept deliberately small.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::ir::{Expr, Place, Stmt};

/// A named taint kind (source or sink family).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaintKind {
    UserInput,
    Clipboard,
    DeviceId,
    Network,
    Logging,
    CodeExecution,
    FileWrite,
    Sql,
}

impl TaintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserInput => "UserInput",
            Self::Clipboard => "Clipboard",
            Self::DeviceId => "DeviceId",
            Self::Network => "Network",
            Self::Logging => "Logging",
            Self::CodeExecution => "CodeExecution",
            Self::FileWrite => "FileWrite",
            Self::Sql => "Sql",
        }
    }
}

/// One source→sink finding inside a function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowFinding {
    pub source_kind: TaintKind,
    pub sink_kind: TaintKind,
    pub source_label: String,
    pub sink_label: String,
    pub tainted_name: String,
    pub detail: String,
}

/// Built-in iOS / libc patterns (substring match on call targets / selectors).
pub struct FlowRules {
    pub sources: Vec<SourceRule>,
    pub sinks: Vec<SinkRule>,
}

#[derive(Clone, Debug)]
pub struct SourceRule {
    pub patterns: &'static [&'static str],
    pub kind: TaintKind,
}

#[derive(Clone, Debug)]
pub struct SinkRule {
    pub patterns: &'static [&'static str],
    pub kind: TaintKind,
    /// Which call arg is the sink port (0-based). `None` = any arg.
    pub arg: Option<usize>,
}

impl Default for FlowRules {
    fn default() -> Self {
        Self {
            sources: alloc::vec![
                SourceRule {
                    patterns: &[
                        "UIPasteboard",
                        "generalPasteboard",
                        "stringForPasteboardType",
                    ],
                    kind: TaintKind::Clipboard,
                },
                SourceRule {
                    patterns: &["UITextField", "textField.text", "stringValue"],
                    kind: TaintKind::UserInput,
                },
                SourceRule {
                    patterns: &[
                        "identifierForVendor",
                        "advertisingIdentifier",
                        "NSUUID",
                    ],
                    kind: TaintKind::DeviceId,
                },
                SourceRule {
                    patterns: &["getenv", "NSUserDefaults", "objectForKey"],
                    kind: TaintKind::UserInput,
                },
            ],
            sinks: alloc::vec![
                SinkRule {
                    patterns: &["NSLog", "os_log", "printf", "fprintf", "puts"],
                    kind: TaintKind::Logging,
                    arg: None,
                },
                SinkRule {
                    patterns: &["system", "popen", "execve", "posix_spawn"],
                    kind: TaintKind::CodeExecution,
                    arg: Some(0),
                },
                SinkRule {
                    patterns: &[
                        "NSURLConnection",
                        "dataTaskWithURL",
                        "dataTaskWithRequest",
                        "sendSynchronousRequest",
                    ],
                    kind: TaintKind::Network,
                    arg: None,
                },
                SinkRule {
                    patterns: &["writeToFile", "writeToURL", "NSFileHandle", "fopen", "fwrite"],
                    kind: TaintKind::FileWrite,
                    arg: None,
                },
                SinkRule {
                    patterns: &["sqlite3_exec", "executeQuery", "executeUpdate"],
                    kind: TaintKind::Sql,
                    arg: None,
                },
            ],
        }
    }
}

fn target_matches(target: &str, patterns: &[&str]) -> bool {
    let t = target.trim().trim_matches('"').trim_start_matches('_');
    patterns.iter().any(|p| t.contains(p))
}

fn classify_source(target: &str, sel: Option<&str>, rules: &FlowRules) -> Option<TaintKind> {
    for r in &rules.sources {
        if target_matches(target, r.patterns) {
            return Some(r.kind);
        }
        if let Some(s) = sel {
            if r.patterns.iter().any(|p| s.contains(p)) {
                return Some(r.kind);
            }
        }
    }
    None
}

fn classify_sink(
    target: &str,
    sel: Option<&str>,
    rules: &FlowRules,
) -> Option<(TaintKind, Option<usize>)> {
    for r in &rules.sinks {
        if target_matches(target, r.patterns) {
            return Some((r.kind, r.arg));
        }
        if let Some(s) = sel {
            if r.patterns.iter().any(|p| s.contains(p)) {
                return Some((r.kind, r.arg));
            }
        }
    }
    None
}

fn expr_names(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Name(n) => out.push(n.clone()),
        Expr::BinOp { lhs, rhs, .. } => {
            expr_names(lhs, out);
            expr_names(rhs, out);
        }
        Expr::Call { args, .. } => {
            for a in args {
                expr_names(a, out);
            }
        }
        Expr::MsgSend {
            receiver, args, ..
        } => {
            expr_names(receiver, out);
            for a in args {
                expr_names(a, out);
            }
        }
        _ => {}
    }
}

/// Analyze IR blocks for tainted name flows into sink calls / message sends.
pub fn analyze_flows(block_stmts: &[Vec<Stmt>], rules: &FlowRules) -> Vec<FlowFinding> {
    // name → (kind, source label)
    let mut tainted: BTreeMap<String, (TaintKind, String)> = BTreeMap::new();
    let mut findings = Vec::new();

    for stmts in block_stmts {
        for s in stmts {
            match s {
                Stmt::Assign { dst, rhs, .. } => {
                    // Source: call / msgsend result
                    if let Some((kind, label)) = source_from_expr(rhs, rules) {
                        match dst {
                            Place::Name(n) => {
                                tainted.insert(n.clone(), (kind, label));
                            }
                            Place::Reg(_) => {
                                // Keep ephemeral: next assign to Name may copy via separate stmt.
                            }
                        }
                    }
                    // Propagation: dst = tainted_name / expr mentioning tainted
                    if let Place::Name(n) = dst {
                        if let Some((k, lab)) = taint_of_expr(rhs, &tainted) {
                            tainted.insert(n.clone(), (k, lab));
                        } else if !matches!(rhs, Expr::Call { .. } | Expr::MsgSend { .. }) {
                            // Overwrite clears taint unless rhs carries it.
                            // Keep if rhs is pure Name already handled above.
                        }
                    }
                    // Sink on RHS expression statement-like assigns (x0 = NSLog(...))
                    collect_sink_findings(rhs, &tainted, rules, &mut findings);
                }
                Stmt::Expr { expr, .. } => {
                    collect_sink_findings(expr, &tainted, rules, &mut findings);
                }
                Stmt::Store { value, .. } => {
                    collect_sink_findings(value, &tainted, rules, &mut findings);
                }
                _ => {}
            }
        }
    }
    findings
}

fn source_from_expr(expr: &Expr, rules: &FlowRules) -> Option<(TaintKind, String)> {
    match expr {
        Expr::Call { target, .. } => {
            let kind = classify_source(target, None, rules)?;
            Some((kind, target.clone()))
        }
        Expr::MsgSend {
            selector,
            receiver,
            ..
        } => {
            let kind = classify_source("", Some(selector), rules)
                .or_else(|| classify_source(&receiver.to_c(), Some(selector), rules))?;
            Some((kind, format!("[{} {}]", receiver.to_c(), selector)))
        }
        _ => None,
    }
}

fn taint_of_expr(
    expr: &Expr,
    tainted: &BTreeMap<String, (TaintKind, String)>,
) -> Option<(TaintKind, String)> {
    let mut names = Vec::new();
    expr_names(expr, &mut names);
    for n in names {
        if let Some(t) = tainted.get(&n) {
            return Some(t.clone());
        }
    }
    None
}

fn collect_sink_findings(
    expr: &Expr,
    tainted: &BTreeMap<String, (TaintKind, String)>,
    rules: &FlowRules,
    out: &mut Vec<FlowFinding>,
) {
    match expr {
        Expr::Call { target, args } => {
            if let Some((sink_kind, port)) = classify_sink(target, None, rules) {
                check_args(target, None, args, port, sink_kind, tainted, out);
            }
            for a in args {
                collect_sink_findings(a, tainted, rules, out);
            }
        }
        Expr::MsgSend {
            receiver,
            selector,
            args,
            ..
        } => {
            if let Some((sink_kind, port)) = classify_sink("", Some(selector), rules) {
                let mut all = alloc::vec![receiver.as_ref().clone()];
                all.extend(args.iter().cloned());
                check_args(
                    &format!("[{} {}]", receiver.to_c(), selector),
                    Some(selector),
                    &all,
                    port,
                    sink_kind,
                    tainted,
                    out,
                );
            }
            collect_sink_findings(receiver, tainted, rules, out);
            for a in args {
                collect_sink_findings(a, tainted, rules, out);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_sink_findings(lhs, tainted, rules, out);
            collect_sink_findings(rhs, tainted, rules, out);
        }
        _ => {}
    }
}

fn check_args(
    sink_label: &str,
    _sel: Option<&str>,
    args: &[Expr],
    port: Option<usize>,
    sink_kind: TaintKind,
    tainted: &BTreeMap<String, (TaintKind, String)>,
    out: &mut Vec<FlowFinding>,
) {
    let indices: Vec<usize> = match port {
        Some(i) => alloc::vec![i],
        None => (0..args.len()).collect(),
    };
    for i in indices {
        let Some(arg) = args.get(i) else { continue };
        let mut names = Vec::new();
        expr_names(arg, &mut names);
        for n in names {
            if let Some((src_kind, src_label)) = tainted.get(&n) {
                out.push(FlowFinding {
                    source_kind: *src_kind,
                    sink_kind,
                    source_label: src_label.clone(),
                    sink_label: sink_label.to_string(),
                    tainted_name: n.clone(),
                    detail: format!(
                        "{} → {} via `{n}` ({}/{})",
                        src_kind.as_str(),
                        sink_kind.as_str(),
                        src_label,
                        sink_label
                    ),
                });
            }
        }
    }
}

/// Convenience: default rules over a function’s IR.
pub fn analyze_flows_default(block_stmts: &[Vec<Stmt>]) -> Vec<FlowFinding> {
    analyze_flows(block_stmts, &FlowRules::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::VarId;
    use alloc::vec;

    #[test]
    fn detects_clipboard_to_nslog() {
        let blocks = vec![vec![
            Stmt::Assign {
                dst: Place::Name(String::from("local_10")),
                rhs: Expr::MsgSend {
                    receiver: alloc::boxed::Box::new(Expr::Name(String::from("pb"))),
                    selector: String::from("stringForPasteboardType:"),
                    args: vec![Expr::Imm(0)],
                    super_call: false,
                },
                comment: None,
            },
            Stmt::Assign {
                dst: Place::Reg(VarId::from_x(0)),
                rhs: Expr::Call {
                    target: String::from("_NSLog"),
                    args: vec![
                        Expr::Name(String::from("fmt")),
                        Expr::Name(String::from("local_10")),
                    ],
                },
                comment: None,
            },
        ]];
        let findings = analyze_flows_default(&blocks);
        assert!(
            !findings.is_empty(),
            "expected clipboard→NSLog finding"
        );
        assert_eq!(findings[0].source_kind, TaintKind::Clipboard);
        assert_eq!(findings[0].sink_kind, TaintKind::Logging);
        assert_eq!(findings[0].tainted_name, "local_10");
    }

    #[test]
    fn getenv_to_system() {
        let blocks = vec![vec![
            Stmt::Assign {
                dst: Place::Name(String::from("cmd")),
                rhs: Expr::Call {
                    target: String::from("_getenv"),
                    args: vec![Expr::Name(String::from("k"))],
                },
                comment: None,
            },
            Stmt::Expr {
                expr: Expr::Call {
                    target: String::from("_system"),
                    args: vec![Expr::Name(String::from("cmd"))],
                },
                comment: None,
            },
        ]];
        let findings = analyze_flows_default(&blocks);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].sink_kind, TaintKind::CodeExecution);
    }
}
