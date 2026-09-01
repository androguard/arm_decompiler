//! Method IR (dex-decompiler-style foundation).
//!
//! Small and permissive: unhandled ARM64 ops fall back to [`Expr::Raw`] / [`Stmt::Raw`].

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarId {
    /// ARM64 register encoding (0–31 for Xn/Wn, 32 = SP, 33 = XZR/WZR sentinel).
    pub reg: u32,
    /// SSA version (0 = unversioned).
    pub ver: u32,
}

impl VarId {
    pub fn new(reg: u32, ver: u32) -> Self {
        Self { reg, ver }
    }

    pub fn from_x(n: u32) -> Self {
        Self::new(n & 31, 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Mul,
    Div,
}

impl BinOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::Mul => "*",
            Self::Div => "/",
        }
    }
}

/// Assignment destination: register or recovered local / high variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    Reg(VarId),
    Name(String),
}

impl Place {
    pub fn to_c(&self) -> String {
        match self {
            Place::Reg(v) => format_var(*v),
            Place::Name(n) => n.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Var(VarId),
    /// Recovered stack local / parameter (Ghidra HighVariable analogue).
    Name(String),
    Imm(u64),
    /// `target(args…)` — C / unresolved call.
    Call {
        target: String,
        args: Vec<Expr>,
    },
    /// ObjC `[receiver selector:args…]` (M4).
    MsgSend {
        receiver: Box<Expr>,
        selector: String,
        args: Vec<Expr>,
        super_call: bool,
    },
    BinOp {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// Memory load / address expression text.
    Mem(String),
    /// Opaque / unlifted fragment.
    Raw(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stmt {
    Assign {
        dst: Place,
        rhs: Expr,
        comment: Option<String>,
    },
    Store {
        addr: Expr,
        value: Expr,
        comment: Option<String>,
    },
    Expr {
        expr: Expr,
        comment: Option<String>,
    },
    Return {
        value: Option<Expr>,
        comment: Option<String>,
    },
    /// Control-flow placeholder (handled by CFG / regions).
    Branch {
        condition: Option<String>,
        target_label: String,
    },
    Label(String),
    Raw(String),
    /// SSA φ at a CFG join (`incomings`: (predecessor block, value)).
    Phi {
        dst: VarId,
        incomings: Vec<(usize, VarId)>,
    },
}

impl Expr {
    pub fn to_c(&self) -> String {
        match self {
            Expr::Var(v) => format_var(*v),
            Expr::Name(n) => n.clone(),
            Expr::Imm(n) => {
                if *n <= 9 {
                    format!("{n}")
                } else {
                    format!("0x{n:x}")
                }
            }
            Expr::Call { target, args } => {
                let a: Vec<String> = args.iter().map(|e| e.to_c()).collect();
                format!("{target}({})", a.join(", "))
            }
            Expr::MsgSend {
                receiver,
                selector,
                args,
                super_call,
            } => {
                let recv = if *super_call {
                    format!("super /* {} */", receiver.to_c())
                } else {
                    receiver.to_c()
                };
                let a: Vec<String> = args.iter().map(|e| e.to_c()).collect();
                crate::objc::format_objc_message(&recv, selector, &a)
            }
            Expr::BinOp { op, lhs, rhs } => {
                format!("({} {} {})", lhs.to_c(), op.as_str(), rhs.to_c())
            }
            Expr::Mem(s) | Expr::Raw(s) => s.clone(),
        }
    }
}

impl Stmt {
    pub fn to_c_line(&self) -> String {
        match self {
            Stmt::Assign { dst, rhs, comment } => {
                append_comment(format!("{} = {};", dst.to_c(), rhs.to_c()), comment)
            }
            Stmt::Store { addr, value, comment } => {
                append_comment(format!("*({}) = {};", addr.to_c(), value.to_c()), comment)
            }
            Stmt::Expr { expr, comment } => {
                append_comment(format!("{};", expr.to_c()), comment)
            }
            Stmt::Return { value, comment } => {
                let base = match value {
                    Some(v) => format!("return {};", v.to_c()),
                    None => String::from("return;"),
                };
                append_comment(base, comment)
            }
            Stmt::Branch {
                condition,
                target_label,
            } => match condition {
                Some(c) => format!("if ({c}) goto {target_label};"),
                None => format!("goto {target_label};"),
            },
            Stmt::Label(l) => format!("{l}:"),
            Stmt::Phi { .. } => String::new(), // stripped before emit
            Stmt::Raw(s) => {
                if s.ends_with(';') {
                    s.clone()
                } else {
                    format!("{s};")
                }
            }
        }
    }
}

pub fn format_var(v: VarId) -> String {
    let base = if v.reg == 32 {
        String::from("sp")
    } else if v.reg == 33 {
        // WZR/XZR reads as zero (Ghidra emits 0).
        String::from("0")
    } else if (64..96).contains(&v.reg) {
        format!("v{}", v.reg - 64)
    } else {
        format!("x{}", v.reg)
    };
    if v.ver == 0 {
        base
    } else {
        format!("{base}_{}", v.ver)
    }
}

fn append_comment(mut base: String, comment: &Option<String>) -> String {
    if let Some(c) = comment {
        base.push_str(" // ");
        base.push_str(c);
    }
    base
}

/// Map arm_disassembler register to [`VarId`] (X-view / V-view).
pub fn var_from_reg(reg: arm_disassembler::Register) -> Option<VarId> {
    use arm_disassembler::Register as R;
    let n = match reg {
        R::X0 | R::W0 => 0,
        R::X1 | R::W1 => 1,
        R::X2 | R::W2 => 2,
        R::X3 | R::W3 => 3,
        R::X4 | R::W4 => 4,
        R::X5 | R::W5 => 5,
        R::X6 | R::W6 => 6,
        R::X7 | R::W7 => 7,
        R::X8 | R::W8 => 8,
        R::X9 | R::W9 => 9,
        R::X10 | R::W10 => 10,
        R::X11 | R::W11 => 11,
        R::X12 | R::W12 => 12,
        R::X13 | R::W13 => 13,
        R::X14 | R::W14 => 14,
        R::X15 | R::W15 => 15,
        R::X16 | R::W16 => 16,
        R::X17 | R::W17 => 17,
        R::X18 | R::W18 => 18,
        R::X19 | R::W19 => 19,
        R::X20 | R::W20 => 20,
        R::X21 | R::W21 => 21,
        R::X22 | R::W22 => 22,
        R::X23 | R::W23 => 23,
        R::X24 | R::W24 => 24,
        R::X25 | R::W25 => 25,
        R::X26 | R::W26 => 26,
        R::X27 | R::W27 => 27,
        R::X28 | R::W28 => 28,
        R::X29 | R::W29 => 29,
        R::X30 | R::W30 => 30,
        R::SP | R::WSP => 32,
        R::XZR | R::WZR => 33,
        // SIMD/FP views → v0–v31 (reg 64+n).
        r if matches!(
            r,
            R::V0
                | R::V1
                | R::V2
                | R::V3
                | R::V4
                | R::V5
                | R::V6
                | R::V7
                | R::V8
                | R::V9
                | R::V10
                | R::V11
                | R::V12
                | R::V13
                | R::V14
                | R::V15
                | R::V16
                | R::V17
                | R::V18
                | R::V19
                | R::V20
                | R::V21
                | R::V22
                | R::V23
                | R::V24
                | R::V25
                | R::V26
                | R::V27
                | R::V28
                | R::V29
                | R::V30
                | R::V31
                | R::Q0
                | R::Q1
                | R::Q2
                | R::Q3
                | R::Q4
                | R::Q5
                | R::Q6
                | R::Q7
                | R::Q8
                | R::Q9
                | R::Q10
                | R::Q11
                | R::Q12
                | R::Q13
                | R::Q14
                | R::Q15
                | R::Q16
                | R::Q17
                | R::Q18
                | R::Q19
                | R::Q20
                | R::Q21
                | R::Q22
                | R::Q23
                | R::Q24
                | R::Q25
                | R::Q26
                | R::Q27
                | R::Q28
                | R::Q29
                | R::Q30
                | R::Q31
                | R::D0
                | R::D1
                | R::D2
                | R::D3
                | R::D4
                | R::D5
                | R::D6
                | R::D7
                | R::D8
                | R::D9
                | R::D10
                | R::D11
                | R::D12
                | R::D13
                | R::D14
                | R::D15
                | R::D16
                | R::D17
                | R::D18
                | R::D19
                | R::D20
                | R::D21
                | R::D22
                | R::D23
                | R::D24
                | R::D25
                | R::D26
                | R::D27
                | R::D28
                | R::D29
                | R::D30
                | R::D31
                | R::S0
                | R::S1
                | R::S2
                | R::S3
                | R::S4
                | R::S5
                | R::S6
                | R::S7
                | R::S8
                | R::S9
                | R::S10
                | R::S11
                | R::S12
                | R::S13
                | R::S14
                | R::S15
                | R::S16
                | R::S17
                | R::S18
                | R::S19
                | R::S20
                | R::S21
                | R::S22
                | R::S23
                | R::S24
                | R::S25
                | R::S26
                | R::S27
                | R::S28
                | R::S29
                | R::S30
                | R::S31
                | R::H0
                | R::H1
                | R::H2
                | R::H3
                | R::H4
                | R::H5
                | R::H6
                | R::H7
                | R::H8
                | R::H9
                | R::H10
                | R::H11
                | R::H12
                | R::H13
                | R::H14
                | R::H15
                | R::H16
                | R::H17
                | R::H18
                | R::H19
                | R::H20
                | R::H21
                | R::H22
                | R::H23
                | R::H24
                | R::H25
                | R::H26
                | R::H27
                | R::H28
                | R::H29
                | R::H30
                | R::H31
                | R::B0
                | R::B1
                | R::B2
                | R::B3
                | R::B4
                | R::B5
                | R::B6
                | R::B7
                | R::B8
                | R::B9
                | R::B10
                | R::B11
                | R::B12
                | R::B13
                | R::B14
                | R::B15
                | R::B16
                | R::B17
                | R::B18
                | R::B19
                | R::B20
                | R::B21
                | R::B22
                | R::B23
                | R::B24
                | R::B25
                | R::B26
                | R::B27
                | R::B28
                | R::B29
                | R::B30
                | R::B31
        ) => 64 + fp_reg_index(r),
        _ => return Option::None,
    };
    Some(VarId::new(n, 0))
}

fn fp_reg_index(reg: arm_disassembler::Register) -> u32 {
    use arm_disassembler::Register as R;
    match reg {
        R::V0 | R::Q0 | R::D0 | R::S0 | R::H0 | R::B0 => 0,
        R::V1 | R::Q1 | R::D1 | R::S1 | R::H1 | R::B1 => 1,
        R::V2 | R::Q2 | R::D2 | R::S2 | R::H2 | R::B2 => 2,
        R::V3 | R::Q3 | R::D3 | R::S3 | R::H3 | R::B3 => 3,
        R::V4 | R::Q4 | R::D4 | R::S4 | R::H4 | R::B4 => 4,
        R::V5 | R::Q5 | R::D5 | R::S5 | R::H5 | R::B5 => 5,
        R::V6 | R::Q6 | R::D6 | R::S6 | R::H6 | R::B6 => 6,
        R::V7 | R::Q7 | R::D7 | R::S7 | R::H7 | R::B7 => 7,
        R::V8 | R::Q8 | R::D8 | R::S8 | R::H8 | R::B8 => 8,
        R::V9 | R::Q9 | R::D9 | R::S9 | R::H9 | R::B9 => 9,
        R::V10 | R::Q10 | R::D10 | R::S10 | R::H10 | R::B10 => 10,
        R::V11 | R::Q11 | R::D11 | R::S11 | R::H11 | R::B11 => 11,
        R::V12 | R::Q12 | R::D12 | R::S12 | R::H12 | R::B12 => 12,
        R::V13 | R::Q13 | R::D13 | R::S13 | R::H13 | R::B13 => 13,
        R::V14 | R::Q14 | R::D14 | R::S14 | R::H14 | R::B14 => 14,
        R::V15 | R::Q15 | R::D15 | R::S15 | R::H15 | R::B15 => 15,
        R::V16 | R::Q16 | R::D16 | R::S16 | R::H16 | R::B16 => 16,
        R::V17 | R::Q17 | R::D17 | R::S17 | R::H17 | R::B17 => 17,
        R::V18 | R::Q18 | R::D18 | R::S18 | R::H18 | R::B18 => 18,
        R::V19 | R::Q19 | R::D19 | R::S19 | R::H19 | R::B19 => 19,
        R::V20 | R::Q20 | R::D20 | R::S20 | R::H20 | R::B20 => 20,
        R::V21 | R::Q21 | R::D21 | R::S21 | R::H21 | R::B21 => 21,
        R::V22 | R::Q22 | R::D22 | R::S22 | R::H22 | R::B22 => 22,
        R::V23 | R::Q23 | R::D23 | R::S23 | R::H23 | R::B23 => 23,
        R::V24 | R::Q24 | R::D24 | R::S24 | R::H24 | R::B24 => 24,
        R::V25 | R::Q25 | R::D25 | R::S25 | R::H25 | R::B25 => 25,
        R::V26 | R::Q26 | R::D26 | R::S26 | R::H26 | R::B26 => 26,
        R::V27 | R::Q27 | R::D27 | R::S27 | R::H27 | R::B27 => 27,
        R::V28 | R::Q28 | R::D28 | R::S28 | R::H28 | R::B28 => 28,
        R::V29 | R::Q29 | R::D29 | R::S29 | R::H29 | R::B29 => 29,
        R::V30 | R::Q30 | R::D30 | R::S30 | R::H30 | R::B30 => 30,
        _ => 31,
    }
}
