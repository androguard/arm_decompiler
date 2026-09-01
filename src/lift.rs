//! Lift ARM64 instructions to IR (dex-decompiler `instructions_to_ir` analogue).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use arm_disassembler::{Formatter, Instruction, Mnemonic, OpKind, SymbolResolver};

use crate::cfg::{
    is_branch, is_call, is_conditional_branch, is_flag_setter, is_pac_elidable, is_return,
};
use crate::ir::{var_from_reg, BinOp, Expr, Place, Stmt, VarId};

pub struct LiftContext<'a, R: SymbolResolver> {
    pub symbols: &'a R,
    pub formatter: Formatter,
}

impl<'a, R: SymbolResolver> LiftContext<'a, R> {
    pub fn lift_insn(&self, insn: &Instruction) -> Vec<Stmt> {
        if insn.is_invalid() {
            return alloc::vec![Stmt::Raw(format!("/* invalid @{:#x} */", insn.vaddr))];
        }
        // Returns must be lifted before the generic branch skip.
        if is_return(insn) {
            return alloc::vec![Stmt::Return {
                value: Some(Expr::Var(VarId::from_x(0))),
                comment: None,
            }];
        }
        // Other branches are represented in the CFG / region tree.
        if is_branch(insn) && !is_call(insn) {
            return Vec::new();
        }
        if is_call(insn) {
            return alloc::vec![self.lift_call(insn)];
        }
        // arm64e PAC/AUT/XPAC — elide (pointer auth is opaque at C level).
        if is_pac_elidable(insn) {
            return Vec::new();
        }

        match insn.mnemonic {
            Mnemonic::Nop => Vec::new(),
            Mnemonic::Mov | Mnemonic::Movz | Mnemonic::Movn | Mnemonic::Movk => {
                self.lift_mov(insn).into_iter().collect()
            }
            Mnemonic::Add | Mnemonic::Adds => self.lift_binop(insn, BinOp::Add),
            Mnemonic::Sub | Mnemonic::Subs => self.lift_binop(insn, BinOp::Sub),
            Mnemonic::And | Mnemonic::Ands => self.lift_binop(insn, BinOp::And),
            Mnemonic::Orr | Mnemonic::Orrs => self.lift_binop(insn, BinOp::Or),
            Mnemonic::Eor | Mnemonic::Eors => self.lift_binop(insn, BinOp::Xor),
            Mnemonic::Lsl => self.lift_binop(insn, BinOp::Shl),
            Mnemonic::Lsr | Mnemonic::Asr => self.lift_binop(insn, BinOp::Shr),
            Mnemonic::Mul | Mnemonic::Madd => self.lift_binop(insn, BinOp::Mul),
            Mnemonic::Fadd => self.lift_binop(insn, BinOp::Add),
            Mnemonic::Fsub => self.lift_binop(insn, BinOp::Sub),
            Mnemonic::Fmul => self.lift_binop(insn, BinOp::Mul),
            Mnemonic::Fdiv => self.lift_binop(insn, BinOp::Div),
            Mnemonic::Fmov => self.lift_mov(insn).into_iter().collect(),
            Mnemonic::Ldr
            | Mnemonic::Ldrb
            | Mnemonic::Ldrh
            | Mnemonic::Ldrsw
            | Mnemonic::Ldur
            | Mnemonic::Ldraa
            | Mnemonic::Ldrab => self.lift_load(insn),
            Mnemonic::Str | Mnemonic::Strb | Mnemonic::Strh | Mnemonic::Stur => {
                self.lift_store(insn)
            }
            // Frame save/restore — recovered in locals.rs, not emitted as Raw.
            Mnemonic::Stp | Mnemonic::Ldp => Vec::new(),
            Mnemonic::Cmp | Mnemonic::Cmn | Mnemonic::Tst => {
                let asm = self.asm(insn);
                alloc::vec![Stmt::Raw(format!("/* {asm} */"))]
            }
            _ => {
                let asm = self.asm(insn);
                alloc::vec![Stmt::Raw(asm)]
            }
        }
    }

    fn asm(&self, insn: &Instruction) -> String {
        self.formatter.format(insn, self.symbols)
    }

    fn lift_call(&self, insn: &Instruction) -> Stmt {
        let target = if matches!(insn.mnemonic, Mnemonic::Bl) {
            let t = insn.near_branch_target;
            self.symbols
                .resolve(t)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("sub_{t:x}"))
        } else {
            // blr xn
            op_reg(insn, 0)
                .map(|v| crate::ir::format_var(v))
                .unwrap_or_else(|| String::from("x?"))
        };
        // Strip assembler quotes around stub names: `"_objc_msgSend$hello:"`
        let target = target.trim().trim_matches('"').to_string();
        // AAPCS64 args filled later by `trim_call_args` from preceding defs.
        let args = Vec::new();
        Stmt::Assign {
            dst: Place::Reg(VarId::from_x(0)),
            rhs: Expr::Call { target, args },
            comment: Some(self.asm(insn)),
        }
    }

    fn lift_mov(&self, insn: &Instruction) -> Option<Stmt> {
        let dst = op_reg(insn, 0)?;
        let rhs = if insn.op1_kind == OpKind::Immediate {
            Expr::Imm(insn.op1_imm)
        } else if let Some(s) = op_reg(insn, 1) {
            Expr::Var(s)
        } else {
            Expr::Raw(self.asm(insn))
        };
        // movk is partial — keep as raw-ish assign of OR pattern when possible
        if insn.mnemonic == Mnemonic::Movk {
            return Some(Stmt::Assign {
                dst: Place::Reg(dst),
                rhs: Expr::Raw(self.asm(insn)),
                comment: None,
            });
        }
        Some(Stmt::Assign {
            dst: Place::Reg(dst),
            rhs,
            comment: None,
        })
    }

    fn lift_binop(&self, insn: &Instruction, op: BinOp) -> Vec<Stmt> {
        let Some(dst) = op_reg(insn, 0) else {
            return alloc::vec![Stmt::Raw(self.asm(insn))];
        };
        let lhs = op_reg(insn, 1)
            .map(Expr::Var)
            .unwrap_or_else(|| Expr::Raw(String::from("?")));
        let rhs = if insn.op2_kind == OpKind::Immediate {
            Expr::Imm(insn.op2_imm)
        } else {
            op_reg(insn, 2)
                .map(Expr::Var)
                .unwrap_or_else(|| Expr::Imm(0))
        };
        alloc::vec![Stmt::Assign {
            dst: Place::Reg(dst),
            rhs: Expr::BinOp {
                op,
                lhs: alloc::boxed::Box::new(lhs),
                rhs: alloc::boxed::Box::new(rhs),
            },
            comment: None,
        }]
    }

    fn lift_load(&self, insn: &Instruction) -> Vec<Stmt> {
        let Some(dst) = op_reg(insn, 0) else {
            return alloc::vec![Stmt::Raw(self.asm(insn))];
        };
        let addr = mem_expr(insn).unwrap_or_else(|| Expr::Raw(self.asm(insn)));
        alloc::vec![Stmt::Assign {
            dst: Place::Reg(dst),
            rhs: Expr::Mem(format!("*({})", addr.to_c())),
            comment: None,
        }]
    }

    fn lift_store(&self, insn: &Instruction) -> Vec<Stmt> {
        let Some(val) = op_reg(insn, 0) else {
            return alloc::vec![Stmt::Raw(self.asm(insn))];
        };
        let addr = mem_expr(insn).unwrap_or_else(|| Expr::Raw(String::from("?")));
        alloc::vec![Stmt::Store {
            addr,
            value: Expr::Var(val),
            comment: None,
        }]
    }
}

fn op_reg(insn: &Instruction, idx: u8) -> Option<VarId> {
    let (kind, reg) = match idx {
        0 => (insn.op0_kind, insn.op0_reg),
        1 => (insn.op1_kind, insn.op1_reg),
        2 => (insn.op2_kind, insn.op2_reg),
        3 => (insn.op3_kind, insn.op3_reg),
        _ => return None,
    };
    if kind != OpKind::Register {
        return None;
    }
    var_from_reg(reg)
}

fn mem_expr(insn: &Instruction) -> Option<Expr> {
    use arm_disassembler::Register;
    if insn.memory_base == Register::None {
        return None;
    }
    let base = var_from_reg(insn.memory_base)?;
    if insn.memory_offset != 0 {
        Some(Expr::BinOp {
            op: if insn.memory_offset >= 0 {
                BinOp::Add
            } else {
                BinOp::Sub
            },
            lhs: alloc::boxed::Box::new(Expr::Var(base)),
            rhs: alloc::boxed::Box::new(Expr::Imm(insn.memory_offset.unsigned_abs() as u64)),
        })
    } else {
        Some(Expr::Var(base))
    }
}

/// Lift a contiguous instruction list (one basic block body, excluding terminator CF).
pub fn lift_block<R: SymbolResolver>(insns: &[Instruction], symbols: &R) -> Vec<Stmt> {
    let ctx = LiftContext {
        symbols,
        formatter: Formatter::new(),
    };
    let mut out = Vec::new();
    for (i, insn) in insns.iter().enumerate() {
        // Skip cmp/tst folded into the next conditional branch.
        if is_flag_setter(insn) {
            if let Some(next) = insns.get(i + 1) {
                if is_conditional_branch(next) {
                    continue;
                }
            }
        }
        out.extend(ctx.lift_insn(insn));
    }
    trim_call_args(&mut out);
    out
}

/// Infer call argc from consecutive `x0..` defs earlier in the same block.
fn trim_call_args(stmts: &mut [Stmt]) {
    let mut def_upto: u32 = 0;
    for s in stmts.iter_mut() {
        match s {
            Stmt::Assign {
                dst: Place::Reg(_),
                rhs: Expr::Call { args, .. },
                ..
            } => {
                let n = def_upto.min(8) as usize;
                *args = (0..n).map(|i| Expr::Var(VarId::from_x(i as u32))).collect();
                def_upto = 1;
            }
            Stmt::Assign {
                dst: Place::Reg(v),
                ..
            } if v.reg < 8 => {
                if v.reg == 0 {
                    def_upto = def_upto.max(1);
                }
                if v.reg < 8 {
                    def_upto = def_upto.max(v.reg + 1);
                }
            }
            _ => {}
        }
    }
}
