//! arm64e pointer-authentication helpers (P5-2).
//!
//! PAC sign/auth/strip ops are side-effect free for decompilation: treat them as
//! nops, map authenticated control-flow to the unauthenticated equivalents, and
//! mask signed pointers down to a canonical VA when needed.

use arm_disassembler::Mnemonic;

/// Clear PAC / TBI high bits, keeping a 48-bit userspace VA.
#[inline]
pub fn strip_ptrauth(va: u64) -> u64 {
    va & 0x0000_ffff_ffff_ffff
}

/// True for PAC / AUT / XPAC hint ops that should not appear in C output.
pub fn is_pac_hint(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Pacia
            | Mnemonic::Pacib
            | Mnemonic::Pacda
            | Mnemonic::Pacdb
            | Mnemonic::Paciza
            | Mnemonic::Pacizb
            | Mnemonic::Pacdza
            | Mnemonic::Pacdzb
            | Mnemonic::Pacga
            | Mnemonic::Paciasp
            | Mnemonic::Pacibsp
            | Mnemonic::Paciaz
            | Mnemonic::Pacibz
            | Mnemonic::Pacia1716
            | Mnemonic::Pacib1716
            | Mnemonic::Pacia171615
            | Mnemonic::Pacib171615
            | Mnemonic::Paciasppc
            | Mnemonic::Pacibsppc
            | Mnemonic::Pacnbiasppc
            | Mnemonic::Pacnbibsppc
            | Mnemonic::Autia
            | Mnemonic::Autib
            | Mnemonic::Autda
            | Mnemonic::Autdb
            | Mnemonic::Autiza
            | Mnemonic::Autizb
            | Mnemonic::Autdza
            | Mnemonic::Autdzb
            | Mnemonic::Autiasp
            | Mnemonic::Autibsp
            | Mnemonic::Autiaz
            | Mnemonic::Autibz
            | Mnemonic::Autia1716
            | Mnemonic::Autib1716
            | Mnemonic::Autia171615
            | Mnemonic::Autib171615
            | Mnemonic::Autiasppc
            | Mnemonic::Autibsppc
            | Mnemonic::Xpaci
            | Mnemonic::Xpacd
            | Mnemonic::Xpaclri
    )
}

/// Authenticated return (`retaa` / `retab` / …).
pub fn is_pac_return(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Retaa
            | Mnemonic::Retab
            | Mnemonic::Retaasppc
            | Mnemonic::Retabsppc
            | Mnemonic::Retabsp
    )
}

/// Authenticated indirect call.
pub fn is_pac_call(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Blraa | Mnemonic::Blraaz | Mnemonic::Blrab | Mnemonic::Blrabz
    )
}

/// Authenticated indirect branch.
pub fn is_pac_indirect_br(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Braa | Mnemonic::Braaz | Mnemonic::Brab | Mnemonic::Brabz
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_keeps_low_48() {
        assert_eq!(strip_ptrauth(0xabcd_1234_5678_9abc), 0x0000_1234_5678_9abc);
    }

    #[test]
    fn classifies_common_hints() {
        assert!(is_pac_hint(Mnemonic::Paciasp));
        assert!(is_pac_hint(Mnemonic::Autiasp));
        assert!(is_pac_hint(Mnemonic::Xpaci));
        assert!(is_pac_return(Mnemonic::Retaa));
        assert!(is_pac_call(Mnemonic::Blraa));
        assert!(is_pac_indirect_br(Mnemonic::Braaz));
        assert!(!is_pac_hint(Mnemonic::Ret));
    }
}
