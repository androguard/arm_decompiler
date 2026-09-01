# arm_decompiler

ARM64 → C-like decompiler (Mach-O / IPA today; ELF / Android planned),
using the same pipeline shape as
[dex-decompiler](https://github.com/androguard/dex-decompiler).
Consumed by [apple-re](https://github.com/androguard/apple-re) as a sibling path dependency.

```
  ┌─────────────┐
  │ Mach-O/IPA  │
  └──────┬──────┘
         │  macho_core + apple_metadata
         v
  ┌─────────────┐
  │  ARM64 insn │   arm_disassembler decode
  │   stream    │
  └──────┬──────┘
         │
         v  FunctionCfg
  ┌─────────────┐
  │  CFG        │   blocks, edges, loop headers
  └──────┬──────┘
         │
         v  lift (per block)
  ┌─────────────┐
  │  IR         │   Assign / Call / Return / Raw
  └──────┬──────┘
         │
         v  PassRunner
  ┌─────────────┐
  │  IR (clean) │   RedundantMov, ExprSimplify, DeadAssign
  └──────┬──────┘
         │
         v  construct_ssa + post-SSA cleanup (M2)
  ┌─────────────┐
  │  SSA + φ    │   dominators, rename, copy-prop, inline, φ stripped at emit
  └──────┬──────┘
         │
         v  recover_frame
  ┌─────────────┐
  │  Locals     │   stack slots → local_N, AAPCS64 params
  └──────┬──────┘
         │
         v  build_regions
  ┌─────────────┐
  │  Region     │   Block / Seq / If / Loop
  └──────┬──────┘
         │
         v  emit
  ┌─────────────┐
  │  C-like     │
  │  source     │
  └─────────────┘
```

## Status

Foundation crate: CFG + lift + passes + regions + emit.

**M1 done:** function bounds (`LC_FUNCTION_STARTS` + symbols), `cmp`/`subs`→branch
predicate fold, fixture harness (`testdata/m1_bounds`).

**M2 done:** CFG dominators, SSA (φ + rename), stack locals / AAPCS64 params,
SSA copy-prop / DCE passes, φ stripped at emit. `_main` decompiles with named
locals instead of register soup.

**M3 done:** `else if` flattening, `switch`/`case` from cmp cascades, `for`
recovery, loop if-join so continue tails aren’t duplicated. Jump-table recovery
still deferred.

**M4 in progress:** `objc_msgSend$sel:` → `[recv sel:args]`; ObjC smoke fixtures
(`_cd_smoke_call` / `_cd_smoke_sum`). ARC/`self` recovery still noisy.

**Roadmap:** see [`ARM64_DECOMPILER_PLAN.md`](./ARM64_DECOMPILER_PLAN.md).  
**Swift ↔ Ghidra alignment:** [`SWIFT_GHIDRA_ALIGNMENT.md`](./SWIFT_GHIDRA_ALIGNMENT.md).  
**Test plan / scoreboard:** [`DECOMPILER_TEST_PLAN.md`](./DECOMPILER_TEST_PLAN.md)  
**Fixture catalog:** [`DECOMPILER_FIXTURES.md`](./DECOMPILER_FIXTURES.md).

## Library

```rust
use arm_decompiler::{decompile_macho_symbol, DecompilerOptions};

let r = decompile_macho_symbol(macho_bytes, "_main", &DecompilerOptions::default())?;
println!("{}", r.source);
```

## CLI

```bash
apple-re decompile App.ipa -n _main
apple-re decompile ./binary -n '-[CDSmoke hello:]' --asm
apple-re decompile ./binary -n _main --simple
```
