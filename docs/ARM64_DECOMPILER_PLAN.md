# ARM64 decompiler plan (`arm_decompiler`)

Living roadmap for turning the current foundation into a serious ARM64 → C/ObjC
decompiler. Informed by:

- **[dex-decompiler](https://github.com/androguard/dex-decompiler)** — Rust CFG → IR →
  `PassRunner` → regions → emit; SSA/φ; value-flow; simplify; modes
  (`Restructure` / `Simple` / `Fallback`). See also its
  [`docs/JADX_GAP_PLAN.md`](../../dex-decompiler/docs/JADX_GAP_PLAN.md).
- **[Ghidra Decompiler](https://github.com/NationalSecurityAgency/ghidra/tree/b070495c0bdfe96b12469550a9bc76131f6c4dd7/Ghidra/Features/Decompiler)** —
  C++ engine (`Funcdata`, p-code, `Heritage` SSA, `Merge`/`HighVariable`, structured
  `BlockGraph`, `Action` pipeline) plus Java front-end
  ([`ghidra.app.decompiler`](https://github.com/NationalSecurityAgency/ghidra/tree/b070495c0bdfe96b12469550a9bc76131f6c4dd7/Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler):
  `DecompInterface`, `DecompileResults`, `ClangToken` / `ClangTokenGroup` markup,
  `PrettyPrinter`, options, caching).

**Last updated:** 2026-09-01 (Phase 6 Swift decompiler)  
**Status key:** `todo` | `doing` | `done` | `wontfix`

---

## 1. Positioning

| | dex-decompiler | Ghidra | apple-re `arm_decompiler` (goal) |
|--|----------------|--------|----------------------------------|
| Input | DEX / APK | Any SLEIGH arch | Mach-O / IPA / ObjC / Swift (ARM64 first) |
| IR | Method IR over Dalvik | p-code `Varnode`/`PcodeOp` | ARM64-lifted IR → optional micro-ops |
| Strength | Embeddable Rust; taint; detectors | Deep SSA, types, structure, jump tables | Same Rust stack as apple-re; ObjC/Swift-aware |
| Weakness | Dalvik-only | Heavy; C++ process; not ObjC-native | Early foundation today |

**Do chase:** readable function bodies, ObjC message recovery, Swift `func` emit, stack locals, structured CF,
symbol/debug-aware naming, class-dump integration, value-flow hooks for future scanners.

**Do not chase (unless goals change):** full Ghidra GUI / Clang markup editor, SLEIGH for all
CPUs, perfect ISO C, bit-identical vs Hex-Rays, SIL-level / full generics / async fidelity.

---

## 2. Current state (foundation)

Already in `arm_decompiler` (dex-shaped skeleton):

| Stage | Module | Today |
|-------|--------|--------|
| Decode | `arm_disassembler` | Linear decode + formatter |
| CFG | `cfg.rs` | Leaders, blocks, cond/goto/exit, loop headers |
| Lift | `lift.rs` | mov/add/ldr/str/bl/ret; else `Raw` |
| Passes | `pass.rs` | RedundantMov, ExprSimplify, DeadAssign |
| Regions | `region.rs` | Naive If / Loop / Seq |
| Emit | `emit.rs` | C-like `void name() { … }` |
| API/CLI | `decompile.rs`, `apple-re decompile` | Symbol → source |

Gaps vs dex-decompiler / Ghidra: no SSA/φ, no stack-frame recovery, no AAPCS64 prototype,
weak structure, no ObjC idioms, no typed AST / pretty tokens, no fixture harness.

---

## 3. Target architecture

Mirror **dex-decompiler’s pipeline** for product shape; borrow **Ghidra’s analysis depth**
where it pays off for native code (without requiring a p-code VM on day one).

```
 IPA / Mach-O / framework
        │
        ▼
 ┌──────────────────┐
 │ Function bounds  │  symbols, LC_FUNCTION_STARTS, ObjC IMPs, eh_frame (later)
 └────────┬─────────┘
          ▼
 ┌──────────────────┐
 │ Decode + CFG     │  arm_disassembler → FunctionCfg (dominators, back-edges, switch)
 └────────┬─────────┘
          ▼
 ┌──────────────────┐
 │ Lift to IR       │  register/stack/memory ops; calls; flags as predicates
 │  (optional μops) │  Ghidra-like: normalize before SSA
 └────────┬─────────┘
          ▼
 ┌──────────────────┐
 │ SSA / Heritage   │  φ at join points; versioned VarId (dex ssa.rs pattern)
 └────────┬─────────┘
          ▼
 ┌──────────────────┐
 │ Local recovery   │  Ghidra Merge/HighVariable analogue: stack slots → locals
 │ + prototype      │  AAPCS64 args/return; callee-saved; FP/LR frame
 └────────┬─────────┘
          ▼
 ┌──────────────────┐
 │ PassRunner       │  copy-prop, const fold, dead, call folding, ObjC idioms
 └────────┬─────────┘
          ▼
 ┌──────────────────┐
 │ Region builder   │  if/else, while/do-while/for, switch, break/continue
 │ + fallback modes │  Restructure | Simple | Fallback (dex DecompilationMode)
 └────────┬─────────┘
          ▼
 ┌──────────────────┐
 │ Emit + markup    │  ObjC/C source; optional token spans (Ghidra Clang* idea)
 └──────────────────┘
          │
          ▼
 value_flow / detectors (later, dex taint path)
```

### Conceptual mapping

| Ghidra | dex-decompiler | arm_decompiler (planned) |
|--------|----------------|---------------------------|
| SLEIGH → p-code | Dalvik decode | `arm_disassembler` → IR (maybe `MicroOp` later) |
| `Funcdata` | per-method CFG+IR | `FunctionDecompile` + `FuncContext` |
| `Heritage` | `ssa.rs` φ + rename | `ssa.rs` |
| `Merge` / `HighVariable` | type_infer + rename | `locals.rs` + `types.rs` |
| `BlockGraph` structure | `region.rs` | strengthen `region.rs` |
| `Action` groups | `Pass` / `PassRunner` | keep + phase groups |
| `DecompInterface` / results | `Decompiler` API | expand `decompile.rs` |
| `ClangToken*` / PrettyPrinter | Java emit + simplify | `emit` + optional `tokens` |
| Jump-table recovery | switch from DEX | `switch` from cmp/br chains + tables |

The Java package under `ghidra.app.decompiler` is mostly **UI/API/markup** around the C++
engine. We should copy its *ideas* (options, results object, address↔token map, pretty
print) — not reimplement the Swing panel.

---

## 4. Phased backlog

### Phase 0 — Correctness baseline (P0)

| ID | Item | Status | Notes |
|----|------|--------|-------|
| P0-1 | Function bounds: stop at next symbol / function_starts, not only first `ret` | done | `bounds.rs` (M1) |
| P0-2 | Dominator tree + proper back-edge / loop nesting | done | `cfg.rs` immediate dominators (M2) |
| P0-3 | CFG: `cbz`/`tbz`/`b.cond` condition exprs tied to prior `cmp`/`tst` | done | Also `subs`/`adds` (M1) |
| P0-4 | AAPCS64 calling convention model | done | Params `param_N` + `undefined8` prototype (M2) |
| P0-5 | Frame recovery: `stp x29,x30`, SP adjust → locals | done | SP + FP (`x29±`) → `local_<hex>`; stp/ldp elided (M2) |
| P0-6 | Fixture harness + golden sources | done | `testdata/m1_bounds` + `tests/m1_fixtures.rs` |
| P0-7 | Modes: Restructure / Simple / Fallback hardened | done | `modes.rs`; Cond→if/goto; auto-downgrade; CLI `--mode` |

**Exit criteria:** `_main` and simple leaf functions decompile without bogus early exit;
stack prologue not emitted as nonsense `sp = sp - N` only. **(M1 met for bounds + fold + fixtures.)**

### Phase 1 — SSA + locals (P0/P1) — *Ghidra Heritage / Merge*

| ID | Item | Status | Notes |
|----|------|--------|-------|
| P1-1 | CFG SSA with φ-nodes (`VarId.ver`) | done | `ssa.rs` Cytron + dominators in `cfg.rs` (M2) |
| P1-2 | Copy propagation + const folding on SSA | done | `ssa_copy_prop`, `inline_ssa_reg_defs`, `fold_call_result_refs` (M2) |
| P1-3 | Dead code on SSA (fix P0 DCE) | done | `dead_ssa_version_assigns`, `RedundantArgLoadPass`, SSA-aware collapse (M2) |
| P1-4 | Stack slot → `local_N` / typed locals | done | Ghidra offsets + `int`/`id`/`void *` lattice |
| P1-5 | Parameter recovery from first-block uses of xN | done | Prologue spills → `param_1`… |
| P1-6 | Return value typing (void vs x0) | done | `void` / `int` / `id` / `undefined8` via `return_ty` |

**Exit criteria:** Register soup reduced; locals look like C variables; φs stripped at emit. **(M2 met: `_main` + leaf fixtures pass scoreboard.)**

### Phase 2 — Structure recovery (P1) — *dex regions + Ghidra BlockGraph*

| ID | Item | Status | Notes |
|----|------|--------|-------|
| P2-1 | Diamond if/else with join detection | done | Join + clang `-O0` empty `b` stubs (M2) |
| P2-2 | while / do-while / for patterns | done | `for` recovered from init/while/step (M3) |
| P2-3 | break / continue | done | break emitted; continue lowers to shared tail after if (M3) |
| P2-4 | Switch: jump tables + cmp-cascade | done | Cmp-cascade (M3) + `jumptable.rs` byte-table/`br`; dispatch Raw stripped |
| P2-5 | else-if chains | done | Emit flattens nested `else { if }` → `else if` (M3) |
| P2-6 | Unreachable / goto cleanup at emit | done | Structured mode; join fix removes duplicate tails (M3) |

**Exit criteria:** Branchy leaf methods emit `if`/`while` without label soup in Restructure mode. **(Met; jump tables recovered for dense `-O2` switches.)**

### Phase 3 — ObjC / Apple IR (P1) — *our differentiator*

| ID | Item | Status | Notes |
|----|------|--------|-------|
| P3-1 | Recognize `objc_msgSend*` / stret / super | done | Tagged stubs `_objc_msgSend$sel:` + classic forms (M4) |
| P3-2 | Selector + receiver → `[recv sel:args]` | done | `__stubs` naming + `objc_storeStrong` → local/`self` |
| P3-3 | Block literals / invoke signatures (basic) | done | `blocks.rs`: `*(block+0x10)` / `*_block_invoke` → `block(args)` |
| P3-4 | Emit method as `- (ret)name:(t)arg…` using class-dump types | done | `objc_proto.rs`; IMP / `-[Cls sel:]` lookup |
| P3-5 | Class-dump + decompile combo CLI | done | `decompile --objc-methods --out` → `Classes.h` + `.m` |
| P3-6 | Swift track (mangling only at first) | done | `swift.rs` New Mangling (`$s`); `// Swift:` comment + JSON |

**Exit criteria:** `-[CDSmoke hello:]` shows `[self hello:…]` / `NSLog` style calls, not only `bl`. **(Met; also `- (int)hello:(int)…` prototypes.)**

### Phase 4 — Types, naming, markup (P2) — *Ghidra types + Clang tokens*

| ID | Item | Status | Notes |
|----|------|--------|-------|
| P4-1 | Type lattice: int/ptr/float/ObjC-id | done | Coarse `Ty` (+ float/double); CFG condition param typing |
| P4-2 | DWARF / compact unwind / debug names when present | done | `dwarf.rs` (gimli); param names; unwind section hints |
| P4-3 | Semantic renames (dex `rename.rs` style) | done | `rename.rs` + CLI `--rename old=new` |
| P4-4 | Token stream + address map (ClangToken analogue) | done | `tokens.rs`; JSON `tokens[]` with optional `vaddr` |
| P4-5 | JSON export of CFG/IR/source | done | `function_to_json` + CLI `--json` |

### Phase 5 — Platform scale (P2)

| ID | Item | Status | Notes |
|----|------|--------|-------|
| P5-1 | Whole-binary / IPA batch decompile to dir | done | CLI `--all --out` (+ `--json`) |
| P5-2 | arm64e PAC/strip hints (don’t crash) | done | `pac.rs`; elide PAC/AUT/XPAC; `retaa`/`blraa`/`braa` as ret/call/br |
| P5-3 | DSC-aware later (shared selectors) | done | Bind/OOB selrefs; `--sel-map` VA→name; SymbolTable fallback (no full DSC parse) |
| P5-4 | Value-flow + simple vuln rules | done | `value_flow.rs` + CLI `--findings`; iOS source/sink set |

**Exit criteria (P5-4):** API + CLI can report at least one class of source→sink flow on IR. **(Met: clipboard/getenv → NSLog/system.)**

### Phase 6 — Swift decompiler (was X-4)

| ID | Item | Status | Notes |
|----|------|--------|-------|
| S0 | Demangle → `SwiftSymbol` + `func` prototype | done | `swift.rs`; repeat types `S2i`; nominal `V`/`C` |
| S1 | Swift dialect emit (`var` / `func` / types) | done | `frame.swift_dialect` + `swift_proto` |
| S2 | Runtime retain/release / overflow-trap elision | done | `swift_runtime.rs` |
| S3 | `__swift5_*` string/type hints | done | `swift_meta.rs` best-effort |
| S4 | Methods + fixtures + `--swift-methods` | done | `swift_fixtures/`; scoreboard group `swift` |

### Phase 6.1 — Close Ghidra gaps (useful parity)

| ID | Item | Status | Notes |
|----|------|--------|-------|
| S5 | Native `swift demangle` fallback | done | `swift_native.rs` (`std` feature); Ghidra-style |
| S6 | Overflow-check elision (`cset` / empty if) | done | `strip_swift_overflow_noise` + emit unwrap |
| S7 | Method `self` via `x20` | done | `rewrite_swift_self` |
| G1–G6 | Ghidra alignment backlog | done | See [`SWIFT_GHIDRA_ALIGNMENT.md`](./SWIFT_GHIDRA_ALIGNMENT.md); `tests/swift_ghidra_align.rs` |

**Exit criteria:** mangled symbols emit `func … { … }`; scoreboard `swift` green; CLI batch `.swift` files.

**Ghidra alignment checklist:** [`SWIFT_GHIDRA_ALIGNMENT.md`](./SWIFT_GHIDRA_ALIGNMENT.md) (demangle / body / metadata / backlog G1–G6).

### Explicit non-goals (near term)

| ID | Item | Status |
|----|------|--------|
| X-1 | Reimplement Ghidra C++ decompiler / SLEIGH | wontfix |
| X-2 | Full Ghidra GUI DecompilePlugin | wontfix |
| X-3 | Bit-identical output vs Ghidra/Hex-Rays | wontfix |
| X-4 | SIL-level / full generics / async / actors | wontfix (beyond Phase 6 v1) |

---

## 5. Suggested module layout (evolution)

```
src/
  cfg.rs          # + dominators, frontiers
  ir.rs           # richer Expr (Cmp, Cast, Field, MsgSend)
  micro.rs        # optional normalized ops (Ghidra p-code lite) — Phase 1+
  lift.rs         # ARM64 → IR/μops
  ssa.rs          # Heritage analogue
  locals.rs       # stack / HighVariable analogue
  calling.rs      # AAPCS64
  pass/           # phased Action groups
  region.rs       # structure
  objc.rs         # msgSend / sel / class
  types.rs        # propagation
  emit.rs         # source
  tokens.rs       # optional markup
  value_flow.rs   # later
  decompile.rs    # API (DecompInterface analogue)
```

Keep **`Pass` / `PassRunner`** as the extension point (dex + Ghidra Action spirit).

---

## 6. Testing strategy (from dex-decompiler)

See **[`DECOMPILER_TEST_PLAN.md`](./DECOMPILER_TEST_PLAN.md)** for the live harness
(manifest + Smoke/Structural/SourceLike tiers + scoreboard), modeled on dex
`fixture_manifest` / `FIXTURE_SOURCE_FIDELITY.md`.

1. **Unit:** CFG leaders, SSA φ placement, frame recovery on hand-written ARM64 blobs.
2. **Fixture binaries:** C (later ObjC) under `testdata/decompiler_fixtures/` with
   per-symbol manifest needles (not full goldens yet).
3. **Parity samples:** compare *structure* (has if/while, call names) to Ghidra output on the
   same fixture — not string-identical.
4. **Regression CLI:** `apple-re decompile fixture -n sym` in CI.
5. **Catalog / plan:** `docs/DECOMPILER_FIXTURES.md` + `DECOMPILER_TEST_PLAN.md`.

---

## 7. Milestones (suggested order)

| Milestone | Delivers | Depends |
|-----------|----------|---------|
| **M1** | P0 function bounds + cmp/branch fold + fixtures | — **done 2026-08-31** |
| **M2** | P1 SSA + stack locals + AAPCS64 prototypes | M1 — **done** (SSA + locals + `_main`) |
| **M3** | P2 structured if/while + switch cascades | M2 — **done** (switch/for/else-if; jump tables deferred) |
| **M4** | P3 ObjC msgSend emission + class-dump types | M2 — **done** (`[self sel:]` + `- (ret)sel:` prototypes + `--objc-methods`) |
| **M5** | P4 types/naming/JSON; batch IPA | M3–M4 — **done** (JSON + `--all --out` + coarse `Ty`; DWARF/tokens deferred) |
| **M6** | P5 value-flow hooks | M2 — **done** (`value_flow` + `--findings`) |

---

## 8. References

- Current overview: [`docs/ARM_DECOMPILER.md`](./ARM_DECOMPILER.md)
- dex-decompiler pipeline: its README “How the decompiler works”
- dex gap process: `../dex-decompiler/docs/JADX_GAP_PLAN.md`
- Ghidra Java API (options, results, Clang tokens):  
  [`ghidra/app/decompiler` @ b070495](https://github.com/NationalSecurityAgency/ghidra/tree/b070495c0bdfe96b12469550a9bc76131f6c4dd7/Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler)
- Ghidra engine concepts: `Funcdata`, `Heritage`, `Merge`, structured `BlockGraph`
  (under `Ghidra/Features/Decompiler/src/decompile/cpp/`)

Update this file when milestones land or priorities change.
