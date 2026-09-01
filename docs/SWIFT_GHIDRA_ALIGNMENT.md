# Swift decompiler ↔ Ghidra alignment

Living checklist for aligning apple-re’s Swift track (`arm_decompiler` Phase 6 / 6.1)
with what **Ghidra** actually does for Swift today — demangle, apply types, decompile
bodies — without reimplementing the Ghidra C++ engine or aiming for SIL-level fidelity.

**Related:** [`ARM64_DECOMPILER_PLAN.md`](./ARM64_DECOMPILER_PLAN.md) (S0–S7),
[`DECOMPILER_FIXTURES.md`](./DECOMPILER_FIXTURES.md) (Swift fixtures),
[`ARM_DECOMPILER.md`](./ARM_DECOMPILER.md) (pipeline overview).

**Ghidra references (current product shape):**

- Feature: `Ghidra/Features/SwiftDemangler` — analyzer demangles `$s` / `$S` / `_T…`
  by calling the native **`swift demangle`** tool and applying names / datatypes /
  calling conventions where the demangle tree allows.
- Decompiler window: still **C-like** p-code output with demangled *labels*, not
  Swift `func` syntax.
- Metadata: partial `__swift5_*` markup; fuller field/type recovery tracked upstream
  (e.g. [ghidra#8607](https://github.com/NationalSecurityAgency/ghidra/issues/8607)).

**Last updated:** 2026-09-01 (G1–G6 backlog implemented)

## Status legend

- `[ ]` not started
- `[~]` partial / best-effort
- `[x]` done (aligned enough for product use)
- `[—]` wontfix / out of scope (documented)

## 1. Positioning

| | Ghidra | apple-re (`arm_decompiler`) |
|--|--------|------------------------------|
| Goal for Swift | Demangle + enrich **C decompiler** | Emit **Swift-shaped** `func` / `var` bodies |
| Demangler | Native `swift demangle` (toolchain required) | In-process New Mangling **+** optional `swift demangle` (`std` feature) |
| Body engine | Full p-code / Heritage / Merge | Shared ARM64 CFG → IR → SSA → regions |
| UI | DecompilePlugin + Clang tokens | CLI / library (`--swift-methods`) |
| Dependency | Swift on `PATH` for demangler | Swift optional (fallback only) |

**Align on:** demangle fidelity, calling-convention / `self`, ARC noise, metadata names,
readable control flow.

**Do not chase:** bit-identical vs Ghidra, Swing UI, SLEIGH, full generics / async /
actors / protocol witnesses (plan X-4).

## 2. Feature matrix

### 2.1 Demangling (Ghidra `SwiftDemanglerAnalyzer`)

| Status | Capability | Ghidra | apple-re | Module / notes |
|--------|------------|--------|----------|----------------|
| [x] | Detect `$s` / `$S` / `_$s` symbols | yes | yes | `is_swift_mangled` |
| [x] | Free-function demangle | `swift demangle` | in-process + native fallback | `swift.rs`, `swift_native.rs` |
| [x] | Method / nominal `V`/`C` path | demangle tree | in-process + native | e.g. `Counter.bump` |
| [x] | Repeat stdlib types (`S2i`) | demangle tree | in-process | `parse_type_atoms` |
| [~] | Full ABI (generics, extensions, thunks) | strong via toolchain | native fallback when parse fails | Prefer improving in-process over always shelling out |
| [x] | Apply demangled **display name** | symbol rename | `demangled_name` + JSON | `FunctionDecompile` |
| [x] | Prototype from demangle | datatype apply (C) | `func … -> Int` | `format_swift_prototype` / `prototype_from_native_demangle` |
| [—] | Persist custom Swift dir in project | removed (PATH-only) | N/A | Follow Ghidra: PATH only, no project path RCE surface |

### 2.2 Decompiler body (Ghidra `DecompInterface` vs our pipeline)

| Status | Capability | Ghidra | apple-re | Notes |
|--------|------------|--------|----------|-------|
| [x] | Structured if / while / return | strong | shared regions | Same CF engine as C/ObjC |
| [x] | Stack locals / params | Merge / HighVariable | `locals.rs` | |
| [x] | Emit Swift dialect (`func` / `var`) | no (C-like) | yes | Product differentiator |
| [~] | Spill → param fold (`x0` after `param_1` store) | usually good | yes (G2) | `swift_fold.rs` |
| [x] | Overflow check elision (`cset` / `b.vs` / empty if) | often cleaned | yes | S6: `strip_swift_overflow_noise` + emit unwrap |
| [x] | Method `self` (`x20`) | via CC apply | `rewrite_swift_self` | S7 |
| [~] | Indirect / field access as named props | struct markup | `self.value` from reflstr | G3: `rewrite_swift_fields` |
| [—] | SIL / async state machines | no | no | X-4 |

### 2.3 Runtime / ARC

| Status | Capability | Ghidra | apple-re | Notes |
|--------|------------|--------|----------|-------|
| [x] | Elide `swift_retain` / `swift_release` (+ bridge) | generic DCE | dedicated strip | `swift_runtime.rs` |
| [~] | `swift_allocObject` → typed `Type()` | weak | comment placeholder | Improve with type metadata |
| [x] | Strip `-Onone` `brk` overflow traps | often | yes | |

### 2.4 Metadata (`__swift5_*`)

| Status | Capability | Ghidra | apple-re | Notes |
|--------|------------|--------|----------|-------|
| [~] | Type / field descriptors | partial; [#8607](https://github.com/NationalSecurityAgency/ghidra/issues/8607) open | best-effort scrape | `swift_meta.rs` |
| [~] | Reflection strings | partial | cstring / reflstr scrape | |
| [x] | Field offset → named struct members in IR | desired upstream | reflstr primary field → `self.field` | G3 (offset tables still later) |
| [ ] | Protocol conformances / witnesses | limited | todo (later) | |

### 2.5 Product / CLI

| Status | Capability | Ghidra | apple-re | Notes |
|--------|------------|--------|----------|-------|
| [x] | Batch decompile Swift symbols | scripts | `--swift-methods --out` | Writes `.swift` |
| [x] | Fixture / regression scoreboard | unit tests | `swift` group | `DECOMPILER_FIXTURES.md` |
| [x] | JSON export (demangled + source) | — | `--json` | |
| [—] | GUI token markup editor | ClangToken* | wontfix | X-2 |

## 3. Conceptual mapping

```text
Ghidra                              apple-re
─────────────────────────────       ─────────────────────────────
SwiftDemanglerAnalyzer          →   swift.rs + swift_native.rs
  (swift demangle + apply)            (in-process, then PATH fallback)
Decompiler p-code / Heritage    →   lift → ssa → locals → region
Merge / datatype apply          →   Ty lattice + Swift prototype
(no Swift syntax emit)          →   emit.swift_dialect (func/var)
(generic DCE)                   →   swift_runtime strip + overflow unwrap
__swift5_* analyzers            →   swift_meta.rs (best-effort)
DecompInterface / results       →   decompile_macho_symbol / FunctionDecompile
```

## 4. Alignment backlog (priority)

Work that moves us **toward Ghidra’s useful bar** (body quality + demangle), while
keeping Swift syntax emit as our edge.

| ID | Item | Status | Aligns with |
|----|------|--------|-------------|
| G1 | Prefer native demangle when in-process signature disagrees | [x] | SwiftDemangler fidelity |
| G2 | Spill folding: after `local = param`, use `param` not `x0` in arithmetic | [x] | Merge / CC apply |
| G3 | Named fields from `__swift5_reflstr` (primary prop) | [x] | Metadata program (ghidra#8607) |
| G4 | Soften remaining register soup in Swift SourceLike fixtures | [x] | `add1` / `bump` promoted SourceLike |
| G5 | Cache native demangle results per process | [x] | Analyzer performance |
| G6 | Document / test “Swift missing from PATH” behavior | [x] | PATH-only demangler; `tests/swift_ghidra_align.rs` |

Tests: `cargo test --test swift_ghidra_align`.

## 5. Acceptance checks (parity smoke)

Run against `testdata/swift_fixtures/libsmoke.dylib` (rebuild: `./build.sh`).

```bash
# Demangle + Swift emit (no Ghidra UI equivalent)
apple-re decompile …/libsmoke.dylib -n '_$s5smoke5helloSiyF'
# expect: func smoke.hello() -> Int { return 1; }

apple-re decompile …/libsmoke.dylib -n '_$s5smoke4add1yS2iF'
# expect: func … -> Int; no cset / empty overflow if; return present

apple-re decompile …/libsmoke.dylib -n '_$s5smoke7CounterV4bumpSiyF'
# expect: func bump(); uses self (not only x20)

apple-re decompile …/libsmoke.dylib --swift-methods --out /tmp/swift_out

cargo test --test decompiler_tests scoreboard -- --nocapture
# expect: swift.* rows PASS
```

**Vs Ghidra (manual):** same symbol should show a demangled name in the listing;
decompiler pane will still be C-like. apple-re wins on syntax; Ghidra usually wins
on local/param cleanliness until G2–G4 land.

## 6. Explicit non-goals

| ID | Item |
|----|------|
| X-G1 | Reimplement Ghidra SLEIGH / p-code VM for Swift |
| X-G2 | Match Ghidra DecompilePlugin / Clang token UI |
| X-G3 | Bit-identical output vs Ghidra or Hex-Rays |
| X-G4 | Full SIL, async/await recovery, actor isolation |

## 7. Module cheat sheet

| File | Role |
|------|------|
| `src/swift.rs` | In-process demangle, `SwiftSymbol`, prototypes |
| `src/swift_native.rs` | `swift demangle` fallback + cache (G1/G5) |
| `src/swift_fold.rs` | Param spill fold (G2) |
| `src/swift_runtime.rs` | ARC / overflow / `self` |
| `src/swift_meta.rs` | `__swift5_*` / `self.field` (G3) |
| `src/emit.rs` | Swift dialect + overflow-if unwrap |
| `src/decompile.rs` | Pipeline hooks |
| `tests/swift_ghidra_align.rs` | G1–G6 integration tests |
| apple-re `apple_re_cli` | `decompile --swift-methods` |
