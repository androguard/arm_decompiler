# arm_decompiler test plan

Regression and progress tracking for ARM64 → C/ObjC decompilation, modeled on
[dex-decompiler](../../dex-decompiler)’s fixture harness
(`tests/decompiler/fixture_*`, `docs/FIXTURE_SOURCE_FIDELITY.md`).

**Goal:** every interesting control-flow / calling / ObjC shape has a checked-in
Mach-O + source, a manifest row, and a test that fails when quality regresses —
and that we can tighten as milestones land.

---

## Layout

| Path | Role |
|------|------|
| `testdata/decompiler_fixtures/` | C/ObjC sources + built Mach-O |
| `…/src/*.c` (and later `*.m`) | Human-readable fixture sources |
| `…/build.sh` | Rebuild `decompiler_fixtures` binary (`clang -O0 -arch arm64`) |
| `…/decompiler_fixtures` | Checked-in arm64 Mach-O under test |
| `tests/decompiler/fixture_harness.rs` | Load binary, decompile by symbol, extract bodies, run checks |
| `tests/decompiler/fixture_manifest.rs` | Per-symbol expectations (`CompareTier`, needles) |
| `tests/decompiler/source_fidelity.rs` | Manifest coverage + fidelity loop |
| `tests/decompiler/m1_fixtures.rs` | M1-specific bounds / fold locks |
| `tests/decompiler/scoreboard.rs` | Prints tier pass/fail summary (how we’re doing) |
| `docs/DECOMPILER_FIXTURES.md` | Short catalog pointer (this file is the plan) |

```bash
# rebuild fixtures after editing sources
cd testdata/decompiler_fixtures && ./build.sh

# run the suite
cargo test --test decompiler_tests -- --test-threads=1

# scoreboard only (see progress without reading panics)
cargo test --test decompiler_tests scoreboard -- --nocapture
```

---

## Compare tiers (same idea as dex)

Expectations match **current** decompiler behavior on real clang `-O0` ARM64 —
not ideal C. When a milestone improves output, **upgrade the tier** or add
`must_contain` / `source_ids`.

| Tier | Meaning | Typical checks |
|------|---------|----------------|
| **Smoke** | Symbol resolves, bounds sane, decompile returns text | Non-empty body; no panic; optional `ret` / `return` |
| **Structural** | Control-flow / call *shape* is visible | `if (`, `while (`, `else`, call name, folded cmp predicate |
| **SourceLike** | Readable C-ish: locals/params, little register soup | Source identifiers present; avoid raw `xN`/`wN`/`sp` soup |

**Anti-goals for v1 tests:** bit-identical to clang source, bit-identical to Ghidra.

---

## Fixture catalog (planned → status)

Statuses: `live` (in binary + manifest) · `stub` (source sketched, binary not required yet) · `planned`.

### A. Bounds & baseline (M1) — `live`

| Symbol | Source | Intent | Tier today |
|--------|--------|--------|------------|
| `_add1` | `arithmetic.c` | Tiny leaf; bounds must not spill | Structural |
| `_absdiff` | `arithmetic.c` | `subs`/`cmp` + `b.cond` fold; two returns | Structural |
| `_main` | `arithmetic.c` | Multi-call epilogue; full `__text` span | Smoke |

### B. Control flow (M3) — `live` (mostly Smoke until regions improve)

| Symbol | Source | Intent | Tier today |
|--------|--------|--------|------------|
| `_if_else` | `control_flow.c` | Diamond if/else | Structural |
| `_if_else_chain` | `control_flow.c` | else-if ladder | Smoke |
| `_nested_if` | `control_flow.c` | Nested predicates | Smoke |
| `_while_sum` | `control_flow.c` | while + accumulate | Smoke |
| `_do_while_count` | `control_flow.c` | do-while | Smoke |
| `_for_sum` | `control_flow.c` | classic for | Smoke |
| `_break_in_loop` | `control_flow.c` | break | Smoke |
| `_continue_in_loop` | `control_flow.c` | continue | Smoke |

### C. Calls & arithmetic — `live`

| Symbol | Source | Intent | Tier today |
|--------|--------|--------|------------|
| `_mul_add` | `arithmetic.c` | mul/add expression | Smoke |
| `_call_add1` | `calls.c` | `bl` to `_add1` appears | Structural |
| `_call_absdiff` | `calls.c` | nested call | Smoke |

### D. Switch (M3) — `live` Smoke

| Symbol | Source | Intent | Tier today |
|--------|--------|--------|------------|
| `_switch_small` | `switch.c` | dense cases → cmp cascade / table | Smoke |
| `_switch_sparse` | `switch.c` | sparse cases | Smoke |

### E. Frame / locals (M2) — `planned`

| Symbol | Intent | Target tier after M2 |
|--------|--------|----------------------|
| `_stack_locals` | `stp` frame → `local_N` not only `*(sp+…)` | SourceLike |
| `_params_three` | x0–x2 → named params in prototype | SourceLike |
| `_returns_int` | `int` prototype + `return` expr | Structural |

### F. ObjC (M4) — `planned`

| Symbol | Intent | Target tier after M4 |
|--------|--------|----------------------|
| `-[CFObjC hello:]` | `objc_msgSend` → `[recv sel:]` | Structural |
| `-[CFObjC sum:with:]` | typed method emit from class-dump | SourceLike |

---

## Work phases

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 1. Harness + manifest + scoreboard | Every exported fixture symbol covered | **done** |
| 2. Structural baseline | Control-flow / call needles match *today’s* output | **done** (honest Smoke/Structural) |
| 3. Promote with milestones | After M2/M3/M4, bump Smoke → Structural → SourceLike | backlog |
| 4. Optional goldens | Checked-in normalized snippets per symbol + update script | backlog |
| 5. ObjC + IPA fixtures | `.m` + thin IPA under `testdata/` | backlog |

---

## Adding a fixture

1. Add a function to the right `testdata/decompiler_fixtures/src/*.c` (or new file + `build.sh`).
2. Run `./build.sh` and commit the binary if it changed.
3. Add a `FixtureSpec` in `fixture_manifest.rs` (coverage test fails if missing).
4. Start at **Smoke**; promote when output earns it.
5. Run `cargo test --test decompiler_tests`.

---

## How to read progress

- **Scoreboard test** lists each symbol’s tier and whether checks passed.
- Manifest rows with `Smoke` + weak needles = “decompiles, quality TBD”.
- A sudden fail on a previously green **Structural** row = regression.
- Plan milestones in [`ARM64_DECOMPILER_PLAN.md`](./ARM64_DECOMPILER_PLAN.md) say when to promote tiers.

---

## Relation to M1 unit locks

`m1_fixtures` keeps hard asserts on bounds math and CFG predicate fold (not just
string needles). Manifest fidelity is the broad progress board; M1 tests are
the regression locks for P0-1 / P0-3.
