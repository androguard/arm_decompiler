# Decompiler fixtures

Catalog of regression inputs for `arm_decompiler`. Full process, tiers, and
milestone promotion rules: **[`DECOMPILER_TEST_PLAN.md`](./DECOMPILER_TEST_PLAN.md)**.

## Suite binary (progress board)

| Path | Role |
|------|------|
| `testdata/decompiler_fixtures/src/*.c` | C sources by category |
| `…/decompiler_fixtures` | Checked-in arm64 Mach-O |
| `…/build.sh` | Rebuild after editing sources |
| `tests/decompiler/*` | Harness, manifest, fidelity, scoreboard |

```bash
cd testdata/decompiler_fixtures && ./build.sh
cargo test --test decompiler_tests -- --test-threads=1
cargo test --test decompiler_tests scoreboard -- --nocapture
```

Groups today: `arithmetic`, `control_flow`, `calls`, `switch`, `objc`, `swift`.

## Swift fixtures (Phase 6)

| Path | Role |
|------|------|
| `testdata/swift_fixtures/smoke.swift` | Free funcs + `Counter.bump` |
| `…/libsmoke.dylib` | Checked-in arm64 dylib (`-Onone`) |
| `…/build.sh` | Rebuild with `swiftc` |

```bash
cd testdata/swift_fixtures && ./build.sh
cargo run -p apple_re_cli -- decompile …/libsmoke.dylib -n '_$s5smoke5helloSiyF'
cargo run -p apple_re_cli -- decompile …/libsmoke.dylib --swift-methods --out /tmp/swift_out
```

Swift ↔ Ghidra feature matrix and backlog: **[`SWIFT_GHIDRA_ALIGNMENT.md`](./SWIFT_GHIDRA_ALIGNMENT.md)**.

## M1 lock binary

| Fixture | Path | Intent |
|---------|------|--------|
| `m1_bounds` | `testdata/m1_bounds` | Multi-function Mach-O (`_add1`, `_absdiff`, `_main`). Bounds + `subs`/`b.cond` fold. |
| `m1_bounds.c` | same dir | Source to rebuild. |

```bash
clang -O0 -arch arm64 -o testdata/m1_bounds \
  testdata/m1_bounds.c
```

Unit tests for hex-level `cmp`/`b.eq` fold live in `cfg::tests`.
