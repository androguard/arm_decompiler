# arm_decompiler

ARM64 → C-like decompiler (Mach-O / IPA today; ELF / Android planned), using the same
pipeline shape as [dex-decompiler](https://github.com/androguard/dex-decompiler).

See [docs/ARM_DECOMPILER.md](docs/ARM_DECOMPILER.md) for the pipeline overview,
[docs/ARM64_DECOMPILER_PLAN.md](docs/ARM64_DECOMPILER_PLAN.md) for the roadmap, and
[docs/SWIFT_GHIDRA_ALIGNMENT.md](docs/SWIFT_GHIDRA_ALIGNMENT.md) for Swift/Ghidra parity.

## Dependencies

This crate currently path-depends on sibling [apple-re](https://github.com/androguard/apple-re)
packages (`macho_core`, `apple_metadata`, `ipa_vfs` from apple-re; `arm_disassembler`
sibling). Clone as siblings:

```
androguard/
  apple-re/
  arm_disassembler/
  arm_decompiler/   ← this repo
```

## Build & test

```bash
cargo test
cargo test --test decompiler_tests scoreboard -- --nocapture
cargo test --test swift_ghidra_align
```

Rebuild fixtures (macOS + clang / swiftc):

```bash
cd testdata/decompiler_fixtures && ./build.sh
cd testdata/swift_fixtures && ./build.sh
```

## Library usage

```rust
use arm_decompiler::{decompile_macho_symbol, DecompilerOptions};

let opts = DecompilerOptions::default();
let out = decompile_macho_symbol(&macho_bytes, "_main", &opts)?;
println!("{}", out.source);
```

CLI decompile remains in apple-re:

```bash
cargo run -p apple_re_cli --manifest-path ../apple-re/Cargo.toml -- decompile ./MyBinary -n _main
```
