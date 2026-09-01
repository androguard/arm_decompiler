//! Decompiler integration tests (dex-decompiler-style suite).
//!
//! - `fixture_harness` / `fixture_manifest`: shared decompile + per-symbol expectations
//! - `source_fidelity`: manifest coverage + fidelity loop
//! - `scoreboard`: print tier progress (`--nocapture`)
//! - `m1_fixtures`: hard locks for bounds + cmp→branch fold
//!
//! See `docs/DECOMPILER_TEST_PLAN.md`.

mod fixture_harness;
mod fixture_manifest;
mod m1_fixtures;
mod scoreboard;
mod source_fidelity;
