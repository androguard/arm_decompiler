//! Integration test entry for arm_decompiler fixtures / fidelity / M1 locks.
//!
//! ```bash
//! cargo test -p arm_decompiler --test decompiler_tests -- --test-threads=1
//! cargo test -p arm_decompiler --test decompiler_tests scoreboard -- --nocapture
//! ```

mod decompiler;
