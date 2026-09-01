//! Print how the decompiler is doing across the fixture catalog.
//!
//! ```bash
//! cargo test -p arm_decompiler --test decompiler_tests scoreboard -- --nocapture
//! ```

use super::fixture_harness::scoreboard_lines;
use super::fixture_manifest::fixture_manifest;

#[test]
fn scoreboard() {
    let lines = scoreboard_lines(fixture_manifest());
    for line in &lines {
        eprintln!("{line}");
    }
    assert!(
        lines.len() > 1,
        "scoreboard produced no fixture rows"
    );
    // Soft board: always passes if the catalog runs. Hard locks live in
    // `source_fidelity` / `m1_fixtures` (those fail the build on regressions).
}
