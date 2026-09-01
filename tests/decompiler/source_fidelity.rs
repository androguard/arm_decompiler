//! Source-fidelity loop: manifest coverage + per-symbol checks.

use super::fixture_harness::{assert_all_fixtures, assert_manifest_covers_catalog};
use super::fixture_manifest::fixture_manifest;

#[test]
fn fixture_manifest_covers_all_c_functions() {
    assert_manifest_covers_catalog(fixture_manifest());
}

#[test]
fn all_fixture_symbols_match_expectations() {
    assert_all_fixtures(fixture_manifest());
}
