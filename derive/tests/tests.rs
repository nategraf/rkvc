#[test]
fn build() {
    let t = trybuild::TestCases::new();
    t.pass("tests/expand/basic.rs");
    t.compile_fail("tests/expand/empty.rs");
    t.pass("tests/expand/primitive_fields.rs");
    t.pass("tests/expand/complex_fields.rs");
    t.pass("tests/expand/crate_path.rs");
    t.compile_fail("tests/expand/parse_errors.rs");
}

#[test]
fn expansions() {
    macrotest::expand("tests/expand/*.rs");
}
