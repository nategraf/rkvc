#[test]
fn build() {
    let t = trybuild::TestCases::new();
    t.pass("tests/samples/basic.rs");
    t.compile_fail("tests/samples/empty.rs");
    t.pass("tests/samples/primitive_fields.rs");
    t.pass("tests/samples/complex_fields.rs");
    t.pass("tests/samples/crate_path.rs");
    t.compile_fail("tests/samples/parse_errors.rs");
    t.pass("tests/samples/visibilities.rs");
    t.pass("tests/samples/labeled.rs");
}

#[test]
fn expansions() {
    macrotest::expand("tests/samples/*.rs");
}
