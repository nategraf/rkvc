# rkvc-derive

This crate supplies the `Attributes` macro, which is used to improve the experience of defining credentials using `rkvc`.

## Example

```rust
use rkvc_derive::Attributes;

#[derive(Attributes)]
struct MyAttributes {
    value1: u64,
    value2: u32,
    value3: String,
}
```

More examples can be found, with realistic use cases, in the [`examples` directory of `rkvc`](../examples/).

You can also see what various test cases exapnd to by looking at the `macrotest` files in the [`tests/expand` directory](./tests/expand/).

## Test

Tests are defined using `macrotest` and `trybuild`, testing what the macro expands to and what the compilation output is respectively.

```sh
cargo test
```

Output is compared to `*.expanded.rs` and `.stderr` files stored alongside the tests in [`tests/expand`](./tests/expand).
When making an intentional change, the following command can be used to update the test files.

```sh
TRYBUILD=overwrite MACROTEST=overwrite cargo test
```

Examine the changes and commit them with `git` if they are as expected.
