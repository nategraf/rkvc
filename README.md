# rkvc

`rkvc` is a library for building anonymous credentials from algebraic MACs, based on the techniques described in [Revisiting Keyed-Verification Anonymous Credentials](https://eprint.iacr.org/2024/1552), and in prior works[^1].

## Project Structure

The project consists of several components:

- `src/`: Core library implementation
  - `attributes.rs`: Attributes system for credential data
  - `cmz.rs`: CMZ credential scheme implementation
  - `hash.rs`: Cryptographic hashing utilities
  - `pederson.rs`: Pedersen commitment scheme
  - `range.rs`: Range proofs with Bulletproofs
  - `zkp.rs`: Zero-knowledge proof primitives

- `derive/`: Procedural macros for attribute definitions
- `examples/`: Sample implementations demonstrating library usage

## Getting Started

### Prerequisites

- Rust 1.85 or later
- `cargo expand` is required for macro tests
  - `cargo install --locked cargo-expand`

### Building

```sh
cargo build
```

### Running Tests

```sh
cargo test --workspace
```

#### Updating macro tests

When developing the macro implementation, test vectors can be updated with the following command.

```
TRYBUILD=overwrite MACROTEST=overwrite cargo test -p rkvc-derive
```

Examine the changes and check commit them with `git` if they are as expected.

### Development Commands

```sh
# Code linting
cargo clippy

# Code formatting
cargo fmt
```

## Features

- `default`: Includes `derive` feature
- `derive`: Enables derive macros for attributes
- `std`: Standard library support (disabled by default for no_std compatibility)

## Examples

Several examples are provided to demonstrate library usage:

- [expiration.rs](./examples/src/bin/expiration.rs): A simple credential with an ID and expiration time.
- [lox.rs](./examples/src/bin/lox.rs): Example implementation of Lox.
- [ooni.rs](./examples/src/bin/ooni.rs): Example implementation targeting the use case of OONI.

Run examples with:

```sh
cargo run --manifest-path examples/Cargo.toml --bin ${EXAMPLE:?}
```

[^1]: **TODO: List prior works e.g. CMZ'14 and BBDT'16**
