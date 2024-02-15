_Generating the C header:_


1. use `nightly` instead of `stable`

```sh
rustup default nightly
```
> **Note**: If you run into _'unknown feature'_ issues by using latest nightly, force it to 1.72.0 by executing: `rustup default nightly-2023-06-15`

2. Install [cbindgen](https://github.com/eqrion/cbindgen/)

```sh
cargo install cbindgen
```

3. Install [cargo expand](https://github.com/dtolnay/cargo-expand)

```sh
cargo install cargo-expand
```

4. Generate the header file:

```sh
cbindgen --config include/cbindgen.toml --crate anoncreds --output include/libanoncreds.h
```

5. Copy to React Native:

```sh
cp include/libanoncreds.h wrappers/javascript/packages/anoncreds-react-native/cpp/include/
```
