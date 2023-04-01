_Generating the C header:_

1. Install [cbindgen](https://github.com/eqrion/cbindgen/)
1. Install [cargo expand](https://github.com/dtolnay/cargo-expand)
1. use `nightly` and not `stable
  - `rustup default nightly`


```sh
cargo install cbindgen
```

Generate the header file:

```sh
cbindgen --config include/cbindgen.toml --crate anoncreds --output include/libanoncreds.h
```

Copy to React Native:

```sh
cp include/libanoncreds.h wrappers/javascript/anoncreds-react-native/cpp/include/
```
