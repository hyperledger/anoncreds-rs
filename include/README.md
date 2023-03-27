_Generating the C header:_

Install [cbindgen](https://github.com/eqrion/cbindgen/):

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
