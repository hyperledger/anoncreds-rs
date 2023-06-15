# Anoncreds Uniffi

A `uniffi` wrapper built on top of [hyperledger/anoncreds-rs](https://github.com/hyperledger/anoncreds-rs).

## Prerequisites

Before you start, please ensure you have the following installed:

- Rust, you can install it via [rustup](https://rustup.rs/)
- Swift, you can install it via Xcode, you can download it from [Mac App Store](https://apps.apple.com/us/app/xcode/id497799835)
- [uniffi-rs](https://github.com/mozilla/uniffi-rs), you can add it as a dependency to your `Cargo.toml`

## Building the Project

After you have installed all the necessary prerequisites, follow these steps to build the project:

1. Clone the repository:

`git clone https://github.com/input-output-hk/anoncreds-rs.git`

2. Navigate into the project directory:

`cd uniffi`

3. Build the project:

`cargo build`

## Building release for a target

To build this uniffi to any target you can run the following commands:

1. Create the wrapper bindings from uniffi

`uniffi-bindgen generate src/anoncreds.udl --language <swift or kotlin> -o ./wrappers/<language>/anoncreds`

2. Create a release build for all the targets you required. A target is the arch and the OS (example: `x86_64-apple-darwin` is the target for intel macos).

`cargo build --release --target <target>`

⚠️ **WARNING:** If your not sure of the available targets you can run `rustup target list` and add a target by running `rustup target add <target>`.

## Building for macOS and iOS

For macOS, you can build a Swift Package project for all architectures using the provided `build-release-apple-universal.sh` script:

1. Ensure the script is executable:

`chmod +x ./build-release-apple-universal.sh`

2. Run the script:

`./build-release-apple-universal.sh`

This will create a Swift Package project inside the `output-frameworks` folder, containing everything needed to run `uniffi` for Swift on macOS and iOS for all architectures.

## Contributing

Contributions are always welcome! Please read our [contributing guide](CONTRIBUTING.md) to get started.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.