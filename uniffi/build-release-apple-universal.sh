#!/bin/bash -e

echo "Verify and install required targets"
targets=(
  "x86_64-apple-ios"
  "aarch64-apple-ios"
  "aarch64-apple-ios-sim"
  "aarch64-apple-darwin"
  "x86_64-apple-darwin"
)

for target in "${targets[@]}"; do
  if ! rustup target list | grep -q "$target (installed)"; then
    echo "Target $target is not installed. Installing..."
    rustup target add "$target"
    echo "Target $target installed."
  else
    echo "Target $target is already installed."
  fi
done

# Create output directories
mkdir -p ./target/universal-ios-sim/release || true
mkdir -p ./target/universal-darwin/release || true

# Generate Uniffi bindings
echo "Creating uniffi bindings"
cargo run --bin uniffi-bindgen generate src/anoncreds.udl --language swift -o ./wrappers/swift/anoncreds

# Build targets
echo "Build all targets"
for target in "${targets[@]}"; do
  echo "Starting $target build"
  cargo build --release --target "$target"
  echo "Finished $target build"
done

# Remove existing files in the destination directories
rm -f ./target/universal-ios-sim/release/libanoncreds_uniffi.a || true
rm -f ./target/universal-darwin/release/libanoncreds_uniffi.a || true
rm -dr ./target/universal/libanoncreds.xcframework || true

# Create universal libraries
echo "Creating lipo universal libraries"
lipo -create ./target/aarch64-apple-ios-sim/release/libanoncreds_uniffi.a ./target/x86_64-apple-ios/release/libanoncreds_uniffi.a -output ./target/universal-ios-sim/release/libanoncreds_uniffi.a

lipo -create ./target/aarch64-apple-darwin/release/libanoncreds_uniffi.a ./target/x86_64-apple-darwin/release/libanoncreds_uniffi.a -output ./target/universal-darwin/release/libanoncreds_uniffi.a

# Create XCFramework
echo "Creating xcframework"
xcodebuild -create-xcframework \
  -library ./target/aarch64-apple-ios/release/libanoncreds_uniffi.a \
  -headers ./wrappers/swift/anoncreds/ \
  -library ./target/universal-ios-sim/release/libanoncreds_uniffi.a \
  -headers ./wrappers/swift/anoncreds/ \
  -library ./target/universal-darwin/release/libanoncreds_uniffi.a \
  -headers ./wrappers/swift/anoncreds/ \
  -output ./target/universal/libanoncreds.xcframework

echo "Removing .swift files from headers"
dir="./target/universal/libanoncreds.xcframework"

# Compress and copy XCFramework
target_dir_name="libanoncreds.xcframework"
source_dir="./target/universal/"
dest_dir="./output-frameworks/anoncreds-swift"
zip_name="libanoncreds.xcframework.zip"

echo "Zip xcframework"
rm -f "$dest_dir/$zip_name" || true
zip -r "$dest_dir/$zip_name" "$source_dir/$target_dir_name"

echo "Copy .swift binders"
rm -f "./output-frameworks/anoncreds-swift/AnoncredsSwift/Sources/Swift/anoncreds.swift" || true
mkdir -p ./output-frameworks/anoncreds-swift/AnoncredsSwift/Sources/Swift || true
mv "./wrappers/swift/anoncreds/anoncreds.swift" "./output-frameworks/anoncreds-swift/AnoncredsSwift/Sources/Swift/anoncreds.swift"

rm -f "/wrappers/swift/anoncreds/anoncreds.swift" || true

