#!/bin/sh

# NOTE:
# MacOS universal build currently requires MacOS 11 (Big Sur) for the appropriate SDK,
# and `sudo xcode-select --install` must be run to install the command line utilities.
# Rust's `beta` channel must be installed because aarch64 is still a tier-2 target:
# `rustup toolchain install beta`.

RUSTUP=${RUSTUP:-`command -v rustup`}
PROJECT=aries-askar

if [ ! -x "$RUSTUP" ]; then
	echo "rustup command not found: it can be obtained from https://rustup.rs/"
	exit 1
fi

TOOLCHAIN=`$RUSTUP default`
TARGET_DIR="${TARGET_DIR-./target/darwin-universal}"

if [ -z "$BUILD_TOOLCHAIN" ]; then
	BUILD_TOOLCHAIN=${TOOLCHAIN%%-*}
	if [ -z "$BUILD_TOOLCHAIN" ]; then
		echo "Error: Could not determine default Rust toolchain"
		exit 1
	fi
fi

MACOS_UNIVERSAL_TARGETS="aarch64-apple-darwin x86_64-apple-darwin"

# Fail on any execution errors
set -e

INSTALLED_TARGETS=`$RUSTUP +$BUILD_TOOLCHAIN target list --installed`
# Install target(s) as needed
echo "Checking install targets for MacOS universal build .."
for target in $MACOS_UNIVERSAL_TARGETS; do
	if ! `echo "$INSTALLED_TARGETS" | grep -q $target`; then
		$RUSTUP +$BUILD_TOOLCHAIN target add $target
	fi
done

MAJOR_VER=`sw_vers | grep ProductVersion | cut -f 2 | cut -f 1 -d .`
if [ "$MAJOR_VER" -lt 11 ]; then
	echo "MacOS universal build requires OS 11 (Big Sur) or newer"
	TARGET=
fi

# Build both targets and combine them into a universal library with `lipo`
TARGET_LIBS=
for target in $MACOS_UNIVERSAL_TARGETS; do
	echo "Building $PROJECT for toolchain '$BUILD_TOOLCHAIN', target '$target'.."
	$RUSTUP run $BUILD_TOOLCHAIN cargo build --lib --features=vendored --release --target $target
	TARGET_LIBS="./target/$target/release/libanoncreds.dylib $TARGET_LIBS"
done

mkdir -p "${TARGET_DIR}/release" ./target/release
OUTPUT="${TARGET_DIR}/release/libanoncreds.dylib"
echo "Combining targets into universal library"
lipo -create -output $OUTPUT $TARGET_LIBS
