# INSTALL IOS TARGETS
rustup target add aarch64-apple-ios &
rustup toolchain install stable --target aarch64-apple-ios  --profile minimal --no-self-update &
rustup target add aarch64-apple-ios-sim &
rustup toolchain install stable --target aarch64-apple-ios-sim  --profile minimal --no-self-update &
rustup target add x86_64-apple-ios &
rustup toolchain install stable --target x86_64-apple-ios  --profile minimal --no-self-update &

# INSTALL ANDROID TARGETS
rustup target add aarch64-linux-android &
rustup toolchain install 1.64.0 --target aarch64-linux-android --profile minimal --no-self-update &
rustup target add armv7-linux-androideabi &
rustup toolchain install 1.64.0 --target armv7-linux-androideabi --profile minimal --no-self-update &
rustup target add i686-linux-android &
rustup toolchain install 1.64.0 --target i686-linux-android --profile minimal --no-self-update &
rustup target add x86_64-linux-android &
rustup toolchain install 1.64.0 --target x86_64-linux-android --profile minimal --no-self-update &

# INSTALL CROSS
cargo install --git https://github.com/cross-rs/cross --tag v0.2.4 cross &

# WAIT FOR BACKGROUND TASKS
wait

# BUILD IOS TARGETS
cargo  build --release --target aarch64-apple-ios --features=vendored
cargo  build --release --target aarch64-apple-ios-sim --features=vendored
cargo  build --release --target x86_64-apple-ios --features=vendored

# BUILD ANDROID TARGETS
cross build --release --target aarch64-linux-android --features=vendored
cross build --release --target armv7-linux-androideabi --features=vendored
cross build --release --target i686-linux-android --features=vendored
cross build --release --target x86_64-linux-android --features=vendored

# BUILD MAC OS TARGETS
../../build-universal.sh