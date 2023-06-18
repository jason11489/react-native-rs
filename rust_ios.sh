set -e

# build Rust project for iOS
cargo build --target aarch64-apple-ios --release
cargo build --target x86_64-apple-ios --release


# create a universal static library
lipo -create -output lib_rust.a \
    target/aarch64-apple-ios/release/librust_module.a \
    target/x86_64-apple-ios/release/librust_module.a


# Generate header file
cbindgen --lang c --crate rust_module --output rust_module.h

