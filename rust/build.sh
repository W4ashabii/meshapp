#!/bin/bash
# Build script for Rust core library
# This builds the library for use with Flutter FFI

set -e

echo "Building meshapp-core..."

# Build release version for production
cargo build --release

# Copy the library to the Flutter directory based on platform
PLATFORM=$(uname -s)

if [ "$PLATFORM" = "Linux" ]; then
    echo "Copying libmeshapp_core.so to flutter directory..."
    cp target/release/libmeshapp_core.so ../flutter/
elif [ "$PLATFORM" = "Darwin" ]; then
    echo "Copying libmeshapp_core.dylib to flutter directory..."
    cp target/release/libmeshapp_core.dylib ../flutter/
elif [[ "$PLATFORM" == MINGW* ]] || [[ "$PLATFORM" == MSYS* ]]; then
    echo "Copying meshapp_core.dll to flutter directory..."
    cp target/release/meshapp_core.dll ../flutter/
fi

echo "Build complete!"




