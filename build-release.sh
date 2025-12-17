#!/bin/bash
# Release build script for meshapp
# Builds Rust library and Flutter app for all platforms

set -e

echo "🚀 Building meshapp for release..."

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build Rust library
echo -e "${BLUE}📦 Building Rust core library...${NC}"
cd rust
cargo build --release
cd ..

# Copy library to Flutter directory
PLATFORM=$(uname -s)
if [ "$PLATFORM" = "Linux" ]; then
    echo -e "${GREEN}✓${NC} Copying libmeshapp_core.so to Flutter directory..."
    cp rust/target/release/libmeshapp_core.so flutter/
elif [ "$PLATFORM" = "Darwin" ]; then
    echo -e "${GREEN}✓${NC} Copying libmeshapp_core.dylib to Flutter directory..."
    cp rust/target/release/libmeshapp_core.dylib flutter/
elif [[ "$PLATFORM" == MINGW* ]] || [[ "$PLATFORM" == MSYS* ]]; then
    echo -e "${GREEN}✓${NC} Copying meshapp_core.dll to Flutter directory..."
    cp rust/target/release/meshapp_core.dll flutter/
fi

# Build Flutter app
echo -e "${BLUE}📱 Building Flutter app...${NC}"
cd flutter

# Get dependencies
flutter pub get

# Build for current platform
if [ "$PLATFORM" = "Linux" ]; then
    echo -e "${BLUE}🐧 Building for Linux...${NC}"
    flutter build linux --release
    echo -e "${GREEN}✓${NC} Linux build complete: flutter/build/linux/x64/release/bundle/"
elif [ "$PLATFORM" = "Darwin" ]; then
    echo -e "${BLUE}🍎 Building for macOS...${NC}"
    flutter build macos --release
    echo -e "${GREEN}✓${NC} macOS build complete: flutter/build/macos/Build/Products/Release/"
elif [[ "$PLATFORM" == MINGW* ]] || [[ "$PLATFORM" == MSYS* ]]; then
    echo -e "${BLUE}🪟 Building for Windows...${NC}"
    flutter build windows --release
    echo -e "${GREEN}✓${NC} Windows build complete: flutter/build/windows/x64/runner/Release/"
fi

cd ..

echo -e "${GREEN}✅ Release build complete!${NC}"

