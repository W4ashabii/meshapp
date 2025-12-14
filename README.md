# 🛰️ Offline-First Encrypted Mesh Messenger

A fully offline-capable, Bluetooth Low Energy based, store-and-forward mesh messenger with end-to-end encryption.

## Project Structure

```
meshapp/
├── rust/          # Rust core library (FFI)
├── flutter/       # Flutter UI application
└── README.md
```

## Development Status

**Phase 0: Skeleton** ✅
- Monorepo structure
- Rust ↔ Flutter FFI setup
- Test function

## Building

### Prerequisites
- Rust (latest stable)
- Flutter SDK (3.0.0+)
- Platform-specific build tools

### Step 1: Build Rust Library

```bash
cd rust
cargo build --release
```

Or use the build script:
```bash
cd rust
./build.sh
```

This will compile the Rust library and copy it to the Flutter directory.

### Step 2: Build Flutter App

```bash
cd flutter
flutter pub get
flutter run
```

## FFI Test

The Flutter app includes a test button that calls the `test_ffi()` function from Rust. This verifies that:
- Rust library compiles correctly
- FFI bindings work
- String passing between Rust and Dart functions properly

## Project Structure Details

- `rust/` - Core Rust library with FFI exports
- `rust/src/lib.rs` - Main library with `test_ffi()` function
- `flutter/lib/main.dart` - Flutter UI with FFI bindings
- `flutter/lib/main.dart` - Contains `RustCore` class for FFI calls

## Phase 0 Status

✅ Monorepo structure created
✅ Rust library with FFI exports
✅ Flutter app with FFI bindings
✅ Test function to verify connectivity
✅ Build scripts and documentation

## License

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
