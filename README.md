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

**Phase 1: Identity** ✅
- Identity key generation (Ed25519 + X25519)
- Secure storage of identity keys
- Public identity and fingerprint via FFI
- User ID computation (SHA256 of Ed25519 public key)

**Phase 2: Friends** ✅
- Friend management (add, remove, list)
- QR code export/import for friend public keys
- Local storage of friends
- Manual friend addition via public key

**Phase 3: DM Cryptography** ✅
- DM channel ID derivation (SHA256(min(pubA, pubB) || max(pubA, pubB)))
- Noise Protocol IK pattern implementation
- Encrypt/decrypt APIs for direct messages
- Session-based encryption (handshake simulation for testing)

**Phase 4: Storage** ✅
- SQLite offline-first message storage
- Tables: messages (id, channel_id, ciphertext, timestamp, ttl)
- Channels table scaffolded
- FFI for storing and fetching messages

**Phase 5: Transport** ✅
- Transport abstraction with router
- TTL + deduplication on incoming packets
- Store-and-forward: on-new packets persisted to SQLite
- Loopback transport for testing; BLE hooks to follow

**Phase 7: Geohash Channels** ✅
- Geohash-based channel IDs: `SHA256(geohash + topic)`
- Channel registry table (`channels`) with type = `geo`
- FFI for deriving, registering, and listing geohash channels

**Phase 8: Mentions** ✅
- `@nickname` parsing client-side only (no protocol changes)
- Rust mention extractor matched against local friends list
- FFI to return mentions as JSON for local notifications/UI

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
- `rust/src/lib.rs` - Main library with FFI functions
- `rust/src/identity.rs` - Identity management (key generation, storage)
- `rust/src/friends.rs` - Friend management and storage
- `rust/src/dm_crypto.rs` - DM cryptography with Noise Protocol
- `flutter/lib/main.dart` - Flutter UI with FFI bindings

## Identity System

Each device generates a permanent identity on first launch:
- **Ed25519 keypair** for identity signing
- **X25519 keypair** for key exchange
- **User ID** = SHA256(Ed25519 public key)
- **Fingerprint** = First 16 characters of User ID (for display)

Identity keys are stored securely in:
- Linux: `~/.local/share/meshapp/identity.json` (permissions: 600)
- macOS: `~/Library/Application Support/meshapp/identity.json`
- Windows: `%LOCALAPPDATA%\meshapp\identity.json`

## Phase 2 Status

✅ Friend data structure and storage
✅ Friend management (add, remove, list)
✅ QR code generation for identity export
✅ QR code scanning for friend import
✅ Manual friend addition via public key
✅ Flutter UI with tabbed interface (Identity & Friends)
✅ Secure friend storage (JSON with file permissions)

### Friend Management

Friends are stored locally with:
- **user_id**: SHA256 of Ed25519 public key
- **ed25519_public**: Public key for verification
- **nickname**: Local-only display name

Friends can be added via:
- **QR Code** (recommended): Scan friend's QR code
- **Manual import**: Enter Ed25519 public key directly

Storage location:
- Linux: `~/.local/share/meshapp/friends.json` (permissions: 600)
- macOS: `~/Library/Application Support/meshapp/friends.json`
- Windows: `%LOCALAPPDATA%\meshapp\friends.json`

## Phase 3 Status

✅ DM channel ID derivation (deterministic, private)
✅ Noise Protocol IK pattern (Noise_IK_25519_ChaChaPoly_SHA256)
✅ Session-based encryption/decryption APIs
✅ Test function for encrypt/decrypt roundtrip
✅ FFI functions for channel ID derivation

### phase 4 DM Cryptography

Direct messages use:
- **Channel ID**: `SHA256(min(pubA, pubB) || max(pubA, pubB))` - Same for both peers, cannot be reversed
- **Noise Pattern**: `Noise_IK_25519_ChaChaPoly_SHA256` - Authenticated, forward secrecy
- **Session Management**: Transport state maintained after handshake completion

**Note**: In Phase 3, handshake is simulated for testing. In Phase 5+, handshake will occur over the network transport layer.

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
