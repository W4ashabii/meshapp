# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-12-14

### Added
- **Phase 0: Skeleton** - Monorepo structure with Rust ↔ Flutter FFI
- **Phase 1: Identity** - Ed25519/X25519 key generation and secure storage
- **Phase 2: Friends** - Friend management with QR code import/export
- **Phase 3: DM Cryptography** - Noise Protocol IK encryption for direct messages
- **Phase 4: Storage** - SQLite offline-first message storage
- **Phase 5: Transport** - Transport abstraction with TTL + deduplication
- **Phase 6: Mesh Relay** - Store-and-forward routing with packet persistence
- **Phase 7: Geohash Channels** - Anonymous local group messaging via geohash
- **Phase 8: Mentions** - @nickname parsing for local notifications
- **Phase 9: Optimization** - Packet batching and battery optimization modes
- **Phase 10: Release** - Build scripts and packaging configuration

### Security
- End-to-end encryption using Noise Protocol Framework
- Deterministic anonymous channel IDs
- No usernames or global identifiers
- Metadata-minimizing design
- Secure key storage with file permissions

### Technical
- Rust core library with FFI bindings
- Flutter UI for Android, iOS, Linux, macOS, Windows
- Offline-first architecture
- Store-and-forward mesh networking
- SQLite for local persistence

## [Unreleased]

### Planned
- Bluetooth Low Energy transport implementation
- Mobile app packaging (Android APK, iOS IPA)
- Desktop app packaging (AppImage, DMG, MSI)
- Performance optimizations
- UI/UX improvements

