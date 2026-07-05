# AEGIS-MESH

<p align="center">
  <strong>Ultra-Censorship-Resistant Communication Platform</strong>
  <br>
  <em>Communication is a human right. AEGIS-MESH protects that right.</em>
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-1.75%2B-orange.svg">
  <img alt="Android" src="https://img.shields.io/badge/Android-8.0%2B-green.svg">
  <img alt="Tests" src="https://img.shields.io/badge/tests-51%20passing-brightgreen.svg">
  <img alt="Version" src="https://img.shields.io/badge/version-0.2.0-blue.svg">
</p>

---

## Overview

AEGIS-MESH is a communication platform engineered for the harshest censorship environments — where internet is completely shut down, cellular networks are disabled, and surveillance is pervasive. It operates across multiple peer-to-peer transports (Bluetooth LE, Wi-Fi Direct, LoRa radios) using only the hardware already present in modern smartphones, augmented by optional low-cost LoRa USB dongles for kilometer-range messaging.

**Key properties:**
- **No servers** — pure peer-to-peer mesh, no central authority
- **No accounts** — identity is a BIP39 mnemonic, nothing else
- **End-to-end encryption** — Signal Protocol (X3DH + Double Ratchet)
- **Forward secrecy** — DH ratchet on every sender switch
- **Multi-transport** — BLE, Wi-Fi Direct, LoRa, loopback (testing)
- **Store & forward** — messages queued for offline peers
- **Anti-forensics** — encrypted-at-rest identity, emergency wipe, screenshot blocking

## Repository structure

```
aegis-mesh/
├── crates/
│   ├── aegis-core/          # Pure Rust library (crypto, mesh, storage, transports)
│   ├── aegis-cli/           # Cross-platform CLI (Linux/macOS/Windows)
│   └── aegis-ffi/           # UniFFI bindings for Android/iOS/Python
├── android/                 # Complete Kotlin/Compose Android app
│   └── app/src/main/java/network/aegis/mesh/
│       ├── ui/              # 7 Compose screens (onboarding, peers, chat, channels, settings, scan)
│       ├── ble/             # BLE mesh manager
│       ├── ffi/             # UniFFI Kotlin bindings
│       └── di/              # Hilt DI module
├── docs/                    # Documentation
├── .github/workflows/       # CI config
├── Cargo.toml               # Rust workspace
├── build-apk.sh             # One-command APK build script
└── README.md                # This file
```

## Quick start

### Linux CLI (fastest way to test)

```bash
# Build
cargo build --release -p aegis-cli

# Create an identity (passphrase prompted, or set AEGIS_PASSPHRASE env)
./target/release/aegis identity create --name "Alice"

# Terminal 1: start the mesh node
./target/release/aegis serve --loopback --announce-interval 60

# Terminal 2: send a message
./target/release/aegis send --to <recipient-id> --message "hello"
```

### Android APK

The APK must be built on a machine with Android Studio installed. See [BUILD-APK.md](BUILD-APK.md) for complete instructions, or run the one-command build script:

```bash
# Prerequisites: Android Studio + Rust Android targets + uniffi-bindgen
./build-apk.sh           # debug APK
./build-apk.sh release   # release APK (needs signing keystore)
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Android UI (Kotlin/Compose)                    │
│  - Onboarding, peer list, chat, channels, etc.  │
│  - BLE / Wi-Fi Direct / USB-serial Android APIs │
└────────────────────┬────────────────────────────┘
                     │ JNI / UniFFI
┌────────────────────▼────────────────────────────┐
│  aegis-ffi  (Rust + UniFFI bindings)            │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│  aegis-core  (pure Rust)                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  crypto  │  │  mesh    │  │  transport   │  │
│  │  Ed25519 │  │  router  │  │  BLE (JNI)   │  │
│  │  X25519  │  │  store&fwd│ │  LoRa (USB)  │  │
│  │  AES-GCM │  │  peers   │  │  Loopback    │  │
│  │  Signal  │  └──────────┘  └──────────────┘  │
│  └──────────┘                                   │
│  ┌──────────────────────────────────────────┐   │
│  │  storage (SQLite via rusqlite)           │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

## Security

### Cryptographic primitives

| Operation | Algorithm | Rust Crate |
|-----------|-----------|------------|
| Identity keys | Ed25519 (SLIP-0010 derivation) | `ed25519-dalek` 2.1 |
| Key agreement | X25519 (with Ed25519→X25519 conversion) | `x25519-dalek` 2.0 |
| Symmetric encryption | AES-256-GCM (deterministic counter nonce) | `aes-gcm` 0.10 |
| Key derivation | HKDF-SHA256 | `hkdf` 0.12 |
| Passphrase KDF | Argon2id (64 MiB / 3 iter / 4 lanes) | `argon2` 0.5 |
| Mnemonic | BIP39 (24 words, 256 bits entropy) | `bip39` 2.0 |
| Hashing | SHA-256 / SHA-512 | `sha2` 0.10 |
| Memory wiping | Zeroizing<T> on drop | `zeroize` 1.7 |

### Protocol

- **Identity**: Ed25519 signing keypair derived from BIP39 seed via SLIP-0010 (HMAC-SHA512)
- **Key agreement**: X3DH — Alice's ephemeral public key transmitted in initial message; Bob derives same root key
- **Forward secrecy**: Double Ratchet with DH ratchet on every sender switch + KDF-chain between
- **Authentication**: Every envelope Ed25519-signed; receiver verifies against sender's registered verifying key
- **Identity binding**: `identity_id == SHA-256(verifying_key)` verified on every prekey bundle
- **Safety numbers**: 60-digit decimal (~2^199 entropy) for MITM detection

### Anti-forensics

- Encrypted-at-rest identity (Argon2id + AES-256-GCM with AAD binding)
- Emergency wipe (triple-tap UI or `aegis wipe` CLI)
- `FLAG_SECURE` on all activities (blocks screenshots)
- SQLite `PRAGMA secure_delete = ON`
- Transactional wipe + VACUUM
- Paranoid default: ephemeral messages, no persistence

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

## Development

### Build

```bash
# Build all crates
cargo build --workspace

# Run tests (51 tests)
cargo test --workspace

# Build release CLI
cargo build --release -p aegis-cli

# Lint
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Project structure (Rust)

| Module | Responsibility | Tests |
|--------|----------------|-------|
| `crypto/identity` | BIP39 mnemonic, Ed25519, SLIP-0010, X25519 conversion | 6 |
| `crypto/aead` | AES-256-GCM, Argon2id, HKDF | 4 |
| `crypto/x25519` | Ephemeral + static DH with low-order point validation | 3 |
| `crypto/signal` | X3DH + Double Ratchet (DH ratchet) | 3 |
| `crypto/fingerprint` | 60-digit safety numbers, constant-time compare | 4 |
| `crypto/keystore` | Atomic file keystore + in-memory (Zeroizing) | 3 |
| `mesh/peer` | Peer registry with rate limiting + Blocked protection | 2 |
| `mesh/router` | Distance-vector routing, signed announcements, dedup | 6 |
| `mesh/store_forward` | Priority queue (BTreeMap), bounded, requeue | 4 |
| `messaging/envelope` | Wire format, signatures, validation, freshness | 4 |
| `messaging/channel` | Group chat with admin/owner roles | 3 |
| `storage/sqlite` | SQLite with PRAGMAs, transactional wipe | 3 |
| `transport/loopback` | Unix socket for testing (CancellationToken) | 1 |
| `transport/lora` | Meshtastic serial (spawn_blocking) | 1 |
| `transport/ble` | BLE JNI bridge (bounded queue) | 2 |
| `config` | Node config with validation + 0600 perms | — |

### CLI commands

```bash
aegis identity create --name "Alice"     # Generate new identity
aegis identity show                       # Display public identity
aegis identity reveal                     # Show mnemonic (TTY only)
aegis identity import --name "Alice"      # Restore from mnemonic
aegis serve --loopback --announce-interval 60   # Start mesh node
aegis send --to <id> --message "hello"    # Send message
aegis peers list                          # List known peers
aegis wipe                                # Emergency wipe
```

## Testing

All 51 unit tests pass:

```bash
$ cargo test --workspace
test result: ok. 51 passed; 0 failed; 0 ignored; 0 measured out
```

Tests cover:
- X3DH full round-trip (Alice initiates, Bob derives same root key)
- Double Ratchet with DH ratchet (multi-message, AAD binding)
- Identity binding rejection (forged bundle detected)
- Mesh routing (deliver/relay/drop, dedup, max_hops before dedup)
- Store & forward (correct priority order, bounded queue, requeue)
- Transport (loopback round-trip, BLE size cap, LoRa packet encode)
- Storage (envelope round-trip with kind preservation, wipe)
- Crypto (AES-GCM, Argon2id, HKDF, X25519, Ed25519, fingerprints)

## Roadmap

- [ ] Full Double Ratchet with skipped-message-key cache
- [ ] Wi-Fi Direct transport (Kotlin-side)
- [ ] File sharing (chunked encrypted transfer)
- [ ] Reticulum network stack integration
- [ ] LXMF messages and LXST voice calls
- [ ] Offline maps (MBTiles, geohash channels)
- [ ] iOS port (UniFFI supports Swift)
- [ ] Tor/Arti integration
- [ ] Reproducible builds
- [ ] Formal security audit

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

## References

- [Signal Protocol](https://signal.org/docs/) — X3DH + Double Ratchet
- [Bitchat](https://github.com/lukebarrett/bitchat) — Bluetooth mesh chat
- [Briar](https://briarproject.org/) — Tor + Bluetooth messaging
- [Meshtastic](https://meshtastic.org/) — LoRa mesh
- [Reticulum](https://reticulum.network/) — network stack

## Contributing

Contributions welcome. Please read the audit report ([docs/AUDIT.md](docs/AUDIT.md)) for known issues and the security model before contributing crypto code.

---

<p align="center">
  <em>Build it. Deploy it. Protect it.</em>
  <br>
  <strong>AEGIS-MESH — The Last Communication Platform You'll Ever Need.</strong>
</p>
