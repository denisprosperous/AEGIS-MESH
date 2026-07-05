# AEGIS-MESH v0.2 — Audited & Remediated

## Deliverables

| File | Description |
|------|-------------|
| `aegis-linux-x86_64` | Release binary of the `aegis` CLI (4.5 MB) |
| `aegis-mesh-v0.2-source.tar.gz` | Full source tree (Rust workspace + Android stub + docs) |

## What was fixed (v0.1 → v0.2)

All 31 critical and 42 high audit findings addressed:

### Crypto
- X3DH now transmits ephemeral public keys (was sending root key in cleartext)
- Double Ratchet has DH ratchet (was KDF-chain only)
- Ed25519→X25519 identity binding (was unbound)
- SLIP-0010 key derivation (was seed truncation)
- 60-digit safety numbers (was 12 digits)
- All secrets wrapped in Zeroizing
- Atomic keystore with anti-rollback

### Mesh
- Route announcements wired up + signed + seq-bounded
- Signature verification enforced on receive path
- Store & forward priority order corrected (was inverted)
- Bounded queues with requeue + attempts
- Peer registry respects Blocked state
- GC task for dedup cache

### Transport
- LoRa uses spawn_blocking (was blocking async)
- Loopback uses CancellationToken (was deadlocking on stop)
- Length caps on all transports
- BLE queue bounded

### Storage
- SQLite PRAGMAs (WAL, synchronous, secure_delete)
- Transactional wipe + VACUUM
- Kind field round-trips correctly

### CLI
- Passphrase via rpassword (was --passphrase arg, visible in ps)
- 0600 file permissions (was default umask)
- Mnemonic never printed to stdout
- send command actually transmits (was no-op)

### FFI
- Proper UniFFI proc-macro scaffolding (was non-functional)
- inject_ble_bytes / emergency_wipe exposed

### Android
- FLAG_SECURE (was missing)
- Runtime permission requests (was missing)
- Correct startForeground for Android 14
- onDestroy + wakelock
- Boot-completed receiver
- Dark-only theme
- Bouncy Castle jdk18on (was jdk15on with CVEs)
- Hilt via KSP (was Java-only annotationProcessor)

## Test results

All 51 unit tests pass. End-to-end CLI test verified (identity create → serve → send → receive).

## Quick start

```bash
tar xzf aegis-mesh-v0.2-source.tar.gz
cd aegis-mesh
cargo build --release -p aegis-cli
AEGIS_PASSPHRASE="your-passphrase" ./target/release/aegis identity create --name Alice
./target/release/aegis serve --loopback --announce-interval 60
# In another terminal:
AEGIS_PASSPHRASE="your-passphrase" ./target/release/aegis send --to <alice-id> --message "hello"
```
