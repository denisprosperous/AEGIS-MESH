# AEGIS-MESH v0.2 — Audited & Remediated

**Ultra-censorship-resistant communication platform.** Rust core + CLI + UniFFI + Android stub.

> Communication is a human right. AEGIS-MESH protects that right.

## What's new in v0.2

This version addresses all 31 critical and 42 high findings from the v0.1 audit:

- **X3DH fixed**: Alice's ephemeral public keys are now transmitted in the initial message; Bob derives the same root key from his own secrets (was broken — root key was sent in cleartext).
- **Double Ratchet**: DH ratchet on every sender switch (was KDF-chain only — no post-compromise healing).
- **Ed25519↔X25519 binding**: Identity keys are cryptographically bound; bundles verify `identity_id == SHA-256(identity_key)`.
- **SLIP-0010 derivation**: Ed25519 keys derived via HMAC-SHA512 (was seed truncation).
- **60-digit safety numbers**: ~2^199 entropy (was 12 digits, brute-forceable in hours).
- **Route announcements signed + seq-bounded**: `process_route_announce` wired up, authenticated, rejects absurd seq jumps.
- **Signature verification enforced**: on receive path (was never called).
- **Store & forward fixed**: correct priority ordering (was inverted), bounded queue, requeue with attempts.
- **Transport hardening**: `spawn_blocking` for LoRa serial, `CancellationToken` for loopback shutdown, length caps everywhere.
- **SQLite hardened**: WAL, synchronous, secure_delete PRAGMAs; transactional wipe + VACUUM.
- **CLI hardened**: passphrase via `rpassword` (not `--passphrase` arg), 0600 file perms, mnemonic never printed to stdout.
- **FFI functional**: proper UniFFI proc-macro scaffolding with `setup_scaffolding!()` + `#[uniffi::export]`.
- **Android hardened**: `FLAG_SECURE`, runtime permissions, correct `startForeground`, `onDestroy` + wakelock, boot receiver, dark-only theme, Bouncy Castle jdk18on, Hilt via KSP.

## Quick start

```bash
# Build
cargo build --release -p aegis-cli

# Create identity (passphrase prompted via rpassword, or AEGIS_PASSPHRASE env)
./target/release/aegis identity create --name "Alice"

# Terminal 1: start mesh
./target/release/aegis serve --loopback

# Terminal 2: send a message
./target/release/aegis send --to <recipient-id> --message "hello"
```

## Test results

All 51 unit tests pass, covering:
- X3DH full round-trip (Alice initiates, Bob derives same root key, message decrypts)
- Double Ratchet (multi-message, AAD binding)
- Identity binding rejection (forged bundle with mismatched identity_id)
- Mesh routing (deliver/relay/drop decisions, dedup, max_hops before dedup)
- Store & forward (correct priority order, bounded queue, requeue with attempts)
- Transport (loopback round-trip, BLE size cap, LoRa packet encode)
- Storage (envelope round-trip with kind preservation, wipe, KV store)
- Crypto (AES-GCM, Argon2id, HKDF, X25519, Ed25519, fingerprints, safety numbers)

## License

AGPL-3.0-or-later.
