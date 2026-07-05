# Security Model

## Threat model

### What we protect against

- **Network-level surveillance** — passive ISP / state-level packet inspection. Mitigated by end-to-end encryption.
- **Server compromise** — there are no servers; all data is on-device. Nothing to compromise.
- **Device seizure** — emergency wipe destroys all data. Identity at rest is encrypted with Argon2id + AES-256-GCM.
- **Man-in-the-middle** — Ed25519 signatures on every envelope. 60-digit safety-number verification detects MITM.
- **Forward secrecy** — per-session DH ratchet + KDF-chain. Compromise of current keys does not reveal past messages.
- **Censorship** — no central servers, no DNS, no IP addresses required. Operates over BLE / Wi-Fi Direct / LoRa without internet.

### What we do NOT protect against

- **Endpoint compromise** — if the device is rooted and an attacker has live access, they can read decrypted messages from memory.
- **Metadata leakage** — peers you have communicated with can be inferred from your peer registry.
- **Traffic analysis** — message timing and size patterns may be observable, especially over LoRa.
- **Physical device destruction** — no cloud backup. Losing the device loses the identity (mnemonic recovery is the only fallback).
- **Zero-day exploits in Android / Bluetooth stack** — we depend on the underlying OS.

## Cryptographic design

### Identity

Each node has an identity rooted in a 24-word BIP39 mnemonic (256 bits of entropy). The Ed25519 signing keypair is derived via SLIP-0010 (HMAC-SHA512 with key `"ed25519 seed"`), providing domain separation between the BIP39 seed and the Ed25519 key.

The stable Identity ID = `SHA-256(verifying_key).hex()` (64 hex characters). This ID is used as the node's address in the mesh and never changes for a given mnemonic.

The X25519 identity key is derived from the Ed25519 key via standard conversion (SHA-512 hash of the seed, clamped). This binds the signing identity to the DH identity — the same key material is used for both.

### Key agreement (X3DH)

When Alice wants to talk to Bob for the first time:
1. Alice fetches Bob's prekey bundle (propagated via the mesh)
2. Bundle contains: Ed25519 identity key, signed X25519 prekey, optional one-time prekey
3. Alice verifies: (a) `identity_id == SHA-256(identity_key)`, (b) signed prekey signature
4. Alice performs 3 DH operations and combines via HKDF:
   - DH1 = DH(Alice identity X25519, Bob signed prekey)
   - DH2 = DH(Alice ephemeral, Bob signed prekey)
   - DH3 = DH(Alice ephemeral', Bob one-time prekey) [if present]
5. Root key = `HKDF-SHA256(DH1 || DH2 || DH3, salt="aegis-x3dh-root", info="v2")`
6. Alice transmits her ephemeral public keys in the X3DH initial message

Bob derives the same root key from his secrets + Alice's ephemeral public keys.

### Double Ratchet

Each message advances a KDF chain:
```
new_chain_key = HKDF(current_chain_key, salt="aegis-ratchet-chain", info=N)
message_key   = HKDF(new_chain_key,    salt="aegis-ratchet-msg",   info=N+1)
```

On every sender switch, a DH ratchet generates a fresh ratchet keypair, performs DH with the peer's last ratchet public, and mixes into the root key via HKDF. This provides post-compromise healing — even if chain keys are compromised, the next DH ratchet restores secrecy.

### Envelope authentication

Every envelope is Ed25519-signed. The canonical serialization (excluding the signature field) is signed. Receivers verify the signature using the sender's verifying key, obtained from the peer registry or prekey bundle.

### AAD binding

Each ciphertext includes `(session_id, sequence_number)` as additional authenticated data (AAD), binding the ciphertext to its position in the session. This prevents cross-session ciphertext swapping and replay.

## Anti-forensics

- **Encrypted-at-rest identity** — passphrase + Argon2id + AES-256-GCM with AAD binding (`b"aegis-identity-blob-v1"`)
- **Emergency wipe** — triple-tap (UI) or `aegis wipe` (CLI); transactional SQLite wipe + VACUUM
- **No persistent message log** (paranoid mode) — messages live only in volatile memory
- **Screenshot blocking** — `FLAG_SECURE` on all activities
- **SQLite secure_delete** — `PRAGMA secure_delete = ON` overwrites deleted pages
- **Atomic keystore** — write-to-tmp + rename, with version byte + anti-rollback

## Transport security

| Transport | Confidentiality | Authentication |
|-----------|-----------------|----------------|
| BLE | Unencrypted at link layer | End-to-end via Signal Protocol |
| Wi-Fi Direct | WPA2-PSK (group key) | End-to-end via Signal Protocol |
| LoRa | None (radio is broadcast) | End-to-end via Signal Protocol |
| Loopback | None (local Unix socket) | None (testing only) |

**The application-layer encryption (Signal Protocol) is the only thing that matters.** Transport-layer encryption is considered irrelevant — assume the transport is hostile.
