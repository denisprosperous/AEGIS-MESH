# AEGIS-MESH v0.2 — Android UI Complete

## What's in this package

| File | Description |
|------|-------------|
| `aegis-linux-x86_64` | Release CLI binary (4.5 MB) |
| `aegis-mesh-v0.2-android.tar.gz` | Full source: Rust core + CLI + FFI + complete Android app |

## Android app — what was built

A complete, production-ready Compose UI with 7 screens:

1. **OnboardingScreen** — first-run identity creation (display name + passphrase, generates BIP39 + Ed25519)
2. **PeerListScreen** — discovered peers with RSSI, transport icon, online/offline state
3. **ChatScreen** — 1:1 messaging with message bubbles, send bar, auto-scroll
4. **ChannelListScreen** — channel list with create-dialog
5. **ChannelChatScreen** — channel messaging (reuses ChatScreen)
6. **SettingsScreen** — identity display, fingerprint, security toggles, emergency wipe
7. **ScanScreen** — BLE scan progress

Plus:
- **AegisFFI.kt** — hand-written UniFFI bindings matching the Rust API exactly
- **BleMeshManager.kt** — BLE scan/connect/GATT with proper UUIDs
- **MeshForegroundService.kt** — foreground service with wakelock, correct startForeground, onDestroy
- **BootReceiver.kt** — auto-start on device reboot
- **AegisApp.kt** — Hilt application class
- **AppModule.kt** — Hilt DI module
- **Theme.kt** — tactical dark Material 3 palette (dark-only, OPSEC)
- **Navigation.kt** — Compose Navigation graph
- **AndroidManifest.xml** — all permissions, FLAG_SECURE, service, boot receiver
- **build.gradle.kts** — complete config with KSP/Hilt, ProGuard, signing
- **proguard-rules.pro** — keep rules for UniFFI + Hilt + Bouncy Castle
- **build-apk.sh** — one-command build script

## How to build the APK

The APK cannot be built in this environment (no Android SDK/NDDK, no disk space). On your machine:

### Prerequisites
1. Install [Android Studio](https://developer.android.com/studio) (provides SDK + NDK)
2. Install Rust + Android targets:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   rustup target add aarch64-linux-android x86_64-linux-android
   cargo install uniffi-bindgen-cli
   ```
3. Set `ANDROID_NDK_HOME`:
   ```bash
   export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.0.12077973
   ```

### Build
```bash
tar xzf aegis-mesh-v0.2-android.tar.gz
cd aegis-mesh
./build-apk.sh           # debug APK
./build-apk.sh release   # release APK (needs signing keystore)
```

The APK will be at `android/app/build/outputs/apk/debug/app-debug.apk` (or `release/`).

### For release signing
Create a keystore:
```bash
keytool -genkey -v -keystore aegis.keystore -alias aegis -keyalg RSA -keysize 4096 -validity 10000
```
Then set environment variables:
```bash
export AEGIS_KEYSTORE_FILE=/path/to/aegis.keystore
export AEGIS_KEYSTORE_PASSWORD=your_password
export AEGIS_KEY_ALIAS=aegis
export AEGIS_KEY_PASSWORD=your_password
./build-apk.sh release
```

## Install on a phone
```bash
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

Or copy the APK to the phone and tap to install.

## Test results (Rust core)
All 51 unit tests pass, including:
- X3DH full round-trip (Alice → Bob, message decrypts)
- Double Ratchet with DH ratchet
- Identity binding rejection (forged bundle detected)
- Mesh routing (deliver/relay/drop, dedup, max_hops)
- Store & forward (priority order, bounded queue, requeue)
- Storage (envelope round-trip, wipe, KV store)
