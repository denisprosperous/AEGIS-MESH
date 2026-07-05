# Building the AEGIS-MESH Android APK

This guide walks through building a signed APK from source.

## Prerequisites

### 1. Android Studio

Download and install [Android Studio](https://developer.android.com/studio) (Hedgehog 2023.1.1 or later). This provides:
- Android SDK (API 34)
- Android NDK (27.0.12077973 or later)
- Gradle 8.7+

### 2. Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
rustup target add aarch64-linux-android x86_64-linux-android
cargo install uniffi-bindgen-cli
```

### 3. Environment variables

```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.0.12077973
```

Verify:
```bash
ls $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang
```

## Build

### Option A: One-command build script

```bash
./build-apk.sh           # debug APK
./build-apk.sh release   # release APK (needs signing keystore)
```

The script:
1. Cross-compiles `aegis-ffi` for `arm64-v8a` and `x86_64`
2. Copies `.so` files into `android/app/src/main/jniLibs/`
3. Generates UniFFI Kotlin bindings
4. Runs `./gradlew assembleDebug` or `assembleRelease`

### Option B: Manual build

```bash
# 1. Cross-compile Rust
cargo build --release -p aegis-ffi --target aarch64-linux-android
cargo build --release -p aegis-ffi --target x86_64-linux-android

# 2. Copy native libraries
mkdir -p android/app/src/main/jniLibs/{arm64-v8a,x86_64}
cp target/aarch64-linux-android/release/libaegis_ffi.so android/app/src/main/jniLibs/arm64-v8a/
cp target/x86_64-linux-android/release/libaegis_ffi.so android/app/src/main/jniLibs/x86_64/

# 3. Generate UniFFI Kotlin bindings
uniffi-bindgen generate \
    --library target/aarch64-linux-android/release/libaegis_ffi.so \
    --language kotlin \
    --out-dir android/app/src/main/java/network/aegis/mesh/ffi/

# 4. Build APK
cd android
./gradlew assembleDebug
```

## Signing the release APK

### 1. Create a keystore

```bash
keytool -genkey -v \
    -keystore aegis.keystore \
    -alias aegis \
    -keyalg RSA -keysize 4096 \
    -validity 10000
```

### 2. Set environment variables

```bash
export AEGIS_KEYSTORE_FILE=/path/to/aegis.keystore
export AEGIS_KEYSTORE_PASSWORD=your_keystore_password
export AEGIS_KEY_ALIAS=aegis
export AEGIS_KEY_PASSWORD=your_key_password
```

### 3. Build release APK

```bash
./build-apk.sh release
```

The signed APK will be at:
```
android/app/build/outputs/apk/release/app-release.apk
```

## Install on a phone

```bash
# Enable USB debugging on the phone, connect via USB
adb install -r android/app/build/outputs/apk/debug/app-debug.apk

# Or copy the APK to the phone and tap to install
```

## Troubleshooting

### "failed to find tool aarch64-linux-android-clang"

`ANDROID_NDK_HOME` is not set or points to the wrong location. Verify the path contains `toolchains/llvm/prebuilt/linux-x86_64/bin/`.

### "uniffi-bindgen: command not found"

Install it: `cargo install uniffi-bindgen-cli`

### Gradle build fails with "SDK location not found"

Create `android/local.properties`:
```
sdk.dir=/home/youruser/Android/Sdk
```

### Build runs out of memory

Add to `android/gradle.properties`:
```
org.gradle.jvmargs=-Xmx4g
```

### App crashes on launch with "UnsatisfiedLinkError"

The native library (`libaegis_ffi.so`) is missing for your device's ABI. Verify:
- `android/app/src/main/jniLibs/arm64-v8a/libaegis_ffi.so` exists (for physical devices)
- `android/app/src/main/jniLibs/x86_64/libaegis_ffi.so` exists (for emulators)

## System requirements

- 8 GB RAM minimum (16 GB recommended for release builds)
- 10 GB free disk space (SDK + NDK + Gradle cache + build artifacts)
- Linux, macOS, or Windows (WSL2 for Windows)
- JDK 17 (bundled with Android Studio)
