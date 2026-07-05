#!/usr/bin/env bash
# build-apk.sh — Build the AEGIS-MESH Android APK.
#
# Prerequisites:
#   1. Android Studio installed (provides SDK + NDK)
#   2. Rust installed with Android targets:
#        rustup target add aarch64-linux-android x86_64-linux-android
#   3. ANDROID_NDK_HOME set (e.g. ~/Android/Sdk/ndk/27.0.12077973)
#   4. uniffi-bindgen installed:
#        cargo install uniffi-bindgen-cli
#
# Usage:
#   ./build-apk.sh            # debug APK
#   ./build-apk.sh release     # release APK (needs signing config)

set -euo pipefail
cd "$(dirname "$0")"

BUILD_TYPE="${1:-debug}"
NDK_HOME="${ANDROID_NDK_HOME:-$HOME/Android/Sdk/ndk/27.0.12077973}"

echo "=== AEGIS-MESH Android Build ==="
echo "Build type: $BUILD_TYPE"
echo "NDK: $NDK_HOME"
echo ""

# Step 1: Cross-compile Rust core for Android
echo "[1/4] Cross-compiling Rust core (aegis-ffi)..."
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android26-clang"
export CC_aarch64_linux_android="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
export CC_x86_64_linux_android="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android26-clang"
export CXX_aarch64_linux_android="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++"
export CXX_x86_64_linux_android="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android26-clang++"

cargo build --release -p aegis-ffi --target aarch64-linux-android
cargo build --release -p aegis-ffi --target x86_64-linux-android

# Step 2: Copy .so files into jniLibs
echo "[2/4] Copying native libraries..."
mkdir -p android/app/src/main/jniLibs/arm64-v8a
mkdir -p android/app/src/main/jniLibs/x86_64
cp target/aarch64-linux-android/release/libaegis_ffi.so android/app/src/main/jniLibs/arm64-v8a/
cp target/x86_64-linux-android/release/libaegis_ffi.so android/app/src/main/jniLibs/x86_64/

# Step 3: Generate UniFFI Kotlin bindings
echo "[3/4] Generating UniFFI Kotlin bindings..."
uniffi-bindgen generate \
    --library target/aarch64-linux-android/release/libaegis_ffi.so \
    --language kotlin \
    --out-dir android/app/src/main/java/network/aegis/mesh/ffi/

# Step 4: Build APK
echo "[4/4] Building APK..."
cd android
if [ "$BUILD_TYPE" = "release" ]; then
    ./gradlew assembleRelease
    echo ""
    echo "=== APK Built ==="
    echo "Location: app/build/outputs/apk/release/app-release.apk"
else
    ./gradlew assembleDebug
    echo ""
    echo "=== APK Built ==="
    echo "Location: app/build/outputs/apk/debug/app-debug.apk"
fi
