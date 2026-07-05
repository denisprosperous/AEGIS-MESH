# ProGuard rules for AEGIS-MESH

# Keep UniFFI bindings
-keep class network.aegis.mesh.ffi.** { *; }

# Keep Hilt generated code
-keep class dagger.hilt.** { *; }
-keep class * extends dagger.hilt.android.HiltAndroidApp { *; }

# Keep Compose
-keep class androidx.compose.** { *; }

# Bouncy Castle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Rust native library
-keep class network.aegis.mesh.AegisFFI { *; }

# Kotlin metadata
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes SourceFile,LineNumberTable
