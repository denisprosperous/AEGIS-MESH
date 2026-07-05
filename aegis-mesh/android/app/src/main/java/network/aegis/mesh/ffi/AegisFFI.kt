package network.aegis.mesh.ffi

/**
 * Hand-written Kotlin bindings for the AEGIS-MESH Rust core (aegis-ffi).
 *
 * These match the #[uniffi::export] functions in crates/aegis-ffi/src/lib.rs.
 * To regenerate from source after API changes:
 *   cargo build --release -p aegis-ffi --target aarch64-linux-android
 *   uniffi-bindgen generate --library libaegis_ffi.so --language kotlin --out-dir .
 */
object AegisFFI {
    init {
        System.loadLibrary("aegis_ffi")
    }

    /** Generate a new identity. Returns encrypted blob. */
    external fun generateIdentity(displayName: String, passphrase: String): ByteArray

    /** Get the identity ID from an encrypted blob. */
    external fun getIdentityId(blob: ByteArray, passphrase: String): String

    /** Get the display name. */
    external fun getDisplayName(blob: ByteArray, passphrase: String): String

    /** Get the fingerprint display string (10 groups of 4 hex chars). */
    external fun getFingerprint(blob: ByteArray, passphrase: String): String

    /** Get the verifying key bytes (32 bytes). */
    external fun getVerifyingKey(blob: ByteArray, passphrase: String): ByteArray

    /** Compute the 60-digit safety number between two fingerprint hex strings. */
    external fun safetyNumber(fp1Hex: String, fp2Hex: String): String

    /** Build a signed direct message envelope. Returns JSON bytes. */
    external fun buildDirectMessage(
        blob: ByteArray,
        passphrase: String,
        recipientId: String,
        text: String,
    ): ByteArray

    /** Parse an envelope and return the sender ID. */
    external fun parseEnvelopeSender(envelopeBytes: ByteArray): String

    /** Inject BLE bytes from the Kotlin GATT callback. */
    external fun injectBleBytes(bytes: ByteArray)

    /** Emergency wipe — clear all in-memory state. */
    external fun emergencyWipe()
}
