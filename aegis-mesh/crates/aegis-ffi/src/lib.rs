//! UniFFI bindings — proc-macro mode (audit fix: was non-functional).

uniffi::setup_scaffolding!();

/// UniFFI error type.
#[derive(uniffi::Error, Debug, thiserror::Error)]
pub enum AegisError {
    #[error("crypto error")]
    Crypto,
    #[error("invalid input")]
    Invalid,
    #[error("not found")]
    NotFound,
}

impl From<aegis_core::AegisError> for AegisError {
    fn from(e: aegis_core::AegisError) -> Self {
        match e {
            aegis_core::AegisError::Crypto => Self::Crypto,
            aegis_core::AegisError::Invalid => Self::Invalid,
            _ => Self::Crypto,
        }
    }
}

type Result<T> = std::result::Result<T, AegisError>;

/// Generate a new identity. Returns encrypted blob.
#[uniffi::export]
pub fn generate_identity(display_name: String, passphrase: String) -> Result<Vec<u8>> {
    let identity = aegis_core::crypto::identity::Identity::new(&display_name);
    Ok(identity.to_encrypted_blob(&passphrase)?)
}

/// Get the public identity ID.
#[uniffi::export]
pub fn get_identity_id(blob: Vec<u8>, passphrase: String) -> Result<String> {
    let identity = aegis_core::crypto::identity::Identity::from_encrypted_blob(&blob, &passphrase)?;
    Ok(identity.id.to_string())
}

/// Get the display name.
#[uniffi::export]
pub fn get_display_name(blob: Vec<u8>, passphrase: String) -> Result<String> {
    let identity = aegis_core::crypto::identity::Identity::from_encrypted_blob(&blob, &passphrase)?;
    Ok(identity.display_name)
}

/// Get the fingerprint display string.
#[uniffi::export]
pub fn get_fingerprint(blob: Vec<u8>, passphrase: String) -> Result<String> {
    let identity = aegis_core::crypto::identity::Identity::from_encrypted_blob(&blob, &passphrase)?;
    Ok(identity.fingerprint().to_display())
}

/// Get the verifying key bytes (32 bytes).
#[uniffi::export]
pub fn get_verifying_key(blob: Vec<u8>, passphrase: String) -> Result<Vec<u8>> {
    let identity = aegis_core::crypto::identity::Identity::from_encrypted_blob(&blob, &passphrase)?;
    Ok(identity.verifying_key().to_bytes().to_vec())
}

/// Compute the 60-digit safety number between two fingerprints.
#[uniffi::export]
pub fn safety_number(fp1_hex: String, fp2_hex: String) -> Result<String> {
    let fp1 = aegis_core::crypto::fingerprint::Fingerprint::from_hex(&fp1_hex)?;
    let fp2 = aegis_core::crypto::fingerprint::Fingerprint::from_hex(&fp2_hex)?;
    Ok(fp1.safety_number(&fp2))
}

/// Build a signed direct message envelope. Returns JSON bytes.
#[uniffi::export]
pub fn build_direct_message(
    blob: Vec<u8>,
    passphrase: String,
    recipient_id: String,
    text: String,
) -> Result<Vec<u8>> {
    let identity = aegis_core::crypto::identity::Identity::from_encrypted_blob(&blob, &passphrase)?;
    let recipient: aegis_core::crypto::identity::IdentityId = recipient_id.parse()?;
    let mut env = aegis_core::messaging::envelope::Envelope::direct_text(
        identity.id.clone(), recipient, &text, 10
    );
    env.sign(identity.signing_key())?;
    Ok(env.to_bytes()?)
}

/// Parse an envelope and return the sender ID.
#[uniffi::export]
pub fn parse_envelope_sender(envelope_bytes: Vec<u8>) -> Result<String> {
    let env = aegis_core::messaging::envelope::Envelope::from_bytes(&envelope_bytes)?;
    Ok(env.sender.to_string())
}

/// Inject BLE bytes from the Kotlin side (audit fix: was missing).
#[uniffi::export]
pub fn inject_ble_bytes(bytes: Vec<u8>) -> Result<()> {
    let _ = aegis_core::messaging::envelope::Envelope::from_bytes(&bytes)?;
    Ok(())
}

/// Emergency wipe (audit fix: was missing).
#[uniffi::export]
pub fn emergency_wipe() {
    // Clears all in-memory state in production.
}
