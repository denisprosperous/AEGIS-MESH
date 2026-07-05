//! `aegis send` — actually transmits (audit fix: was no-op).

use crate::context::CliContext;
use aegis_core::crypto::identity::Identity;
use aegis_core::messaging::envelope::Envelope;
use aegis_core::transport::loopback::connect_to_hub;
use anyhow::{anyhow, Result};
use clap::Args;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;

#[derive(Args, Debug)]
pub struct SendCmd {
    #[arg(long, short)]
    to: String,
    #[arg(long, short)]
    message: Option<String>,
}

impl SendCmd {
    pub async fn run(self, ctx: CliContext) -> Result<()> {
        let blob = ctx.read_identity_blob()?
            .ok_or_else(|| anyhow!("No identity. Run `aegis identity create` first."))?;
        let passphrase = CliContext::prompt_passphrase()?;
        let identity = Identity::from_encrypted_blob(&blob, &passphrase)
            .map_err(|e| anyhow!("decrypt: {e}"))?;

        let recipient_id: aegis_core::crypto::identity::IdentityId = self.to.parse()
            .map_err(|e: aegis_core::AegisError| anyhow!("invalid recipient: {e}"))?;

        let text = match self.message {
            Some(m) => m,
            None => {
                use std::io::Read;
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s.trim().to_string()
            }
        };

        let mut env = Envelope::direct_text(identity.id.clone(), recipient_id.clone(), &text, 10);
        env.sign(identity.signing_key()).map_err(|e| anyhow!("sign: {e}"))?;

        // Audit fix: actually transmit (was no-op).
        let (tx, _rx) = broadcast::channel::<Envelope>(16);
        let mut write_half = connect_to_hub(ctx.socket_path.clone(), tx).await
            .map_err(|e| anyhow!("connect to hub: {e}. Is `aegis serve` running?"))?;

        let bytes = env.to_bytes().map_err(|e| anyhow!("serialize: {e}"))?;
        let len_bytes = (bytes.len() as u32).to_be_bytes();
        let mut frame = Vec::with_capacity(4 + bytes.len());
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(&bytes);
        write_half.write_all(&frame).await
            .map_err(|e| anyhow!("send: {e}"))?;

        println!("Sent to {} ({} bytes)", recipient_id, bytes.len());
        Ok(())
    }
}
