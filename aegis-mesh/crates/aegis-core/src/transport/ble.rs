//! BLE transport — JNI bridge with bounded queue (audit fix: was unbounded Vec).

use crate::error::{AegisError, Result};
use crate::messaging::envelope::{Envelope, MAX_ENVELOPE_SIZE};
use crate::transport::{incoming_channel, Transport};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, info};

/// Real BLE service UUID (audit fix: was "aegis-mesh-ble-v1" — not a valid UUID).
pub const AEGIS_SERVICE_UUID: &str = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";

/// Bounded outgoing queue (audit fix: was unbounded Vec → OOM on disconnect).
const MAX_OUTGOING: usize = 256;

pub struct BleTransport {
    incoming_tx: broadcast::Sender<Envelope>,
    outgoing: Arc<Mutex<Vec<Envelope>>>,
    started: Arc<Mutex<bool>>,
}

impl BleTransport {
    pub fn new() -> Self {
        let (tx, _rx) = incoming_channel(256);
        Self {
            incoming_tx: tx,
            outgoing: Arc::new(Mutex::new(Vec::new())),
            started: Arc::new(Mutex::new(false)),
        }
    }

    /// Inject incoming bytes from Kotlin BLE callback — with size cap (audit fix).
    pub async fn inject_incoming(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_ENVELOPE_SIZE {
            return Err(AegisError::Invalid);
        }
        let env = Envelope::from_bytes(bytes)?;
        let _ = self.incoming_tx.send(env);
        Ok(())
    }

    /// Drain outgoing — bounded (audit fix: was unbounded).
    pub async fn drain_outgoing(&self) -> Vec<Envelope> {
        let mut q = self.outgoing.lock().await;
        if q.len() > MAX_OUTGOING {
            // Drop oldest to prevent OOM.
            let excess = q.len() - MAX_OUTGOING;
            q.drain(..excess);
        }
        std::mem::take(&mut *q)
    }
}

impl Default for BleTransport { fn default() -> Self { Self::new() } }

#[async_trait]
impl Transport for BleTransport {
    fn name(&self) -> &'static str { "ble" }

    async fn start(&self) -> Result<()> {
        *self.started.lock().await = true;
        info!("ble transport started (JNI bridge mode)");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        *self.started.lock().await = false;
        Ok(())
    }

    async fn send(&self, env: &Envelope) -> Result<bool> {
        let started = self.started.lock().await;
        if !*started { return Err(AegisError::Transport); }
        drop(started);
        let mut q = self.outgoing.lock().await;
        // Audit fix: bound the queue.
        if q.len() >= MAX_OUTGOING {
            q.remove(0); // drop oldest
        }
        q.push(env.clone());
        debug!("ble queued envelope {}", env.id);
        Ok(true)
    }

    fn subscribe(&self) -> broadcast::Receiver<Envelope> { self.incoming_tx.subscribe() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    #[tokio::test]
    async fn inject_size_capped() {
        let ble = BleTransport::new();
        ble.start().await.unwrap();
        let big = vec![0u8; MAX_ENVELOPE_SIZE + 1];
        assert!(ble.inject_incoming(&big).await.is_err());
    }

    #[tokio::test]
    async fn outgoing_bounded() {
        let ble = BleTransport::new();
        ble.start().await.unwrap();
        let alice = Identity::new("Alice").public_view().id;
        let bob = Identity::new("Bob").public_view().id;
        // Enqueue 2x MAX_OUTGOING.
        for _ in 0..(MAX_OUTGOING * 2) {
            let env = Envelope::direct_text(alice.clone(), bob.clone(), "x", 10);
            ble.send(&env).await.unwrap();
        }
        let drained = ble.drain_outgoing().await;
        assert!(drained.len() <= MAX_OUTGOING, "queue must be bounded");
    }
}
