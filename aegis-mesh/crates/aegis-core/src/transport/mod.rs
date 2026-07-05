//! Transport layer — BLE, LoRa (Meshtastic), loopback.

pub mod ble;
pub mod lora;
pub mod loopback;

use crate::error::Result;
use crate::messaging::envelope::Envelope;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::broadcast;

#[async_trait]
pub trait Transport: Send + Sync {
    fn name(&self) -> &'static str;
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn send(&self, env: &Envelope) -> Result<bool>;
    fn subscribe(&self) -> broadcast::Receiver<Envelope>;
}

pub type DynTransport = Arc<dyn Transport>;

pub fn incoming_channel(capacity: usize) -> (broadcast::Sender<Envelope>, broadcast::Receiver<Envelope>) {
    broadcast::channel(capacity)
}
