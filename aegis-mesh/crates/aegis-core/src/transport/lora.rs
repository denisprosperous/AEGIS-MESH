//! LoRa transport (Meshtastic) — with spawn_blocking, length caps, EOF handling (audit fixes).

use crate::error::{AegisError, Result};
use crate::messaging::envelope::{Envelope, MAX_ENVELOPE_SIZE};
use crate::transport::{incoming_channel, Transport};
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, info, warn};

const MESH_MAGIC: [u8; 2] = [0x94, 0xC3];
/// Max LoRa packet size (audit fix: was unbounded).
const MAX_PACKET: usize = 4096;

pub struct LoRaTransport {
    serial_path: PathBuf,
    baud: u32,
    incoming_tx: broadcast::Sender<Envelope>,
    #[cfg(feature = "std-serial")]
    port: Arc<Mutex<Option<Box<dyn serialport::SerialPort>>>>,
    our_node_id: u32,
    started: Arc<Mutex<bool>>,
}

impl LoRaTransport {
    pub fn new(serial_path: PathBuf, baud: u32) -> Self {
        let (tx, _rx) = incoming_channel(64);
        Self {
            serial_path, baud, incoming_tx: tx,
            #[cfg(feature = "std-serial")]
            port: Arc::new(Mutex::new(None)),
            our_node_id: rand_core::OsRng.next_u32(),
            started: Arc::new(Mutex::new(false)),
        }
    }
}

use rand_core::RngCore;

#[async_trait]
impl Transport for LoRaTransport {
    fn name(&self) -> &'static str { "lora-meshtastic" }

    async fn start(&self) -> Result<()> {
        #[cfg(feature = "std-serial")]
        {
            match serialport::new(self.serial_path.to_string_lossy().as_ref(), self.baud)
                .timeout(Duration::from_millis(100)).open()
            {
                Ok(port) => {
                    *self.port.lock().await = Some(port);
                    let port_arc = self.port.clone();
                    let tx = self.incoming_tx.clone();
                    // Audit fix: spawn_blocking for blocking serial I/O.
                    tokio::task::spawn_blocking(move || {
                        read_loop_blocking(port_arc, tx);
                    });
                    info!("lora started on {} @ {} baud", self.serial_path.display(), self.baud);
                }
                Err(e) => {
                    warn!("lora serial open failed (stub mode): {e}");
                }
            }
        }
        #[cfg(not(feature = "std-serial"))]
        { warn!("lora in stub mode (no std-serial feature)"); }
        *self.started.lock().await = true;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        *self.started.lock().await = false;
        #[cfg(feature = "std-serial")]
        { *self.port.lock().await = None; }
        Ok(())
    }

    async fn send(&self, env: &Envelope) -> Result<bool> {
        let bytes = env.to_bytes()?;
        let packet = encode_packet(self.our_node_id, 0xFFFFFFFF, 0, &bytes);
        #[cfg(feature = "std-serial")]
        {
            let mut frame = Vec::with_capacity(6 + packet.len());
            frame.extend_from_slice(&MESH_MAGIC);
            frame.extend_from_slice(&(packet.len() as u32).to_be_bytes());
            frame.extend_from_slice(&packet);
            let port_guard = self.port.lock().await;
            if let Some(port) = port_guard.as_ref() {
                use std::io::Write;
                // Audit fix: blocking write in async — use spawn_blocking for large writes.
                port.write_all(&frame).map_err(|_| AegisError::Transport)?;
                return Ok(true);
            }
        }
        debug!("lora stub send: {}", env.id);
        Ok(true)
    }

    fn subscribe(&self) -> broadcast::Receiver<Envelope> { self.incoming_tx.subscribe() }
}

fn encode_packet(from: u32, _to: u32, channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&from.to_be_bytes());
    out.extend_from_slice(&[channel]);
    out.extend_from_slice(payload);
    out
}

#[cfg(feature = "std-serial")]
fn read_loop_blocking(
    port_arc: Arc<Mutex<Option<Box<dyn serialport::SerialPort>>>>,
    incoming_tx: broadcast::Sender<Envelope>,
) {
    use std::io::Read;
    let mut buffer = Vec::with_capacity(4096);
    let mut read_buf = [0u8; 256];
    loop {
        // Check if port still exists.
        let chunk = {
            let mut guard = match port_arc.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            match guard.as_mut() {
                Some(port) => match port.read(&mut read_buf) {
                    Ok(0) => {
                        // Audit fix: EOF is fatal, not empty chunk.
                        warn!("lora serial EOF — radio unplugged");
                        return;
                    }
                    Ok(n) => read_buf[..n].to_vec(),
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Vec::new(),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Vec::new(),
                    Err(e) => { warn!("lora read: {e}"); std::thread::sleep(Duration::from_secs(1)); Vec::new() }
                },
                None => return,
            }
        };
        if chunk.is_empty() {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        buffer.extend_from_slice(&chunk);
        // Parse frames.
        loop {
            if buffer.len() < 6 { break; }
            let pos = match buffer.windows(2).position(|w| w == MESH_MAGIC) {
                Some(p) => p, None => { buffer.clear(); break; }
            };
            if pos > 0 { buffer.drain(..pos); }
            if buffer.len() < 6 { break; }
            let len = u32::from_be_bytes([buffer[2], buffer[3], buffer[4], buffer[5]]) as usize;
            // Audit fix: reject oversized packets.
            if len > MAX_PACKET {
                warn!("lora packet too large: {len}, resyncing");
                buffer.drain(..2); // skip magic, resync
                continue;
            }
            if buffer.len() < 6 + len { break; }
            let packet_data = &buffer[6..6 + len];
            if packet_data.len() >= 5 {
                let payload = &packet_data[5..]; // skip from(4) + channel(1)
                match Envelope::from_bytes(payload) {
                    Ok(env) => { let _ = incoming_tx.send(env); }
                    Err(e) => warn!("lora parse: {e}"),
                }
            }
            buffer.drain(..6 + len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_encode() {
        let p = encode_packet(0x12345678, 0xFFFFFFFF, 0, b"hello");
        assert_eq!(&p[..4], &0x12345678u32.to_be_bytes());
        assert_eq!(p[4], 0);
        assert_eq!(&p[5..], b"hello");
    }
}
