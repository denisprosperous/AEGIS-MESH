//! Loopback transport — with async-correct shutdown, 0600 perms, length caps (audit fixes).

use crate::error::{AegisError, Result};
use crate::messaging::envelope::{Envelope, MAX_ENVELOPE_SIZE};
use crate::transport::{incoming_channel, Transport};
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub struct LoopbackTransport {
    socket_path: PathBuf,
    incoming_tx: broadcast::Sender<Envelope>,
    write_halfs: Arc<Mutex<Vec<OwnedWriteHalf>>>,
    cancel: CancellationToken,
    listener: Arc<Mutex<Option<UnixListener>>>,
}

impl LoopbackTransport {
    pub fn new(socket_path: PathBuf) -> Self {
        let (tx, _rx) = incoming_channel(256);
        Self {
            socket_path, incoming_tx: tx,
            write_halfs: Arc::new(Mutex::new(Vec::new())),
            cancel: CancellationToken::new(),
            listener: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl Transport for LoopbackTransport {
    fn name(&self) -> &'static str { "loopback" }

    async fn start(&self) -> Result<()> {
        // Audit fix: reject symlinks (TOCTOU protection).
        if let Ok(meta) = tokio::fs::symlink_metadata(&self.socket_path).await {
            if meta.file_type().is_symlink() {
                return Err(AegisError::Invalid);
            }
            let _ = tokio::fs::remove_file(&self.socket_path).await;
        }
        if let Some(parent) = self.socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        *self.listener.lock().await = Some(listener);

        // Audit fix: set 0600 permissions on socket.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600));
        }

        let incoming_tx = self.incoming_tx.clone();
        let write_halfs = self.write_halfs.clone();
        let listener_arc = self.listener.clone();
        let cancel = self.cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    accept_result = async {
                        let listener_opt = listener_arc.lock().await;
                        match listener_opt.as_ref() {
                            Some(l) => l.accept().await,
                            None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "no listener")),
                        }
                    } => {
                        match accept_result {
                            Ok((stream, _)) => {
                                let tx = incoming_tx.clone();
                                let wh = write_halfs.clone();
                                tokio::spawn(async move { handle_client(stream, tx, wh).await; });
                            }
                            Err(e) => { warn!("loopback accept: {e}"); break; }
                        }
                    }
                }
            }
            debug!("loopback listener exited");
        });

        info!("loopback listening on {}", self.socket_path.display());
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.cancel.cancel(); // Audit fix: signal cancellation (was deadlocking).
        *self.listener.lock().await = None;
        self.write_halfs.lock().await.clear();
        let _ = std::fs::remove_file(&self.socket_path);
        Ok(())
    }

    async fn send(&self, env: &Envelope) -> Result<bool> {
        let bytes = env.to_bytes()?;
        // Audit fix: build single buffer (was two write_all calls — partial failure desync).
        let len_bytes = (bytes.len() as u32).to_be_bytes();
        let mut frame = Vec::with_capacity(4 + bytes.len());
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(&bytes);

        let mut write_halfs = self.write_halfs.lock().await;
        if write_halfs.is_empty() { return Ok(false); }
        let mut delivered = 0;
        let mut failed = Vec::new();
        for (i, wh) in write_halfs.iter_mut().enumerate() {
            if let Err(e) = wh.write_all(&frame).await {
                warn!("loopback write: {e}");
                failed.push(i);
            } else { delivered += 1; }
        }
        for i in failed.into_iter().rev() { write_halfs.remove(i); }
        Ok(delivered > 0)
    }

    fn subscribe(&self) -> broadcast::Receiver<Envelope> { self.incoming_tx.subscribe() }
}

async fn handle_client(
    stream: UnixStream,
    incoming_tx: broadcast::Sender<Envelope>,
    write_halfs: Arc<Mutex<Vec<OwnedWriteHalf>>>,
) {
    let (read_half, write_half) = stream.into_split();
    write_halfs.lock().await.push(write_half);
    let mut reader = read_half;
    let mut len_buf = [0u8; 4];
    loop {
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {
                let len = u32::from_be_bytes(len_buf) as usize;
                // Audit fix: cap length (was 1MB, now 64KB).
                if len > MAX_ENVELOPE_SIZE {
                    warn!("loopback frame too large: {len}");
                    break;
                }
                let mut payload = vec![0u8; len];
                if let Err(e) = reader.read_exact(&mut payload).await {
                    warn!("loopback read payload: {e}"); break;
                }
                match Envelope::from_bytes(&payload) {
                    Ok(env) => { let _ = incoming_tx.send(env); }
                    Err(e) => warn!("loopback parse: {e}"),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => { warn!("loopback read: {e}"); break; }
        }
    }
    debug!("loopback client disconnected");
}

/// Connect to a loopback hub.
pub async fn connect_to_hub(
    socket_path: PathBuf,
    incoming_tx: broadcast::Sender<Envelope>,
) -> Result<OwnedWriteHalf> {
    let stream = UnixStream::connect(&socket_path).await
        .map_err(|e| AegisError::Transport)?;
    let (mut read_half, write_half) = stream.into_split();
    tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        loop {
            match read_half.read_exact(&mut len_buf).await {
                Ok(_) => {
                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len > MAX_ENVELOPE_SIZE { break; }
                    let mut payload = vec![0u8; len];
                    if read_half.read_exact(&mut payload).await.is_err() { break; }
                    if let Ok(env) = Envelope::from_bytes(&payload) {
                        let _ = incoming_tx.send(env);
                    }
                }
                Err(_) => break,
            }
        }
    });
    Ok(write_half)
}
