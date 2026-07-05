//! `aegis serve` — honors --announce-interval, proper shutdown (audit fixes).

use crate::context::CliContext;
use aegis_core::crypto::identity::Identity;
use aegis_core::mesh::router::{RouteDecision, Router};
use aegis_core::mesh::store_forward::StoreForward;
use aegis_core::messaging::envelope::{Envelope, EnvelopeType, Payload};
use aegis_core::transport::ble::BleTransport;
use aegis_core::transport::lora::LoRaTransport;
use aegis_core::transport::loopback::LoopbackTransport;
use aegis_core::transport::Transport;
use anyhow::{anyhow, Result};
use clap::Args;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

#[derive(Args, Debug)]
pub struct ServeCmd {
    #[arg(long)]
    loopback: bool,
    #[arg(long)]
    lora: bool,
    #[arg(long)]
    lora_device: Option<std::path::PathBuf>,
    #[arg(long, default_value = "115200")]
    lora_baud: u32,
    #[arg(long)]
    ble: bool,
    /// Audit fix: honored (was silently ignored).
    #[arg(long, default_value = "30")]
    announce_interval: u64,
}

impl ServeCmd {
    pub async fn run(self, ctx: CliContext) -> Result<()> {
        let blob = ctx.read_identity_blob()?
            .ok_or_else(|| anyhow!("No identity. Run `aegis identity create` first."))?;
        let passphrase = CliContext::prompt_passphrase()?;
        let identity = Identity::from_encrypted_blob(&blob, &passphrase)
            .map_err(|e| anyhow!("decrypt: {e}"))?;

        info!("Starting AEGIS-MESH node: {} ({})", identity.display_name, identity.id);

        let router = Arc::new(Router::new(identity.id.clone(), 10));
        let store_forward = Arc::new(StoreForward::new());
        let (incoming_tx, _) = broadcast::channel::<Envelope>(256);
        let mut transports: Vec<Arc<dyn Transport>> = Vec::new();

        if self.loopback {
            let t = Arc::new(LoopbackTransport::new(ctx.socket_path.clone()));
            t.start().await.map_err(|e| anyhow!("loopback: {e}"))?;
            let rx = t.subscribe();
            let tx = incoming_tx.clone();
            tokio::spawn(async move { let mut rx = rx; while let Ok(env) = rx.recv().await { let _ = tx.send(env); } });
            transports.push(t);
        }
        if self.lora {
            let dev = self.lora_device.clone().unwrap_or_else(|| std::path::PathBuf::from("/dev/ttyUSB0"));
            let t = Arc::new(LoRaTransport::new(dev, self.lora_baud));
            t.start().await.map_err(|e| anyhow!("lora: {e}"))?;
            let rx = t.subscribe();
            let tx = incoming_tx.clone();
            tokio::spawn(async move { let mut rx = rx; while let Ok(env) = rx.recv().await { let _ = tx.send(env); } });
            transports.push(t);
        }
        if self.ble {
            let t = Arc::new(BleTransport::new());
            t.start().await.map_err(|e| anyhow!("ble: {e}"))?;
            let rx = t.subscribe();
            let tx = incoming_tx.clone();
            tokio::spawn(async move { let mut rx = rx; while let Ok(env) = rx.recv().await { let _ = tx.send(env); } });
            transports.push(t);
        }
        if transports.is_empty() {
            warn!("No transports enabled. Use --loopback, --lora, or --ble.");
            return Ok(());
        }

        let mut incoming_rx = incoming_tx.subscribe();
        let our_id = identity.id.clone();
        let signing_key = identity.signing_key().clone();
        let verifying_key_bytes = identity.verifying_key().to_bytes();
        let peers = Arc::new(aegis_core::mesh::peer::PeerRegistry::new());

        // Audit fix: honor --announce-interval (was hardcoded 30).
        let announce_interval = self.announce_interval;
        let announce_router = router.clone();
        let announce_transports = transports.clone();
        let announce_peers = peers.clone();
        tokio::spawn(async move {
            let mut seq: u64 = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(announce_interval)).await;
                seq += 1;
                let mut env = Envelope::route_announce(
                    announce_router.our_id.clone(),
                    announce_router.our_id.clone(),
                    verifying_key_bytes,
                    0, seq, 10,
                );
                if env.sign(&signing_key).is_err() { continue; }
                for t in &announce_transports { let _ = t.send(&env).await; }
                let _ = announce_peers;
            }
        });

        // GC task for dedup cache (audit fix: was never called).
        let gc_router = router.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                gc_router.table.gc_seen().await;
            }
        });

        info!("Node running. Ctrl-C to stop.");
        loop {
            tokio::select! {
                Ok(env) = incoming_rx.recv() => {
                    Self::handle_inbound(&our_id, &router, &store_forward, &transports, &peers, env).await;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutting down...");
                    break;
                }
            }
        }
        for t in &transports { let _ = t.stop().await; }
        Ok(())
    }

    async fn handle_inbound(
        our_id: &aegis_core::crypto::identity::IdentityId,
        router: &Arc<Router>,
        store_forward: &Arc<StoreForward>,
        transports: &[Arc<dyn Transport>],
        peers: &Arc<aegis_core::mesh::peer::PeerRegistry>,
        env: Envelope,
    ) {
        if env.sender == *our_id { return; }
        match router.route_inbound(&env).await {
            Ok(RouteDecision::Deliver) => Self::display(&env),
            Ok(RouteDecision::DeliverAndRelay) => {
                Self::display(&env);
                Self::relay(&env, router, transports, peers).await;
            }
            Ok(RouteDecision::Relay) => Self::relay(&env, router, transports, peers).await,
            Ok(RouteDecision::Drop) => {}
            Err(e) => error!("route: {e}"),
        }
    }

    async fn relay(
        env: &Envelope,
        router: &Arc<Router>,
        transports: &[Arc<dyn Transport>],
        peers: &Arc<aegis_core::mesh::peer::PeerRegistry>,
    ) {
        let mut env = env.clone();
        if !env.advance_ttl(router.max_hops) { return; }
        let neighbors = peers.neighbor_ids().await;
        let _targets = router.forward_targets(&env, &neighbors).await;
        // Audit fix: flood once (was flooded twice).
        for t in transports { let _ = t.send(&env).await; }
    }

    fn display(env: &Envelope) {
        if let Payload::Text(text) = &env.payload {
            let ts = time::OffsetDateTime::now_utc()
                .format(time::macros::format_description!("[hour]:[minute]:[second]"))
                .unwrap_or_else(|_| "??:??:??".into());
            let id_short = &env.sender.as_str()[..8.min(env.sender.as_str().len())];
            println!("[{ts}] {id_short} > {text}");
        }
    }
}

fn identity_key_bytes() -> [u8; 32] { [0u8; 32] }
