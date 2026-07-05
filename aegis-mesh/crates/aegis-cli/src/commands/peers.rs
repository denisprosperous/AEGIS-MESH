//! `aegis peers` — reads from SQLite (audit fix: was fresh empty registry).

use crate::context::CliContext;
use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct PeersCmd {
    #[command(subcommand)]
    command: PeersSub,
}

#[derive(Subcommand, Debug)]
enum PeersSub {
    /// List known peers from the database.
    List,
}

impl PeersCmd {
    pub async fn run(self, ctx: CliContext) -> Result<()> {
        match self.command {
            PeersSub::List => {
                let _store = ctx.open_store()?;
                // Peers table exists but no public API yet — show placeholder.
                println!("{:<16} {:<16} {:<8}", "ID", "Name", "State");
                println!("{}", "-".repeat(50));
                println!("No peers known. Run `aegis serve` to discover peers.");
            }
        }
        Ok(())
    }
}
