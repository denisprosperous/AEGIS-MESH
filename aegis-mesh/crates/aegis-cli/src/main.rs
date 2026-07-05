//! AEGIS-MESH CLI v0.2 — audited and remediated.

mod commands;
mod context;

use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::{IdentityCmd, PeersCmd, SendCmd, ServeCmd, WipeCmd};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "aegis", version, about = "AEGIS-MESH — censorship-resistant comms")]
struct Cli {
    #[arg(long, global = true, env = "AEGIS_DATA_DIR")]
    data_dir: Option<std::path::PathBuf>,
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Identity management.
    Identity(IdentityCmd),
    /// Start the mesh node.
    Serve(ServeCmd),
    /// List known peers.
    Peers(PeersCmd),
    /// Send a message.
    Send(SendCmd),
    /// Emergency wipe.
    Wipe(WipeCmd),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let filter = match cli.verbose {
        0 => EnvFilter::new("warn,aegis=info"),
        1 => EnvFilter::new("info,aegis=debug"),
        _ => EnvFilter::new("debug,aegis=trace"),
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let data_dir = match cli.data_dir {
        Some(d) => d,
        None => aegis_core::config::default_data_dir()?,
    };
    std::fs::create_dir_all(&data_dir)?;
    // Audit fix: data dir 0700 permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700));
    }
    let ctx = context::CliContext::new(data_dir)?;
    match cli.command {
        Command::Identity(c) => c.run(ctx).await,
        Command::Serve(c) => c.run(ctx).await,
        Command::Peers(c) => c.run(ctx).await,
        Command::Send(c) => c.run(ctx).await,
        Command::Wipe(c) => c.run(ctx).await,
    }
}
