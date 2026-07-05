//! `aegis identity` — no --passphrase arg, never prints mnemonic to stdout (audit fixes).

use crate::context::CliContext;
use aegis_core::crypto::identity::Identity;
use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct IdentityCmd {
    #[command(subcommand)]
    command: IdentitySub,
}

#[derive(Subcommand, Debug)]
enum IdentitySub {
    /// Create a new identity.
    Create(CreateArgs),
    /// Show public identity.
    Show,
    /// Display mnemonic (requires passphrase, TTY only).
    Reveal,
    /// Import from mnemonic.
    Import(ImportArgs),
}

#[derive(Args, Debug)]
struct CreateArgs {
    #[arg(long, short)]
    name: String,
}

#[derive(Args, Debug)]
struct ImportArgs {
    #[arg(long, short)]
    name: String,
}

impl IdentityCmd {
    pub async fn run(self, ctx: CliContext) -> Result<()> {
        match self.command {
            IdentitySub::Create(args) => create(&ctx, args).await,
            IdentitySub::Show => show(&ctx).await,
            IdentitySub::Reveal => reveal(&ctx).await,
            IdentitySub::Import(args) => import(&ctx, args).await,
        }
    }
}

async fn create(ctx: &CliContext, args: CreateArgs) -> Result<()> {
    if ctx.identity_path.exists() {
        return Err(anyhow!("Identity already exists. Run `aegis wipe` first."));
    }
    // Audit fix: passphrase via rpassword (was --passphrase arg, visible in ps).
    let passphrase = CliContext::prompt_passphrase()?;
    if passphrase.len() < 8 {
        return Err(anyhow!("Passphrase must be at least 8 characters."));
    }
    let identity = Identity::new(&args.name);
    let blob = identity.to_encrypted_blob(&passphrase)
        .map_err(|e| anyhow!("encrypt: {e}"))?;
    ctx.write_identity_blob(&blob)?;

    println!("Identity created.");
    println!("  Name:        {}", identity.display_name);
    println!("  ID:          {}", identity.id);
    println!("  Fingerprint: {}", identity.fingerprint().to_display());
    println!();
    println!("  Encrypted identity written to {}", ctx.identity_path.display());
    // Audit fix: mnemonic NOT printed to stdout. User must run `aegis identity reveal`.
    println!("  Run `aegis identity reveal` to view your mnemonic (required for recovery).");
    Ok(())
}

async fn show(ctx: &CliContext) -> Result<()> {
    let blob = ctx.read_identity_blob()?
        .ok_or_else(|| anyhow!("No identity found. Run `aegis identity create` first."))?;
    let passphrase = CliContext::prompt_passphrase()?;
    let identity = Identity::from_encrypted_blob(&blob, &passphrase)
        .map_err(|e| anyhow!("decrypt: {e}"))?;
    println!("Name:        {}", identity.display_name);
    println!("ID:          {}", identity.id);
    println!("Fingerprint: {}", identity.fingerprint().to_display());
    Ok(())
}

async fn reveal(ctx: &CliContext) -> Result<()> {
    let blob = ctx.read_identity_blob()?
        .ok_or_else(|| anyhow!("No identity found."))?;
    let passphrase = CliContext::prompt_passphrase()?;
    let identity = Identity::from_encrypted_blob(&blob, &passphrase)
        .map_err(|e| anyhow!("decrypt: {e}"))?;
    // Print to stderr (not stdout) so it's not captured by pipes.
    eprintln!("Mnemonic: {}", identity.mnemonic());
    eprintln!("Save this in a secure offline location. Press Enter to clear.");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

async fn import(ctx: &CliContext, args: ImportArgs) -> Result<()> {
    let passphrase = CliContext::prompt_passphrase()?;
    if passphrase.len() < 8 {
        return Err(anyhow!("Passphrase must be at least 8 characters."));
    }
    let mnemonic = rpassword::prompt_password("BIP39 mnemonic: ")?;
    let identity = Identity::from_mnemonic(&args.name, &mnemonic)
        .map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
    let blob = identity.to_encrypted_blob(&passphrase)
        .map_err(|e| anyhow!("encrypt: {e}"))?;
    ctx.write_identity_blob(&blob)?;
    println!("Identity imported.");
    println!("  ID:          {}", identity.id);
    println!("  Fingerprint: {}", identity.fingerprint().to_display());
    Ok(())
}
