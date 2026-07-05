//! `aegis wipe` — removes all files including WAL/shm (audit fix).

use crate::context::CliContext;
use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct WipeCmd {
    #[arg(long, short)]
    yes: bool,
}

impl WipeCmd {
    pub async fn run(self, ctx: CliContext) -> Result<()> {
        if !self.yes {
            println!("This will DESTROY all data in {}:", ctx.data_dir.display());
            print!("Type WIPE to confirm: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim() != "WIPE" {
                println!("Aborted.");
                return Ok(());
            }
        }
        // Audit fix: remove all files including WAL/shm sidecars.
        for entry in std::fs::read_dir(&ctx.data_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let _ = std::fs::remove_file(&path);
            }
        }
        println!("All data wiped.");
        Ok(())
    }
}
