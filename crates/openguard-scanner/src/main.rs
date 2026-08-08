#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use openguard_detection::FileScanner;
use std::{path::PathBuf, sync::atomic::AtomicBool};

#[derive(Debug, Parser)]
#[command(
    name = "OpenGuardScanner",
    version,
    about = "Standalone OpenGuard native scan worker"
)]
struct Arguments {
    target: PathBuf,
    #[arg(long, default_value_t = 8 * 1024 * 1024 * 1024_u64)]
    maximum_bytes: u64,
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let scanner = FileScanner::new()?.with_maximum_bytes(arguments.maximum_bytes);
    let finding = scanner.scan_file(arguments.target, &AtomicBool::new(false))?;
    println!("{}", serde_json::to_string_pretty(&finding)?);
    Ok(())
}
