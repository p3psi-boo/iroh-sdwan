use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use ironet::{control::DEFAULT_CONTROL_SOCKET, daemon, logging};

#[derive(Debug, Parser)]
#[command(
    name = "ironetd",
    version,
    about = "Privileged ironet data-plane daemon"
)]
struct Cli {
    /// Configuration file. May also be set with IRONET_CONFIG.
    #[arg(
        short = 'c',
        long,
        env = "IRONET_CONFIG",
        default_value = "/etc/ironet/config.toml"
    )]
    config: PathBuf,
    /// Versioned JSONL control socket. May also be set with IRONET_SOCKET.
    #[arg(
        long,
        env = "IRONET_SOCKET",
        default_value = DEFAULT_CONTROL_SOCKET
    )]
    socket: PathBuf,
    /// Reduce operational logging.
    #[arg(short, long)]
    quiet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    logging::init(cli.quiet);
    daemon::run(cli.config, cli.socket).await
}
