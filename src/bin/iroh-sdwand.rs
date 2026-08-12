use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use iroh_sdwan::{control::DEFAULT_CONTROL_SOCKET, daemon, logging};

#[derive(Debug, Parser)]
#[command(
    name = "iroh-sdwand",
    version,
    about = "Privileged iroh-sdwan data-plane daemon"
)]
struct Cli {
    /// Configuration file. May also be set with IROH_SDWAN_CONFIG.
    #[arg(
        short = 'c',
        long,
        env = "IROH_SDWAN_CONFIG",
        default_value = "/etc/iroh-sdwan/config.toml"
    )]
    config: PathBuf,
    /// Versioned JSONL control socket. May also be set with IROH_SDWAN_SOCKET.
    #[arg(
        long,
        env = "IROH_SDWAN_SOCKET",
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
