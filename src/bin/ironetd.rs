use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use ironet::{control::DEFAULT_CONTROL_SOCKET, daemon, logging};

#[derive(Debug, Parser)]
#[command(
    name = "ironetd",
    version,
    about = "Run the ironet network daemon",
    long_about = "Run the ironet network daemon in the foreground.\n\nThe daemon loads a validated configuration, creates the configured network interface and routes, maintains peer connections, and serves runtime commands through a Unix control socket. It is normally started by the system service.",
    after_help = "Example:\n  ironetd --config /etc/ironet/config.toml --socket /run/ironet/control.sock"
)]
struct Cli {
    /// Path to the validated daemon configuration file.
    #[arg(
        short = 'c',
        long,
        env = "IRONET_CONFIG",
        default_value = "/etc/ironet/config.toml"
    )]
    config: PathBuf,
    /// Path to the Unix control socket used by `ironet` runtime commands.
    #[arg(
        long,
        env = "IRONET_SOCKET",
        default_value = DEFAULT_CONTROL_SOCKET
    )]
    socket: PathBuf,
    /// Suppress informational logs.
    #[arg(short, long)]
    quiet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    logging::init(cli.quiet);
    daemon::run(cli.config, cli.socket).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_explains_daemon_responsibilities_and_arguments() {
        let mut command = Cli::command();
        for argument in command.get_arguments() {
            assert!(argument.get_help().is_some());
        }
        let help = command.render_long_help().to_string();
        for required in [
            "creates the configured network interface and routes",
            "maintains peer connections",
            "Unix control socket",
            "normally started by the system service",
        ] {
            assert!(
                help.contains(required),
                "daemon help is missing {required:?}"
            );
        }
    }
}
