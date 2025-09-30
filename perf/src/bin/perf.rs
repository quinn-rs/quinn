use clap::{Parser, Subcommand};
use tracing::error;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use perf::{client, server};

#[derive(Parser)]
#[clap(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a perf server
    Server(server::Opt),
    /// Run as a perf client
    Client(client::Opt),
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opt = Cli::parse();

    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("warn"))
                .unwrap(),
        )
        .with(fmt::layer())
        .init();

    let r = match opt.command {
        Commands::Server(opt) => server::run(opt).await,
        Commands::Client(opt) => client::run(opt).await,
    };
    if let Err(e) = r {
        error!("{:#}", e);
    }
}
