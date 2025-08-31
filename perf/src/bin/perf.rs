use clap::{Parser, Subcommand};
use tracing::error;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use perf::{client, server};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opt = Cli::parse();

    let registry = tracing_subscriber::registry();
    #[cfg(feature = "tokio-console")]
    let registry = registry.with(console_subscriber::spawn());
    registry
        .with(
            fmt::layer().with_filter(
                EnvFilter::try_from_default_env()
                    .or_else(|_| EnvFilter::try_new("warn"))
                    .unwrap(),
            ),
        )
        .init();

    let r = match opt.command {
        Commands::Server(opt) => server::run(opt).await,
        Commands::Client(opt) => client::run(opt).await,
    };
    if let Err(e) = r {
        error!("{:#}", e);
    }
}

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
