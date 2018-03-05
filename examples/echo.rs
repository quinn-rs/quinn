extern crate failure;
extern crate quicr;
#[macro_use]
extern crate slog;
extern crate slog_term;

use std::sync::Arc;

use failure::Error;
use slog::Drain;

fn main() {
    run().unwrap();
}

fn run() -> Result<(), Error> {
    let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let drain = slog_term::FullFormat::new(decorator).use_original_order().build().fuse();
    let log = slog::Logger::root(drain, o!());
    let endpoint = quicr::Endpoint::new(log, quicr::Config::default())?;
    Ok(())
}
