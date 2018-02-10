extern crate failure;
extern crate quicr;
extern crate rustls;

use std::sync::Arc;

use failure::Error;

fn main() {
    run().unwrap();
}

fn run() -> Result<(), Error> {
    let endpoint = quicr::Endpoint::listen(Arc::new(rustls::ServerConfig::new(Arc::new(rustls::NoClientAuth))))?;
    Ok(())
}
