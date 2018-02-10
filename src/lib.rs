extern crate bytes;
extern crate byteorder;
extern crate rand;
extern crate rustls;
extern crate slab;
extern crate webpki;

mod varint;
mod endpoint;

pub use endpoint::Endpoint;

use varint::Varint;

