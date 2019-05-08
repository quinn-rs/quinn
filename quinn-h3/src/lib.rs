#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[macro_use]
extern crate proptest;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

pub mod client;
pub mod connection;
mod frame;
pub mod proto;
pub mod qpack;
pub mod server;

#[derive(Clone, Default)]
pub struct Settings {
    pub max_header_list_size: u64,
    pub num_placeholders: u64,
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
}
