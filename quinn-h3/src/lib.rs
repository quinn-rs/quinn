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

#[derive(Clone)]
pub struct Settings {
    pub max_header_list_size: u64,
    pub num_placeholders: u64,
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_header_list_size: u64::max_value(),
            num_placeholders: 0,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
        }
    }
}
