#[macro_use]
extern crate log;
extern crate env_logger;
pub enum Mode {
    SSH,
}

const MAX_DATAGRAM_SIZE: usize = 0xffff;

mod client;
mod server;

pub use client::client;
pub use server::server;
