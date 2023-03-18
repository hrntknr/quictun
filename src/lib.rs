#[macro_use]
extern crate log;
extern crate env_logger;
pub enum Mode {
    NC,
}

const MAX_DATAGRAM_SIZE: usize = 0xffff;

mod client;
mod server;
mod util;

pub use client::client;
pub use server::server;
