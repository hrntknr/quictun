#[macro_use]
extern crate log;
extern crate env_logger;
pub enum Mode {
    NC,
    Client,
}

const MAX_DATAGRAM_SIZE: usize = 1025;

mod client;
mod server;
mod util;

pub use client::client;
pub use server::server;
pub use util::PortAddress;
