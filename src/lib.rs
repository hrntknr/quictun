#[macro_use]
extern crate log;
extern crate env_logger;

const MAX_DATAGRAM_SIZE: usize = 1350;

mod client;
mod server;

pub use client::client;
pub use server::server;
