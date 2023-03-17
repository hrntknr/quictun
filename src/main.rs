#[macro_use]
extern crate log;
extern crate env_logger;

use std::{process::exit, str::FromStr};

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Args {
    #[structopt(short, long, default_value = "10")]
    conn_timeout: u64,
    #[structopt(subcommand)]
    mode: Mode,
}

#[derive(StructOpt, Debug)]
enum Mode {
    Server {
        #[structopt(short, long, default_value = "[::0]:2222")]
        listen: String,
        #[structopt(short, long, default_value)]
        cert: Cert,
        #[structopt(short, long, default_value)]
        key: Key,
    },
    Client {
        #[structopt(short, long, default_value = "1")]
        keep_alive: u64,

        endpoint: String,
        target: String,
    },
}

#[derive(StructOpt, Clone, Debug)]
struct Cert {
    str: String,
}
impl Default for Cert {
    fn default() -> Self {
        let proj_dirs = directories::ProjectDirs::from("net", "hrntknr", "quictun");
        let proj_dirs = match proj_dirs {
            Some(d) => d,
            None => {
                panic!("failed to get project directories");
            }
        };
        Cert {
            str: String::from(proj_dirs.config_dir().join("server.crt").to_str().unwrap()),
        }
    }
}
impl FromStr for Cert {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Cert {
            str: String::from(s),
        })
    }
}
impl std::fmt::Display for Cert {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.str)
    }
}

#[derive(StructOpt, Clone, Debug)]
struct Key {
    str: String,
}
impl Default for Key {
    fn default() -> Self {
        let proj_dirs = directories::ProjectDirs::from("net", "hrntknr", "quictun");
        let proj_dirs = match proj_dirs {
            Some(d) => d,
            None => {
                panic!("failed to get project directories");
            }
        };
        Key {
            str: String::from(proj_dirs.config_dir().join("server.key").to_str().unwrap()),
        }
    }
}
impl FromStr for Key {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Key {
            str: String::from(s),
        })
    }
}
impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.str)
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::from_args();
    match args.mode {
        Mode::Client {
            keep_alive,
            endpoint,
            target,
        } => match quictun::client(args.conn_timeout, keep_alive, endpoint, target).await {
            Ok(_) => {}
            Err(e) => {
                error!("client: {}", e);
                exit(1);
            }
        },
        Mode::Server { listen, cert, key } => {
            match quictun::server(args.conn_timeout, listen, cert.str, key.str).await {
                Ok(_) => {}
                Err(e) => {
                    error!("server: {}", e);
                    exit(1);
                }
            }
        }
    }
}
