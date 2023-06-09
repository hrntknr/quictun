#[macro_use]
extern crate log;
extern crate env_logger;
mod config;

use structopt::StructOpt;

#[tokio::main]
async fn main() {
    let args = crate::config::Args::from_args();
    match args.mode {
        crate::config::Mode::NC {
            client_cert,
            client_key,
            no_client_auth,
            v6,
            v4,
            keep_alive,
            conn_timeout,
            endpoint,
            target,
        } => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("off"))
                .init();
            match quictun::client(
                &client_cert.str,
                &client_key.str,
                no_client_auth,
                v6,
                v4,
                keep_alive,
                conn_timeout,
                &endpoint,
                &target,
                quictun::Mode::NC,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    error!("client: {}", e);
                    std::process::exit(1);
                }
            }
        }
        crate::config::Mode::Client {
            client_cert,
            client_key,
            no_client_auth,
            v6,
            v4,
            keep_alive,
            conn_timeout,
            endpoint,
            target,
        } => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                .init();
            match quictun::client(
                &client_cert.str,
                &client_key.str,
                no_client_auth,
                v6,
                v4,
                keep_alive,
                conn_timeout,
                &endpoint,
                &target,
                quictun::Mode::Client,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    error!("client: {}", e);
                    std::process::exit(1);
                }
            }
        }
        crate::config::Mode::Server {
            listen,
            auto_generate,
            cert,
            key,
            root_cert,
            root_key,
            client_cert,
            client_key,
            no_client_auth,
            conn_timeout,
            target_whitelist,
        } => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                .init();
            match quictun::server(
                &listen,
                &auto_generate,
                &cert.str,
                &key.str,
                &root_cert.str,
                &root_key.str,
                &client_cert.str,
                &client_key.str,
                no_client_auth,
                conn_timeout,
                &target_whitelist,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    error!("server: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
