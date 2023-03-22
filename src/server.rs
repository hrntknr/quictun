use anyhow::{anyhow, Result};

pub async fn server(
    listen: &String,
    auto_generate: &String,
    cert: &String,
    key: &String,
    root_cert: &String,
    root_key: &String,
    client_cert: &String,
    client_key: &String,
    no_client_auth: bool,
    conn_timeout: u64,
    target_whitelist: &String,
) -> Result<()> {
    let endpoint = server_init(
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
    )
    .await?;
    info!("listening on {}", listen);

    let stop = crate::util::handle_signal();
    let mut set = tokio::task::JoinSet::new();
    loop {
        let mut stop = stop.clone();
        tokio::select! {
            Some(conn) = endpoint.accept() => {
                debug!("connection incoming");
                let conn = match conn.await {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(anyhow!("failed to accept connection: {}", e));
                    }
                };
                let target_whitelist = target_whitelist.clone();
                let fut = async move {
                    return handle_connection(&target_whitelist, &conn, stop.clone()).await;
                };
                set.spawn(fut);
            }
            _ = stop.changed() => {
                endpoint.wait_idle().await;
                break;
            }
            Some(res) = set.join_next() => {
                match res.unwrap() {
                    Ok(_) => {
                        debug!("handle_connection closed");
                    }
                    Err(e) => {
                        return Err(anyhow!("failed to handle connection: {}", e));
                    }
                }
            }
        }
    }

    while let Some(res) = set.join_next().await {
        match res.unwrap() {
            Ok(_) => {}
            Err(e) => {
                return Err(anyhow!("failed to handle connection: {}", e));
            }
        }
    }

    return Ok(());
}

async fn server_init(
    listen: &String,
    auto_generate: &String,
    cert: &String,
    key: &String,
    root_cert: &String,
    root_key: &String,
    client_cert: &String,
    client_key: &String,
    no_client_auth: bool,
    conn_timeout: u64,
) -> Result<quinn::Endpoint> {
    if auto_generate != "" {
        match crate::util::generate(
            no_client_auth,
            &auto_generate,
            &cert,
            &key,
            &root_cert,
            &root_key,
            &client_cert,
            &client_key,
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                return Err(anyhow!("failed to generate cert: {}", e));
            }
        };
    }
    if !async_std::path::Path::new(&cert).exists().await {
        return Err(anyhow!("cert file not found"));
    }
    if !async_std::path::Path::new(&key).exists().await {
        return Err(anyhow!("key file not found"));
    }
    let key = async_std::fs::read(key).await?;
    let key =
        rustls_pemfile::pkcs8_private_keys(&mut &*key).expect("malformed PKCS #8 private key");
    let key = rustls::PrivateKey(match key.into_iter().next() {
        Some(x) => x,
        None => {
            return Err(anyhow!("no keys found"));
        }
    });

    let cert = async_std::fs::read(cert).await?;
    let cert = rustls_pemfile::certs(&mut &*cert).expect("invalid PEM-encoded certificate");
    let cert = cert.into_iter().map(rustls::Certificate).collect();

    let mut server_config = match no_client_auth {
        true => rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert, key)?,
        false => {
            let root_cert = async_std::fs::read(root_cert).await?;
            let root_cert = rustls_pemfile::certs(&mut &*root_cert)
                .expect("invalid PEM-encoded root certificate");

            let mut roots = rustls::RootCertStore::empty();
            for data in root_cert.into_iter() {
                roots.add(&rustls::Certificate(data))?;
            }
            rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_client_cert_verifier(rustls::server::AllowAnyAuthenticatedClient::new(roots))
                .with_single_cert(cert, key)?
        }
    };
    server_config.alpn_protocols = vec![b"quic/v1".to_vec()];

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(conn_timeout).try_into()?,
    ));

    let mut quinn_server_config =
        quinn::ServerConfig::with_crypto(std::sync::Arc::new(server_config));
    quinn_server_config.transport_config(std::sync::Arc::new(transport_config));
    let endpoint = quinn::Endpoint::server(quinn_server_config, listen.parse()?)?;

    return Ok(endpoint);
}

type Streams = std::sync::Arc<
    tokio::sync::RwLock<std::collections::HashMap<u64, (quinn::RecvStream, quinn::SendStream)>>,
>;
async fn handle_connection(
    target_whitelist: &String,
    conn: &quinn::Connection,
    stop: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    info!("{}: connection established", conn.remote_address());
    let streams: Streams =
        std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    let mut stop = stop.clone();
    let mut set = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = conn.closed() => {
                break;
            }
            _ = stop.changed() => {
                break;
            }
            stream = conn.accept_bi() => {
                let (mut write, mut read) = match stream {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("failed to accept stream: {}", e);
                        break;
                    }
                };
                debug!("accepted quic stream: {}", read.id().index());

                match read.id().index() {
                    0 => {
                        let target_whitelist = target_whitelist.clone();
                        let conn_clone = conn.clone();
                        let streams = streams.clone();
                        let stop = stop.clone();
                        let fut = async move {
                            return handle_ctrl_stream(
                                &target_whitelist,
                                &conn_clone,
                                &mut read,
                                &mut write,
                                &streams,
                                stop.clone()
                            ).await
                        };
                        set.spawn(fut);
                    }
                    _ => {
                        let index = read.id().index();
                        let mut streams = streams.write().await;
                        streams.insert(index, (read, write));
                        debug!("new stream: {}", index);
                    }
                }
            }
        }
    }

    while let Some(res) = set.join_next().await {
        match res.unwrap() {
            Ok(_) => {}
            Err(e) => {
                return Err(anyhow!("failed to handle connection: {}", e));
            }
        }
    }

    info!("{}: connection closed", conn.remote_address());
    return Ok(());
}

async fn handle_ctrl_stream(
    target_whitelist: &String,
    conn: &quinn::Connection,
    ctrl_read: &mut quinn::RecvStream,
    _ctrl_write: &mut quinn::SendStream,
    streams: &Streams,
    stop: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let mut buf = [0u8; crate::MAX_DATAGRAM_SIZE];
    let mut read_remain = Vec::new();

    let mut stop = stop.clone();
    let mut set = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = conn.closed() => {
                break;
            }
            _ = stop.changed() => {
                break;
            }
            r = ctrl_read.read(&mut buf) => {
                let v = match r {
                    Err(e) => {
                        debug!("failed to read from ctrl stream: {}", e);
                        break;
                    }
                    Ok(None) => {
                        break;
                    }
                    Ok(Some(v)) => v,
                };
                read_remain.extend_from_slice(&buf[..v]);
                loop {
                    let (parsed, n) = match crate::util::parse_pkt_ctrl_cmd(&read_remain) {
                        Ok(v) => v,
                        Err(_) => {
                            break;
                        }
                    };
                    let conn = conn.clone();
                    let target_whitelist = target_whitelist.clone();
                    let streams = streams.clone();
                    let stop = stop.clone();
                    debug!("new command: {:?}", parsed);
                    let fut = async move {
                        let res = crate::util::no_error(
                            handle_command(
                                &conn,
                                &target_whitelist,
                                parsed.command,
                                parsed.stream_id,
                                &parsed.buf,
                                &streams,
                                stop
                            ).await
                        );
                        debug!("command finished: {:?}", res);
                        return res;
                    };
                    set.spawn(fut);
                    read_remain.drain(..n);
                }
            }
        }
    }

    while let Some(res) = set.join_next().await {
        match res.unwrap() {
            Ok(_) => {}
            Err(e) => {
                debug!("failed to handle command: {}", e);
                return Err(anyhow!("failed to handle command: {}", e));
            }
        }
    }

    return Ok(());
}

async fn handle_command(
    conn: &quinn::Connection,
    target_whitelist: &String,
    command: u8,
    stream_id: u64,
    payload: &[u8],
    streams: &Streams,
    stop: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    match command {
        0x00 => {
            return Ok(());
        }
        0x01 => {
            debug!("open stream: {}", stream_id);
            let target = std::str::from_utf8(&payload).unwrap();
            info!("{}: connect to {}", conn.remote_address(), target);
            if !regex::Regex::new(target_whitelist)?.is_match(target) {
                return Err(anyhow!("target not allowed: {}", target));
            }
            let mut streams = streams.write().await;
            let (quic_read, quic_write) = streams.get_mut(&stream_id).unwrap();
            let tcp_stream = match tokio::net::TcpStream::connect(target).await {
                Ok(s) => s,
                Err(e) => {
                    quic_write.finish().await?;
                    return Err(anyhow!("failed to connect to target: {}", e));
                }
            };
            let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);

            crate::util::pipe_stream_tcp(
                conn,
                quic_read,
                quic_write,
                &mut tcp_read,
                &mut tcp_write,
                stop,
            )
            .await?;

            info!("{}: disconnected from {}", conn.remote_address(), target);
            return Ok(());
        }
        _ => {
            return Err(anyhow!("unknown command"));
        }
    };
}
