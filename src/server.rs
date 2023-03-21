use anyhow::{anyhow, Result};
use byteorder::ByteOrder;

pub async fn server(
    listen: String,
    auto_generate: String,
    cert: String,
    key: String,
    root_cert: String,
    root_key: String,
    client_cert: String,
    client_key: String,
    no_client_auth: bool,
    conn_timeout: u64,
    target_whitelist: String,
) -> Result<()> {
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
    let key = match key.into_iter().next() {
        Some(x) => rustls::PrivateKey(x),
        None => {
            return Err(anyhow!("no keys found"));
        }
    };

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

    info!("listening on {}", listen);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
    tokio::spawn(async move {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        let mut sigint =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
        loop {
            tokio::select! {
                _ = sigterm.recv() => println!("Recieve SIGTERM"),
                _ = sigint.recv() => println!("Recieve SIGTERM"),
            };
            stop_tx.send(()).unwrap();
        }
    });

    loop {
        let mut clone = stop_rx.clone();
        tokio::select! {
            Some(conn) = endpoint.accept() => {
                debug!("connection incoming");
                let conn = match conn.await {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(anyhow!("failed to accept connection: {}", e));
                    }
                };
                let stop_rx_clone = stop_rx.clone();
                let target_whitelist_clone = target_whitelist.clone();
                let (on_err_tx, mut on_err_rx) = tokio::sync::mpsc::channel(1);
                tokio::spawn(async move {
                    tokio::select! {
                        e = on_err_rx.recv() => {
                            let str = format!("{}", e.unwrap());
                            debug!("on_err_rx: {}", str);
                            conn.close(quinn::VarInt::from_u32(1u32), str.as_bytes());
                        }
                        v = handle_connection(target_whitelist_clone ,&conn, stop_rx_clone.clone(), on_err_tx.clone()) => {
                            match v {
                                Ok(_) => {
                                    conn.close(quinn::VarInt::from_u32(0u32), b"");
                                }
                                Err(e) => {
                                    conn.close(quinn::VarInt::from_u32(1u32), format!("{}", e).as_bytes());
                                }
                            }
                        }
                    }
                });
            }
            _ = clone.changed() => {
                endpoint.wait_idle().await;
                break;
            }
        }
    }

    return Ok(());
}

type Streams = std::sync::Arc<
    tokio::sync::RwLock<std::collections::HashMap<u64, (quinn::RecvStream, quinn::SendStream)>>,
>;

async fn handle_connection(
    target_whitelist: String,
    conn: &quinn::Connection,
    stop_rx: tokio::sync::watch::Receiver<()>,
    on_err_tx: tokio::sync::mpsc::Sender<anyhow::Error>,
) -> Result<()> {
    info!("connection established: {:?}", conn.remote_address());
    let streams = std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    let mut stop_rx_clone = stop_rx.clone();
    loop {
        tokio::select! {
            _ = stop_rx_clone.changed() => {
                break;
            }
            stream = conn.accept_bi() => {
                let (write, read) = match stream {
                    Err(e) => {
                        return Err(e.into());
                    }
                    Ok(s) => s,
                };
                debug!("stream incoming: {:?}", read.id());
                match read.id() {
                    quinn::StreamId(0) => {
                        let stream_clone =streams.clone();
                        let stop_rx_clone = stop_rx.clone();
                        let on_err_tx_clone = on_err_tx.clone();
                        let target_whitelist_clone = target_whitelist.clone();
                        let conn_clone = conn.clone();
                        tokio::spawn(async move {
                            match handle_ctrl_stream(target_whitelist_clone, &conn_clone,read, write, stream_clone, stop_rx_clone, on_err_tx_clone.clone()).await {
                                Ok(_) => {},
                                Err(e) => {
                                    let _ = on_err_tx_clone.try_send(e);
                                }
                            }
                        });
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

    return Ok(());
}

async fn handle_ctrl_stream(
    target_whitelist: String,
    conn: &quinn::Connection,
    mut read: quinn::RecvStream,
    _write: quinn::SendStream,
    streams: Streams,
    stop_rx: tokio::sync::watch::Receiver<()>,
    on_err_tx: tokio::sync::mpsc::Sender<anyhow::Error>,
) -> Result<()> {
    let mut buf = [0u8; crate::MAX_DATAGRAM_SIZE];
    let mut read_remain = Vec::new();

    let mut stop_rx_clone = stop_rx.clone();
    loop {
        tokio::select! {
            _ = stop_rx_clone.changed() => {
                break;
            }
            r = read.read(&mut buf) => {
                match r {
                    Err(e) => {
                        return Err(anyhow!("failed to read from ctrl stream: {}", e));
                    }
                    Ok(None) => {
                        break;
                    }
                    Ok(Some(v)) => {
                        read_remain.extend_from_slice(&buf[..v]);
                        loop {
                            if 0 == read_remain.len() {
                                break;
                            }
                            if 3 > read_remain.len() {
                                break;
                            }
                            let command = read_remain[0];
                            let length = byteorder::BigEndian::read_u16(&read_remain[1..3]) as usize;
                            if 3 + length > read_remain.len() {
                                break;
                            }
                            let payload = &read_remain[3..3 + length];

                            handle_command(conn,target_whitelist.clone(), command, payload, streams.clone(), stop_rx.clone(), on_err_tx.clone()).await?;

                            read_remain.drain(..3 + length);
                        }
                    }
                }
            }
        }
    }

    return Ok(());
}

async fn handle_command(
    conn: &quinn::Connection,
    target_whitelist: String,
    command: u8,
    payload: &[u8],
    streams: Streams,
    mut stop_rx: tokio::sync::watch::Receiver<()>,
    on_err_tx: tokio::sync::mpsc::Sender<anyhow::Error>,
) -> Result<()> {
    match command {
        0x00 => {
            return Ok(());
        }
        0x01 => {
            if 8 > payload.len() {
                return Err(anyhow!("invalid payload length"));
            }
            let stream_id = byteorder::BigEndian::read_u64(payload[0..8].as_ref());
            debug!("open stream: {}", stream_id);
            let target = std::str::from_utf8(&payload[8..])?;
            debug!("target: {}", target);
            if !regex::Regex::new(&target_whitelist)?.is_match(target) {
                return Err(anyhow!("target not allowed: {}", target));
            }

            let tcp_stream = tokio::net::TcpStream::connect(target).await?;
            let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);
            let conn_clone = conn.clone();
            tokio::spawn(async move {
                let mut streams = streams.write().await;
                let (quic_read, quic_write) = match streams.get_mut(&stream_id) {
                    Some((r, w)) => (r, w),
                    None => {
                        let _ = on_err_tx.try_send(anyhow!("stream not found: {}", stream_id));
                        return;
                    }
                };

                match crate::util::pipe_stream_tcp(
                    &conn_clone,
                    quic_read,
                    quic_write,
                    &mut tcp_read,
                    &mut tcp_write,
                    &mut stop_rx,
                    on_err_tx.clone(),
                )
                .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        let _ = on_err_tx.try_send(e);
                    }
                };
            });

            return Ok(());
        }
        _ => {
            return Err(anyhow!("unknown command"));
        }
    }
}
