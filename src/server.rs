use byteorder::ByteOrder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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
        crate::util::generate(
            no_client_auth,
            &auto_generate,
            &cert,
            &key,
            &root_cert,
            &root_key,
            &client_cert,
            &client_key,
        )
        .await?;
    }
    if !async_std::path::Path::new(&cert).exists().await {
        return Err("cert file not found".into());
    }
    if !async_std::path::Path::new(&key).exists().await {
        return Err("key file not found".into());
    }
    let key = async_std::fs::read(key).await?;
    let key =
        rustls_pemfile::pkcs8_private_keys(&mut &*key).expect("malformed PKCS #8 private key");
    let key = match key.into_iter().next() {
        Some(x) => rustls::PrivateKey(x),
        None => {
            return Err("no keys found".into());
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
                let fut = handle_connection(target_whitelist.clone() ,conn, stop_rx.clone());
                tokio::spawn(async move {
                    if let Err(e) = fut.await {
                        error!("connection failed: {reason}", reason = e.to_string())
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

async fn handle_connection(
    target_whitelist: String,
    conn: quinn::Connecting,
    stop_rx: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let quic_conn = match conn.await {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("failed to connect: {}", e).into());
        }
    };
    info!("connection established: {:?}", quic_conn.remote_address());

    debug!("waiting for ctrl stream");
    let stream = quic_conn.accept_bi().await;
    let (send, recv) = match stream {
        Err(e) => {
            return Err(e.into());
        }
        Ok(s) => s,
    };
    if send.id().index() != 0 {
        return Err("expected ctrl stream".into());
    }
    debug!("ctrl stream established: {}", send.id().index());

    handle_stream(target_whitelist, quic_conn, send, recv, stop_rx).await?;

    return Ok(());
}

async fn handle_stream(
    target_whitelist: String,
    conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    mut stop_rx: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let mut buf = [0u8; crate::MAX_DATAGRAM_SIZE];

    let mut recv_box = std::boxed::Box::new(recv);
    let send_lock = std::sync::Arc::new(tokio::sync::Mutex::new(send));
    let mut upstream_send: Option<tokio::io::WriteHalf<tokio::net::TcpStream>> = None;

    let (upstream_close_tx, mut upstream_close_rx) = tokio::sync::watch::channel(());
    let close_tx_lock = std::sync::Arc::new(tokio::sync::Mutex::new(upstream_close_tx));
    let mut read_remain = Vec::new();
    loop {
        let close_tx_lock = close_tx_lock.clone();
        let send_lock = send_lock.clone();
        tokio::select! {
            e = conn.closed() => {
                match e {
                    quinn::ConnectionError::ApplicationClosed { .. } => {
                        info!("connection closed");
                        break;
                    }
                    quinn::ConnectionError::ConnectionClosed { .. } => {
                        info!("connection closed");
                        break;
                    }
                    _ => {
                        warn!("connection closed: {:?}", e);
                        break;
                    }
                }
            }
            _ = stop_rx.changed() => {
                break;
            }
            _ = upstream_close_rx.changed() => {
                break;
            }
            v = recv_box.read(&mut buf) => {
                debug!("client: recv: {:?}", v);
                let v = match v {
                    Ok(v) => {v}
                    Err(e) => {
                        debug!("client: recv error: {:?}", e);
                        continue;
                    }
                };
                read_remain.extend_from_slice(&buf[..v]);
                loop {
                    let close_tx_lock = close_tx_lock.clone();
                    let send_lock = send_lock.clone();
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
                    let opt = handle_command(target_whitelist.clone(), &conn, command, payload, send_lock, &mut upstream_send, close_tx_lock).await?;
                    if opt.is_some() {
                        upstream_send = opt;
                    }
                    read_remain.drain(..3 + length);
                }
            }
        };
    }

    conn.close(quinn::VarInt::from_u32(0u32), &[]);
    info!("connection closed: {}", conn.remote_address());
    return Ok(());
}

async fn handle_command(
    target_whitelist: String,
    conn: &quinn::Connection,
    command: u8,
    payload: &[u8],
    send_lock: std::sync::Arc<tokio::sync::Mutex<quinn::SendStream>>,
    upstream_send: &mut Option<tokio::io::WriteHalf<tokio::net::TcpStream>>,
    close_tx_lock: std::sync::Arc<tokio::sync::Mutex<tokio::sync::watch::Sender<()>>>,
) -> Result<Option<tokio::io::WriteHalf<tokio::net::TcpStream>>> {
    match command {
        0x01 => {
            let target = std::str::from_utf8(payload)?.trim();
            info!("new request {} {}", target, conn.remote_address());
            if !regex::Regex::new(&target_whitelist)?.is_match(target) {
                info!("target not allowed: {} {}", target, conn.remote_address());
                return Err(format!("target not allowed: {}", target).into());
            }
            let stream = tokio::net::TcpStream::connect(target).await?;
            let (mut read_stream, write_stream) = tokio::io::split(stream);
            info!(
                "connection established upstream {} for {}",
                target,
                conn.remote_address()
            );
            tokio::spawn(async move {
                let mut buf = [0u8; crate::MAX_DATAGRAM_SIZE];
                loop {
                    let v = read_stream.read(&mut buf).await;
                    debug!("upstream: recv: {:?}", v);
                    let v = match v {
                        Ok(v) => v,
                        Err(e) => {
                            error!("upstream: recv error: {}", e);
                            break;
                        }
                    };
                    if v == 0 {
                        break;
                    }
                    {
                        let mut send_lock = send_lock.lock().await;
                        let mut vec = Vec::new();
                        vec.extend_from_slice(&[0x02]);
                        let mut len = [0u8; 2];
                        byteorder::BigEndian::write_u16(&mut len, v as u16);
                        vec.extend_from_slice(&len);
                        vec.extend_from_slice(&buf[..v]);
                        match send_lock.write_all(&vec).await {
                            Ok(_) => {}
                            Err(e) => {
                                error!("upstream: send error: {}", e);
                                break;
                            }
                        }
                    }
                }
                match close_tx_lock.lock().await.send(()) {
                    Ok(_) => {}
                    Err(_) => {}
                };
            });
            return Ok(Some(write_stream));
        }
        0x02 => {
            let upstream_send_mut = upstream_send;
            if !upstream_send_mut.is_none() {
                upstream_send_mut
                    .as_mut()
                    .unwrap()
                    .write_all(payload)
                    .await?;
            }
        }
        _ => {}
    }
    return Ok(None);
}
