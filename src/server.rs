type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub async fn server(conn_timeout: u64, listen: String, cert: String, key: String) -> Result<()> {
    let key = std::fs::read(key)?;
    let key =
        rustls_pemfile::pkcs8_private_keys(&mut &*key).expect("malformed PKCS #8 private key");
    let key = match key.into_iter().next() {
        Some(x) => rustls::PrivateKey(x),
        None => {
            return Err("no keys found".into());
        }
    };

    let cert = std::fs::read(cert)?;
    let cert = rustls_pemfile::certs(&mut &*cert).expect("invalid PEM-encoded certificate");
    let cert = cert.into_iter().map(rustls::Certificate).collect();

    let mut server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;
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
                let fut = handle_connection(conn, stop_rx.clone());
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
    conn: quinn::Connecting,
    mut stop_rx: tokio::sync::watch::Receiver<()>,
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
        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
            info!("connection closed");
            return Ok(());
        }
        Err(e) => {
            return Err(e.into());
        }
        Ok(s) => s,
    };
    if send.id().index() != 0 {
        return Err("expected ctrl stream".into());
    }
    debug!("ctrl stream established: {}", send.id().index());

    handle_stream(quic_conn, send, recv, stop_rx).await?;

    return Ok(());
}

async fn handle_stream(
    mut conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    mut stop_rx: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let mut buf = [0u8; crate::MAX_DATAGRAM_SIZE];
    let mut code = 0u32;
    let mut reason = Vec::new();

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                break;
            }
            v = recv.read(&mut buf) => {
                debug!("client: recv: {:?}", v);
                match v {
                    Ok(v) => {
                        if v.is_none() {
                            break;
                        }
                        if v.unwrap() < 1 {
                            continue;
                        }
                    }
                    Err(e) => {
                        error!("client: recv error: {}", e);
                        code = 1;
                        reason = b"recv failed".to_vec();
                        break;
                    }
                }
                let command = buf[0];
                handle_command(&conn, &send, &recv, command, &buf[1..]).await?;
            }
        };
    }

    debug!("closing connection");
    conn.close(quinn::VarInt::from_u32(code), &reason);
    return Ok(());
}

async fn handle_command(
    mut conn: &quinn::Connection,
    mut send: &quinn::SendStream,
    mut recv: &quinn::RecvStream,
    command: u8,
    payload: &[u8],
) -> Result<()> {
    match command {
        0x01 => {
            let target = std::str::from_utf8(payload)?;
            return Ok(());
        }
        _ => {
            return Ok(());
        }
    }
}
