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
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(10).try_into()?));

    let mut quinn_server_config =
        quinn::ServerConfig::with_crypto(std::sync::Arc::new(server_config));
    quinn_server_config.transport_config(std::sync::Arc::new(transport_config));
    let endpoint = quinn::Endpoint::server(quinn_server_config, listen.parse()?)?;

    info!("listening on {}", listen);

    while let Some(conn) = endpoint.accept().await {
        info!("connection incoming");
        let fut = handle_connection(conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }

    return Ok(());
}

async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
    let quic_conn = match conn.await {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("failed to connect: {}", e).into());
        }
    };
    debug!("connection established: {:?}", quic_conn.remote_address());
    loop {
        let stream = quic_conn.accept_bi().await;
        let stream = match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("connection closed");
                return Ok(());
            }
            Err(e) => {
                return Err(e.into());
            }
            Ok(s) => s,
        };
        handle_request(stream).await?;
    }
}

async fn handle_request(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let mut buf = [0; crate::MAX_DATAGRAM_SIZE];
    loop {
        match recv.read(&mut buf).await {
            Ok(v) => {
                debug!("client: recv: {:?}", v);
            }
            Err(e) => {
                error!("client: recv: {}", e);
                break;
            }
        }
    }
    return Ok(());
}
