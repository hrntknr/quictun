use async_std::io::{ReadExt, WriteExt};
use byteorder::ByteOrder;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct SkipServerVerification;
impl SkipServerVerification {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self)
    }
}
impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

pub async fn client(
    client_cert: String,
    client_key: String,
    no_client_auth: bool,
    keep_alive: u64,
    conn_timeout: u64,
    endpoint: String,
    target: String,
) -> Result<()> {
    info!("client: endpoint: {}, target: {}", endpoint, target);

    let endpoint = url::Url::parse(&endpoint)?;
    if endpoint.scheme() != "quic" {
        return Err("invalid scheme, expected quic://".into());
    }

    let peer_addr = match std::net::ToSocketAddrs::to_socket_addrs(&format!(
        "{}:{}",
        endpoint.host_str().unwrap(),
        endpoint.port().unwrap()
    ))
    .unwrap()
    .next()
    {
        Some(v) => v,
        None => {
            return Err("failed to resolve peer address".into());
        }
    };
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };
    let mut qe = quinn::Endpoint::client(bind_addr.parse()?)?;

    let mut client_config = match no_client_auth {
        true => rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth(),
        false => {
            let client_cert = async_std::fs::read(client_cert).await?;
            let client_cert = rustls_pemfile::certs(&mut &*client_cert)
                .expect("invalid PEM-encoded root certificate");
            let client_cert = client_cert.into_iter().map(rustls::Certificate).collect();
            let client_key = async_std::fs::read(client_key).await?;
            let client_key = rustls_pemfile::pkcs8_private_keys(&mut &*client_key)
                .expect("invalid PEM-encoded root private key");
            let client_key = match client_key.into_iter().next() {
                Some(x) => rustls::PrivateKey(x),
                None => {
                    return Err("no keys found".into());
                }
            };

            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(SkipServerVerification::new())
                // .with_no_client_auth()
                .with_single_cert(client_cert, client_key)?
        }
    };
    client_config.alpn_protocols = vec![b"quic/v1".to_vec()];

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(conn_timeout).try_into()?,
    ));

    let mut quinn_client_config = quinn::ClientConfig::new(std::sync::Arc::new(client_config));
    quinn_client_config.transport_config(std::sync::Arc::new(transport_config));
    qe.set_default_client_config(quinn_client_config);

    let conn = match qe.connect(peer_addr, endpoint.domain().unwrap())?.await {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("failed to connect: {}", e).into());
        }
    };
    let (send, recv) = match conn.open_bi().await {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("failed to open stream: {}", e).into());
        }
    };

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

    handle_stream(conn, send, recv, target, keep_alive, stop_rx).await?;
    qe.wait_idle().await;

    return Ok(());
}

async fn handle_stream(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    target: String,
    keep_alive: u64,
    mut stop_rx: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let mut out: Vec<u8> = Vec::new();
    let target_buf = target.as_bytes();
    out.extend_from_slice(&[0x01]);
    let mut len = [0u8; 2];
    byteorder::BigEndian::write_u16(&mut len, target_buf.len() as u16);
    out.extend_from_slice(&len);
    out.extend_from_slice(target_buf);
    send.write_all(&out).await?;

    let mut code = 0u32;
    let mut reason = Vec::new();
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(keep_alive));
    debug!("client: keepalive: {:?}", keep_alive);
    debug!("client: interval: {:?}", interval);
    let mut buf = [0u8; crate::MAX_DATAGRAM_SIZE];
    let mut stdbuf = [0u8; crate::MAX_DATAGRAM_SIZE];
    let mut stdin = async_std::io::stdin();
    let mut read_remain = Vec::new();
    loop {
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
                debug!("client: stop_rx changed");
                break;
            }
            _ = interval.tick() => {
                debug!("client: interval tick");
                match send.write_all(&[0x00,0x00,0x00]).await {
                    Ok(v) => {
                        debug!("client: send: {:?}", v);
                    }
                    Err(e) => {
                        error!("client: send error: {}", e);
                        code = 1;
                        reason = b"keep alive failed".to_vec();
                        break;
                    }
                }
            }
            v = recv.read(&mut buf) => {
                debug!("client: recv: {:?}", v);
                let v = match v {
                    Ok(v) => {
                        if v.is_none() {
                            continue;
                        }
                        v.unwrap()
                    }
                    Err(e) => {
                        debug!("client: recv error: {:?}", e);
                        continue;
                    }
                };
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
                    handle_command(command, payload).await?;
                    read_remain.drain(..3 + length);
                }
            }
            v = stdin.read(&mut stdbuf) => {
                debug!("client: stdin: {:?}", v);
                match v {
                    Ok(v) => {
                        let mut vec = Vec::new();
                        vec.extend_from_slice(&[0x02]);
                        let mut len = [0u8; 2];
                        byteorder::BigEndian::write_u16(&mut len, v as u16);
                        vec.extend_from_slice(&len);
                        vec.extend_from_slice(&stdbuf[..v]);
                        send.write_all(&vec).await?;
                    }
                    Err(e) => {
                        error!("client: stdin error: {}", e);
                        code = 1;
                        reason = b"stdin failed".to_vec();
                        break;
                    }
                }
            }
        }
    }
    debug!("closing connection");
    conn.close(quinn::VarInt::from_u32(code), &reason);
    return Ok(());
}

async fn handle_command(command: u8, payload: &[u8]) -> Result<()> {
    match command {
        0x02 => {
            async_std::io::stdout().write_all(payload).await?;
            async_std::io::stdout().flush().await?;
            return Ok(());
        }
        _ => {
            return Ok(());
        }
    }
}
