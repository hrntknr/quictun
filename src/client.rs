use crate::PortAddress;
use anyhow::{anyhow, Result};
use byteorder::ByteOrder;
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
    mode: crate::Mode,
) -> Result<()> {
    info!("client: endpoint: {}, target: {}", endpoint, target);

    let endpoint = url::Url::parse(&endpoint)?;
    if endpoint.scheme() != "quic" {
        return Err(anyhow!("Length must be less than 10"));
    }

    let peer_addr = match std::net::ToSocketAddrs::to_socket_addrs(&format!(
        "{}:{}",
        endpoint.host_str().unwrap(),
        endpoint.port().unwrap()
    ))?
    .next()
    {
        Some(v) => v,
        None => {
            return Err(anyhow!("failed to resolve peer address"));
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
            let client_cert = rustls_pemfile::certs(&mut &*client_cert)?;
            let client_cert = client_cert.into_iter().map(rustls::Certificate).collect();
            let client_key = async_std::fs::read(client_key).await?;
            let client_key = rustls_pemfile::pkcs8_private_keys(&mut &*client_key)?;
            let client_key = match client_key.into_iter().next() {
                Some(x) => rustls::PrivateKey(x),
                None => {
                    return Err(anyhow!("no keys found"));
                }
            };
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(SkipServerVerification::new())
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
            return Err(anyhow!("failed to connect: {}", e));
        }
    };
    let (write, read) = match conn.open_bi().await {
        Ok(v) => v,
        Err(e) => {
            return Err(anyhow!("failed to open stream: {}", e));
        }
    };
    debug!("ctrl stream opened: {}", read.id().index());

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

    match mode {
        crate::Mode::Client => {
            handle_stream_client(&conn, read, write, target, keep_alive, stop_rx).await?
        }
        crate::Mode::NC => {
            handle_stream_nc(&conn, read, write, target, keep_alive, stop_rx).await?
        }
    };

    qe.wait_idle().await;

    return Ok(());
}

async fn handle_stream_nc(
    conn: &quinn::Connection,
    _ctrl_read: quinn::RecvStream,
    mut ctrl_write: quinn::SendStream,
    target: String,
    keep_alive: u64,
    mut stop_rx: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let (mut data_write, mut data_read) = conn.open_bi().await?;
    data_write.write(b"").await?;

    let stream_id = data_read.id().index();
    debug!("data stream opened: {}", stream_id);

    let conn_clone = conn.clone();

    debug!("start stream: {}", stream_id);
    let mut out: Vec<u8> = Vec::new();
    let target_buf = target.as_bytes();
    out.extend_from_slice(&[0x01]);
    let mut len = [0u8; 2];
    byteorder::BigEndian::write_u16(&mut len, target_buf.len() as u16 + 8);
    out.extend_from_slice(&len);
    let mut stream_id_buf = [0u8; 8];
    byteorder::BigEndian::write_u64(&mut stream_id_buf, stream_id);
    out.extend_from_slice(&stream_id_buf);
    out.extend_from_slice(target_buf);
    ctrl_write.write_all(&out).await.unwrap();

    let mut code = 0u32;
    let mut reason = Vec::new();
    let mut stdin = async_std::io::stdin();
    let mut stdout = async_std::io::stdout();
    let (on_err_tx, mut on_err_rx) = tokio::sync::mpsc::channel(1);
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(keep_alive));
    loop {
        tokio::select! {
            _ = on_err_rx.recv() => {
                code = 1;
                reason = b"on_err".to_vec();
                break;
            }
            v = crate::util::pipe_stream_std(
                &conn_clone,
                &mut data_read,
                &mut data_write,
                &mut stdin,
                &mut stdout,
                &mut stop_rx,
                on_err_tx.clone(),
            ) => {
                debug!("pipe_stream_std: {:?}", v);
                match v {
                    Ok(_) => {
                        break;
                    }
                    Err(e) => {
                        code = 1;
                        reason = e.to_string().into_bytes();
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                debug!("client: interval tick");
                match ctrl_write.write_all(&[0x00,0x00,0x00]).await {
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
        }
    }

    debug!("closing connection");
    conn.close(quinn::VarInt::from_u32(code), &reason);
    return Ok(());
}

async fn handle_stream_client(
    conn: &quinn::Connection,
    mut ctrl_read: quinn::RecvStream,
    mut ctrl_write: quinn::SendStream,
    target: String,
    keep_alive: u64,
    stop_rx: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let target: PortAddress = match target.parse() {
        Ok(v) => v,
        Err(e) => {
            return Err(anyhow!("failed to parse target: {:?}", e));
        }
    };

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(keep_alive));
    let listener = tokio::net::TcpListener::bind(format!("[::1]:{}", target.port)).await?;
    let mut stop_rx_clone = stop_rx.clone();
    let (on_err_tx, mut on_err_rx) = tokio::sync::mpsc::channel(1);
    loop {
        tokio::select! {
            _ = conn.closed() => {
                debug!("conn closed");
                break;
            }
            e = on_err_rx.recv() => {
                let str = format!("{}", e.unwrap());
                debug!("on_err_rx: {}", str);
                break;
            }
            _ = stop_rx_clone.changed() => {
                debug!("stop_rx changed");
                break;
            }
            _ = interval.tick() => {
                debug!("client: interval tick");
                match ctrl_write.write_all(&[0x00,0x00,0x00]).await {
                    Ok(v) => {
                        debug!("client: send: {:?}", v);
                    }
                    Err(e) => {
                        error!("client: send error: {}", e);
                        break;
                    }
                }
            }
            v = listener.accept() => {
                match v {
                    Ok((stream, _)) => {
                        debug!("accept");
                        let (mut read, mut write) = tokio::io::split(stream);
                        handle_stream_client_accept(&conn, &mut ctrl_read, &mut ctrl_write, &mut read, &mut write, target.address.clone(), stop_rx.clone(), on_err_tx.clone()).await?;
                    }
                    Err(e) => {
                        error!("accept error: {}", e);
                    }
                }
            }
        }
    }
    return Ok(());
}

async fn handle_stream_client_accept(
    conn: &quinn::Connection,
    _ctrl_read: &mut quinn::RecvStream,
    ctrl_write: &mut quinn::SendStream,
    tcp_read: &mut tokio::io::ReadHalf<tokio::net::TcpStream>,
    tcp_write: &mut tokio::io::WriteHalf<tokio::net::TcpStream>,
    target: String,
    mut stop_rx: tokio::sync::watch::Receiver<()>,
    on_err_tx: tokio::sync::mpsc::Sender<anyhow::Error>,
) -> Result<()> {
    let (mut data_write, mut data_read) = conn.open_bi().await?;
    data_write.write(b"").await?;

    let stream_id = data_read.id().index();
    debug!("data stream opened: {}", stream_id);

    debug!("start stream: {}", stream_id);
    let mut out: Vec<u8> = Vec::new();
    let target_buf = target.as_bytes();
    out.extend_from_slice(&[0x01]);
    let mut len = [0u8; 2];
    byteorder::BigEndian::write_u16(&mut len, target_buf.len() as u16 + 8);
    out.extend_from_slice(&len);
    let mut stream_id_buf = [0u8; 8];
    byteorder::BigEndian::write_u64(&mut stream_id_buf, stream_id);
    out.extend_from_slice(&stream_id_buf);
    out.extend_from_slice(target_buf);
    ctrl_write.write_all(&out).await.unwrap();

    crate::util::pipe_stream_tcp(
        conn,
        &mut data_read,
        &mut data_write,
        tcp_read,
        tcp_write,
        &mut stop_rx,
        on_err_tx,
    )
    .await?;

    return Ok(());
}
