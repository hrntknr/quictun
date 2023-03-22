use anyhow::{anyhow, Result};
use std::str::FromStr;

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
    client_cert: &String,
    client_key: &String,
    no_client_auth: bool,
    keep_alive: u64,
    conn_timeout: u64,
    remote: &String,
    target: &String,
    mode: crate::Mode,
) -> Result<()> {
    info!("client: remote: {}, target: {}", remote, target);
    let (peer, host, endpoint) = client_init(
        client_cert,
        client_key,
        no_client_auth,
        conn_timeout,
        remote,
    )
    .await?;

    let conn = endpoint.connect(peer, &host)?.await?;
    let (write, read) = conn.open_bi().await?;
    debug!("ctrl stream opened: {}", read.id().index());

    let stop = crate::util::handle_signal();
    match mode {
        crate::Mode::Client => {
            handle_stream_client(&conn, read, write, target, keep_alive, stop).await?
        }
        crate::Mode::NC => handle_stream_nc(&conn, read, write, target, keep_alive, stop).await?,
    };

    endpoint.close(quinn::VarInt::from_u32(0), b"");
    tokio::time::sleep(std::time::Duration::from_secs(0)).await;

    return Ok(());
}

async fn client_init(
    client_cert: &String,
    client_key: &String,
    no_client_auth: bool,
    conn_timeout: u64,
    remote: &String,
) -> Result<(std::net::SocketAddr, String, quinn::Endpoint)> {
    let remote = url::Url::parse(&remote)?;
    if remote.scheme() != "quic" {
        return Err(anyhow!("invalid scheme"));
    }
    let host = match remote.host_str() {
        Some(v) => v,
        None => {
            return Err(anyhow!("failed to resolve host"));
        }
    };
    let port = match remote.port() {
        Some(v) => v,
        None => {
            return Err(anyhow!("failed to resolve port"));
        }
    };

    let peer_addr =
        match std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port))?.next() {
            Some(v) => v,
            None => {
                return Err(anyhow!("failed to resolve peer address"));
            }
        };
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr.parse()?)?;

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
            let client_key = rustls::PrivateKey(match client_key.into_iter().next() {
                Some(v) => v,
                None => {
                    return Err(anyhow!("failed to load private key"));
                }
            });
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
    endpoint.set_default_client_config(quinn_client_config);

    return Ok((peer_addr, host.to_string(), endpoint));
}

async fn handle_stream_nc(
    conn: &quinn::Connection,
    _ctrl_read: quinn::RecvStream,
    mut ctrl_write: quinn::SendStream,
    target: &String,
    keep_alive: u64,
    stop: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let (mut data_write, mut data_read) = conn.open_bi().await?;
    data_write.write(b"").await?;

    let stream_id = data_read.id().index();
    debug!("data stream opened: {}", stream_id);

    let conn_clone = conn.clone();
    let stop_clone = stop.clone();
    let mut handler = tokio::spawn(async move {
        return crate::util::pipe_stream_std(
            &conn_clone,
            &mut data_read,
            &mut data_write,
            &mut async_std::io::stdin(),
            &mut async_std::io::stdout(),
            stop_clone,
        )
        .await;
    });

    ctrl_write
        .write(&crate::util::create_pkt_ctrl_cmd(
            0x01,
            stream_id,
            target.as_bytes(),
        ))
        .await?;

    let keepalive = &[0u8; 11];
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(keep_alive));
    let mut stop = stop.clone();
    let mut handler_closed = false;
    loop {
        tokio::select! {
            _ = conn.closed() => {
                debug!("conn closed");
                break;
            }
            _ = stop.changed() => {
                debug!("stop changed");
                break;
            }
            _ = interval.tick() => {
                debug!("client: interval tick");
                match ctrl_write.write(keepalive).await {
                    Ok(v) => {
                        debug!("client: send: {:?}", v);
                    }
                    Err(e) => {
                        error!("client: send error: {}", e);
                        break;
                    }
                }
            }
            r = &mut handler => {
                r??;
                handler_closed = true;
                debug!("client: handler done");
                break;
            }
        }
    }

    if !handler_closed {
        handler.await??;
    }

    conn.close(quinn::VarInt::from_u32(0), b"");

    return Ok(());
}

async fn handle_stream_client(
    conn: &quinn::Connection,
    _ctrl_read: quinn::RecvStream,
    ctrl_write: quinn::SendStream,
    target: &String,
    keep_alive: u64,
    stop: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let target = crate::util::PortAddress::from_str(target).map_err(|e| anyhow!(e))?;

    let keepalive = &[0u8; 11];
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(keep_alive));
    let listener = tokio::net::TcpListener::bind(format!("[::1]:{}", target.port)).await?;
    let mut stop = stop.clone();
    let mut handlers = Vec::new();
    let ctrl_write_lock = std::sync::Arc::new(tokio::sync::Mutex::new(ctrl_write));
    loop {
        tokio::select! {
            _ = conn.closed() => {
                debug!("conn closed");
                break;
            }
            _ = stop.changed() => {
                debug!("stop changed");
                break;
            }
            _ = interval.tick() => {
                debug!("client: interval tick");
                match ctrl_write_lock.lock().await.write(keepalive).await {
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
                        let conn = conn.clone();
                        let ctrl_write_lock = ctrl_write_lock.clone();
                        let target = target.address.clone();
                        let stop = stop.clone();
                        let handler = tokio::spawn(async move {
                            return handle_stream_client_accept(
                                &conn,
                                ctrl_write_lock,
                                &mut read,
                                &mut write,
                                &target,
                                stop.clone()
                            ).await;
                        });
                        handlers.push(handler);
                    }
                    Err(e) => {
                        error!("accept error: {}", e);
                    }
                }
            }
        }
    }

    match futures::future::join_all(handlers)
        .await
        .into_iter()
        .find(|x| x.is_err())
    {
        Some(x) => {
            return Err(anyhow!("failed to handle connection: {}", x.err().unwrap()));
        }
        None => {}
    }

    return Ok(());
}

async fn handle_stream_client_accept(
    conn: &quinn::Connection,
    ctrl_write_lock: std::sync::Arc<tokio::sync::Mutex<quinn::SendStream>>,
    tcp_read: &mut tokio::io::ReadHalf<tokio::net::TcpStream>,
    tcp_write: &mut tokio::io::WriteHalf<tokio::net::TcpStream>,
    target: &String,
    stop: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let (mut data_write, mut data_read) = conn.open_bi().await?;
    data_write.write(b"").await?;

    let stream_id = data_read.id().index();
    debug!("data stream opened: {}", stream_id);

    debug!("start stream: {}", stream_id);
    ctrl_write_lock
        .lock()
        .await
        .write(&crate::util::create_pkt_ctrl_cmd(
            0x01,
            stream_id,
            target.as_bytes(),
        ))
        .await?;

    crate::util::pipe_stream_tcp(
        conn,
        &mut data_read,
        &mut data_write,
        tcp_read,
        tcp_write,
        stop,
    )
    .await?;

    return Ok(());
}
