type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Packet {
    stream_id: u64,
    payload: Vec<u8>,
}

impl std::fmt::Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Packet")
            .field("streamId", &self.stream_id)
            .field("payload", &self.payload)
            .finish()
    }
}
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
    conn_timeout: u64,
    keep_alive: u64,
    endpoint: String,
    target: String,
) -> Result<()> {
    debug!("client: endpoint: {}, target: {}", endpoint, target);

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

    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        roots.add(&rustls::Certificate(cert.0)).unwrap();
    }
    let mut client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"quic/v1".to_vec()];

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(10).try_into()?));

    let mut quinn_client_config = quinn::ClientConfig::new(std::sync::Arc::new(client_config));
    quinn_client_config.transport_config(std::sync::Arc::new(transport_config));
    qe.set_default_client_config(quinn_client_config);

    let conn = match qe.connect(peer_addr, endpoint.domain().unwrap())?.await {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("failed to connect: {}", e).into());
        }
    };

    let (mut ctrl_send, mut ctrl_recv) = match conn.open_bi().await {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("failed to open stream: {}", e).into());
        }
    };
    let (mut data_send, mut data_recv) = match conn.open_bi().await {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("failed to open stream: {}", e).into());
        }
    };

    tokio::spawn(async move {
        let mut buf = [0; crate::MAX_DATAGRAM_SIZE];
        loop {
            match data_recv.read(&mut buf).await {
                Ok(v) => {
                    debug!("client: recv: {:?}", v);
                }
                Err(e) => {
                    error!("client: recv: {}", e);
                    break;
                }
            }
        }
    });

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(keep_alive));

        loop {
            interval.tick().await;
            debug!("client: send: ping (keep-alive)");
            let mut out = Vec::new();
            out.extend_from_slice(b"ping");
            match ctrl_send.write(&out).await {
                Ok(v) => {
                    debug!("client: send: {:?}", v);
                }
                Err(e) => {
                    error!("client: send: {}", e);
                    break;
                }
            }
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(100000)).await;

    return Ok(());
}
