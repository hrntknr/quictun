use anyhow::{anyhow, Result};
use async_std::io::{ReadExt, WriteExt};
use byteorder::ByteOrder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct PortAddress {
    pub port: u16,
    pub address: String,
}

#[derive(Copy, Eq, PartialEq, Clone, Debug)]
pub struct ParseError;
impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ParseError")
    }
}

impl std::str::FromStr for PortAddress {
    // type Err = ParseError;
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let idx = s.find(':');
        if idx.is_none() {
            return Err(ParseError);
        }
        let (port, address) = s.split_at(idx.unwrap());
        let port = match port
            .parse::<u16>()
            .map_err(|e| format!("Invalid port: {}", e))
        {
            Ok(0) => return Err(ParseError),
            Ok(v) => v,
            Err(_) => return Err(ParseError),
        };
        Ok(Self {
            port,
            address: address[1..].to_string(),
        })
    }
}

pub async fn generate(
    no_client_auth: bool,
    hostname: &String,
    cert: &String,
    key: &String,
    root_cert: &String,
    root_key: &String,
    client_cert: &String,
    client_key: &String,
) -> Result<()> {
    generate_server(hostname, cert, key).await?;
    if !no_client_auth {
        generate_root(hostname, root_cert, root_key, client_cert, client_key).await?;
    }

    return Ok(());
}

async fn generate_server(hostname: &String, cert: &String, key: &String) -> Result<()> {
    let cert_path = async_std::path::Path::new(&cert);
    let key_path = async_std::path::Path::new(&key);
    if cert_path.exists().await {
        debug!("cert file already exists");
        return Ok(());
    }
    if key_path.exists().await {
        debug!("key file already exists");
        return Ok(());
    }
    async_std::fs::create_dir_all(match cert_path.parent() {
        Some(x) => x,
        None => {
            return Err(anyhow!("failed to get parent directory of cert file"));
        }
    })
    .await?;
    async_std::fs::create_dir_all(match key_path.parent() {
        Some(x) => x,
        None => {
            return Err(anyhow!("failed to get parent directory of key file"));
        }
    })
    .await?;

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, hostname);

    let mut server_param = rcgen::CertificateParams::new(vec![hostname.clone()]);
    server_param.distinguished_name = dn;
    let cert = rcgen::Certificate::from_params(server_param)?;

    async_std::fs::write(cert_path, cert.serialize_pem()?).await?;
    async_std::fs::write(key_path, cert.serialize_private_key_pem()).await?;

    return Ok(());
}

async fn generate_root(
    hostname: &String,
    root_cert: &String,
    root_key: &String,
    client_cert: &String,
    client_key: &String,
) -> Result<()> {
    let root_cert_path = async_std::path::Path::new(&root_cert);
    let root_key_path = async_std::path::Path::new(&root_key);
    let client_cert_path = async_std::path::Path::new(client_cert);
    let client_key_path = async_std::path::Path::new(client_key);

    if root_cert_path.exists().await {
        debug!("root cert file already exists");
        return Ok(());
    }
    if root_key_path.exists().await {
        debug!("root key file already exists");
        return Ok(());
    }
    if client_cert_path.exists().await {
        debug!("client cert file already exists");
        return Ok(());
    }
    if client_key_path.exists().await {
        debug!("client key file already exists");
        return Ok(());
    }
    async_std::fs::create_dir_all(match root_cert_path.parent() {
        Some(x) => x,
        None => {
            return Err(anyhow!("failed to get parent directory of root cert file"));
        }
    })
    .await?;
    async_std::fs::create_dir_all(match root_key_path.parent() {
        Some(x) => x,
        None => {
            return Err(anyhow!("failed to get parent directory of root key file"));
        }
    })
    .await?;
    async_std::fs::create_dir_all(match client_cert_path.parent() {
        Some(x) => x,
        None => {
            return Err(anyhow!(
                "failed to get parent directory of client cert file"
            ));
        }
    })
    .await?;
    async_std::fs::create_dir_all(match client_key_path.parent() {
        Some(x) => x,
        None => {
            return Err(anyhow!("failed to get parent directory of client key file"));
        }
    })
    .await?;

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, hostname);
    let mut root_param = rcgen::CertificateParams::new(vec![]);
    root_param.distinguished_name = dn;
    root_param.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root_param.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let root_cert = rcgen::Certificate::from_params(root_param)?;

    async_std::fs::write(root_cert_path, root_cert.serialize_pem()?).await?;
    async_std::fs::write(root_key_path, root_cert.serialize_private_key_pem()).await?;

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, hostname);
    let mut client_param = rcgen::CertificateParams::new(vec![hostname.clone()]);
    client_param.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    client_param.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    client_param.distinguished_name = dn;
    let client_cert = rcgen::Certificate::from_params(client_param)?;

    async_std::fs::write(
        client_cert_path,
        client_cert.serialize_pem_with_signer(&root_cert)?,
    )
    .await?;
    async_std::fs::write(client_key_path, client_cert.serialize_private_key_pem()).await?;

    return Ok(());
}

pub async fn pipe_stream_std(
    conn: &quinn::Connection,
    quicread: &mut quinn::RecvStream,
    quicwrite: &mut quinn::SendStream,
    baseread: &mut async_std::io::Stdin,
    basewrite: &mut async_std::io::Stdout,
    mut stop_rx: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let mut quicbuf = [0u8; crate::MAX_DATAGRAM_SIZE];
    let mut basebuf = [0u8; crate::MAX_DATAGRAM_SIZE];
    let mut result = Ok(());
    let mut stdend = false;

    loop {
        tokio::select! {
            _ = conn.closed() => {
                debug!("pipe_stream: conn closed");
                break;
            }
            _ = stop_rx.changed() => {
                debug!("pipe_stream: stop_rx changed");
                break;
            }
            v = quicread.read(&mut quicbuf) => {
                let v = match v {
                    Ok(None) => {
                        debug!("pipe_stream: quicread EOF");
                        break;
                    }
                    Ok(Some(v)) => {
                        if v == 0 {
                            debug!("pipe_stream: quicread EOF");
                            break;
                        }
                        v
                    }
                    Err(e) => {
                        debug!("pipe_stream: quicrecv error: {}", e);
                        result = Err(e.into());
                        break;
                    }
                };
                trace!("pipe_stream: quicread {} bytes", v);
                basewrite.write(&quicbuf[..v]).await?;
                basewrite.flush().await?;
            },

            v = baseread.read(&mut basebuf), if !stdend => {
                let v = match v {
                    Ok(v) => {
                        if v == 0 {
                            debug!("pipe_stream: baseread EOF");
                            stdend = true;
                            continue;
                        }
                        v
                    },
                    Err(e) => {
                        debug!("pipe_stream: baserecv error: {}", e);
                        result = Err(e.into());
                        break;
                    }
                };
                quicwrite.write(&basebuf[..v]).await?;
            }
        }
    }
    debug!("pipe_stream: shutdown");
    quicwrite.finish().await?;
    return result;
}

pub async fn pipe_stream_tcp(
    conn: &quinn::Connection,
    quicread: &mut quinn::RecvStream,
    quicwrite: &mut quinn::SendStream,
    baseread: &mut tokio::io::ReadHalf<tokio::net::TcpStream>,
    basewrite: &mut tokio::io::WriteHalf<tokio::net::TcpStream>,
    mut stop_rx: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let mut quicbuf = [0u8; crate::MAX_DATAGRAM_SIZE];
    let mut basebuf = [0u8; crate::MAX_DATAGRAM_SIZE];
    let mut result = Ok(());
    loop {
        tokio::select! {
            _ = conn.closed() => {
                debug!("pipe_stream: conn closed");
                break;
            }
            _ = stop_rx.changed() => {
                debug!("pipe_stream: stop_rx changed");
                break;
            }
            v = quicread.read(&mut quicbuf) => {
                let v = match v {
                    Ok(None) => {
                        debug!("pipe_stream: quicread EOF");
                        break;
                    }
                    Ok(Some(v)) => {
                        if v == 0 {
                            debug!("pipe_stream: quicread EOF");
                            break;
                        }
                        v
                    }
                    Err(e) => {
                        debug!("pipe_stream: quicrecv error: {}", e);
                        result = Err(e.into());
                        break;
                    }
                };
                basewrite.write(&quicbuf[..v]).await?;
            },
            v = baseread.read(&mut basebuf) => {
                let v = match v {
                    Ok(v) => {
                        if v == 0 {
                            debug!("pipe_stream: baserecv EOF");
                            break;
                        }
                        v
                    }
                    Err(e) => {
                        debug!("pipe_stream: baserecv error: {}", e);
                        result = Err(e.into());
                        break;
                    }
                };
                trace!("pipe_stream: baseread {} bytes", v);
                quicwrite.write(&basebuf[..v]).await?;
            }
        }
    }
    debug!("pipe_stream: shutdown");
    basewrite.shutdown().await?;
    quicwrite.finish().await?;
    return result;
}

#[derive(Clone, Debug)]
pub struct CtrlPktStream {
    pub command: u8,
    pub stream_id: u64,
    pub buf: Vec<u8>,
}

pub fn create_pkt_ctrl_cmd(command: u8, stream_id: u64, buf: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&[command]);
    let mut stream_id_buf = [0u8; 8];
    byteorder::BigEndian::write_u64(&mut stream_id_buf, stream_id);
    out.extend_from_slice(&stream_id_buf);
    let mut len = [0u8; 2];
    byteorder::BigEndian::write_u16(&mut len, buf.len() as u16);
    out.extend_from_slice(&len);
    out.extend_from_slice(buf);

    return out;
}

pub fn parse_pkt_ctrl_cmd(buf: &[u8]) -> Result<(CtrlPktStream, usize)> {
    if buf.len() < 11 {
        return Err(anyhow!("invalid ctrl pkt"));
    }
    let command = buf[0];
    let stream_id = byteorder::BigEndian::read_u64(&buf[1..9]);
    let len = byteorder::BigEndian::read_u16(&buf[9..11]) as usize;
    if buf.len() < 11 + len {
        return Err(anyhow!("invalid ctrl pkt"));
    }
    let buf = &buf[11..11 + len];
    let mut copy = Vec::new();
    copy.extend_from_slice(buf);

    return Ok((
        CtrlPktStream {
            command: command,
            stream_id,
            buf: copy,
        },
        buf.len() + 11,
    ));
}

pub fn handle_signal() -> tokio::sync::watch::Receiver<()> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
    tokio::spawn(async move {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        let mut sigint =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
        let mut force = false;
        loop {
            tokio::select! {
                _ = sigterm.recv() => println!("Recieve SIGTERM"),
                _ = sigint.recv() => println!("Recieve SIGTERM"),
            };
            if force {
                std::process::exit(1);
            }
            stop_tx.send(()).unwrap();
            force = true;
        }
    });
    return stop_rx;
}

pub fn no_error(a: Result<()>) -> Result<()> {
    match a {
        Ok(_) => Ok(()),
        Err(e) => {
            debug!("no_error: {}", e);
            Ok(())
        }
    }
}
