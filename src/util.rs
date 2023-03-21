use anyhow::{anyhow, Result};
use async_std::io::{ReadExt, WriteExt};
use byteorder::ByteOrder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    stop_rx: &mut tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let mut quicbuf = [0u8; crate::MAX_DATAGRAM_SIZE];
    let mut basebuf = [0u8; crate::MAX_DATAGRAM_SIZE];

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
                    Ok(None) => continue,
                    Ok(Some(v)) => {
                        if v == 0 {
                            debug!("pipe_stream: quicread EOF");
                            return Ok(());
                        }
                        v
                    },
                    Err(e) => {
                        debug!("pipe_stream: quicrecv error: {:?}", e);
                        return Err(e.into());
                    }
                };
                basewrite.write_all(&quicbuf[..v]).await?;
                basewrite.flush().await?;
            },

            v = baseread.read(&mut basebuf) => {
                let v = match v {
                    Ok(v) => {
                        if v == 0 {
                            debug!("pipe_stream: baseread EOF");
                            return Ok(());
                        }
                        v
                    },
                    Err(e) => {
                        debug!("pipe_stream: baserecv error: {:?}", e);
                        return Err(e.into());
                    }
                };
                quicwrite.write_all(&basebuf[..v]).await?;
            }
        }
    }
    return Ok(());
}

pub async fn pipe_stream_tcp(
    conn: &quinn::Connection,
    quicread: &mut quinn::RecvStream,
    quicwrite: &mut quinn::SendStream,
    baseread: &mut tokio::io::ReadHalf<tokio::net::TcpStream>,
    basewrite: &mut tokio::io::WriteHalf<tokio::net::TcpStream>,
    stop_rx: &mut tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    let mut quicbuf = [0u8; crate::MAX_DATAGRAM_SIZE];
    let mut basebuf = [0u8; crate::MAX_DATAGRAM_SIZE];

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
                    Ok(None) => continue,
                    Ok(Some(v)) => {
                        if v == 0 {
                            debug!("pipe_stream: quicread EOF");
                            return Ok(());
                        }
                        v
                    },
                    Err(e) => {
                        debug!("pipe_stream: quicrecv error: {:?}", e);
                        return Err(e.into());
                    }
                };
                basewrite.write_all(&quicbuf[..v]).await?
            },

            v = baseread.read(&mut basebuf) => {
                let v = match v {
                    Ok(v) => {
                        if v == 0 {
                            debug!("pipe_stream: baserecv EOF");
                            return Ok(());
                        }
                        v
                    },
                    Err(e) => {
                        debug!("pipe_stream: baserecv error: {:?}", e);
                        return Err(e.into());
                    }
                };
                quicwrite.write_all(&basebuf[..v]).await?;
            }
        }
    }
    return Ok(());
}

pub async fn ctrl_write_bytes_with_stream(
    command: u8,
    ctrl_write: &mut quinn::SendStream,
    stream_id: u64,
    buf: &[u8],
) -> Result<()> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&[command]);
    let mut len = [0u8; 2];
    byteorder::BigEndian::write_u16(&mut len, buf.len() as u16 + 8);
    out.extend_from_slice(&len);
    let mut stream_id_buf = [0u8; 8];
    byteorder::BigEndian::write_u64(&mut stream_id_buf, stream_id);
    out.extend_from_slice(&stream_id_buf);
    out.extend_from_slice(buf);
    ctrl_write.write_all(&out).await?;

    return Ok(());
}
