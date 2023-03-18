type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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
            return Err("failed to get parent directory of cert file".into());
        }
    })
    .await?;
    async_std::fs::create_dir_all(match key_path.parent() {
        Some(x) => x,
        None => {
            return Err("failed to get parent directory of key file".into());
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
            return Err("failed to get parent directory of root cert file".into());
        }
    })
    .await?;
    async_std::fs::create_dir_all(match root_key_path.parent() {
        Some(x) => x,
        None => {
            return Err("failed to get parent directory of root key file".into());
        }
    })
    .await?;
    async_std::fs::create_dir_all(match client_cert_path.parent() {
        Some(x) => x,
        None => {
            return Err("failed to get parent directory of client cert file".into());
        }
    })
    .await?;
    async_std::fs::create_dir_all(match client_key_path.parent() {
        Some(x) => x,
        None => {
            return Err("failed to get parent directory of client key file".into());
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
