type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub async fn generate(hostname: &String, cert: &String, key: &String) -> Result<()> {
    let cert_path = async_std::path::Path::new(&cert);
    let key_path = async_std::path::Path::new(&key);
    if cert_path.exists().await {
        debug!("cert file already exists");
    }
    if key_path.exists().await {
        debug!("key file already exists");
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

    let cert = rcgen::generate_simple_self_signed(vec![hostname.clone()])?;
    async_std::fs::write(key_path, cert.serialize_private_key_pem()).await?;
    async_std::fs::write(cert_path, cert.serialize_pem()?).await?;
    return Ok(());
}
