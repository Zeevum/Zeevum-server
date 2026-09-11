//! TLS server configuration built from PEM files on disk

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

/// Builds a TLS server config from a certificate chain and a private key
pub fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let cert_file = &mut BufReader::new(
        File::open(cert_path).with_context(|| format!("Failed to open cert file {cert_path:?}"))?,
    );
    let key_file = &mut BufReader::new(
        File::open(key_path).with_context(|| format!("Failed to open key file {key_path:?}"))?,
    );

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(cert_file)
        .collect::<Result<_, _>>()
        .context("Failed to parse certs")?;

    let key: PrivateKeyDer<'static> =
        PrivateKeyDer::from_pem_reader(key_file).context("Failed to parse key")?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS config")?;

    Ok(Arc::new(config))
}
