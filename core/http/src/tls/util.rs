use std::io::{self, Cursor};

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, pem::PemObject, PrivateKeyDer};
use rustls::pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

fn err(message: impl Into<std::borrow::Cow<'static, str>>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, message.into())
}

/// Loads certificates from `reader`.
pub fn load_certs(reader: &mut dyn io::Read) -> io::Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_reader_iter(reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| err("invalid certificate"))
}

/// Load and decode the private key from `reader`.
pub fn load_private_key(reader: &mut dyn io::Read) -> io::Result<PrivateKeyDer<'static>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    if let Some(key) = PrivatePkcs1KeyDer::pem_reader_iter(&mut Cursor::new(&buf))
        .flatten().next()
    {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }
    if let Some(key) = PrivatePkcs8KeyDer::pem_reader_iter(&mut Cursor::new(&buf))
        .flatten().next()
    {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }
    if let Some(key) = PrivateSec1KeyDer::pem_reader_iter(&mut Cursor::new(&buf))
        .flatten().next()
    {
        return Ok(PrivateKeyDer::Sec1(key));
    }

    Err(err("failed to find key; supported formats are: RSA, PKCS8, SEC1"))
}

/// Load and decode CA certificates from `reader`.
pub fn load_ca_certs(reader: &mut dyn io::BufRead) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(reader)? {
        roots.add(cert).map_err(|e| err(format!("CA cert error: {}", e)))?;
    }

    Ok(roots)
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! tls_example_key {
        ($k:expr) => {
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/tls/private/", $k))
        }
    }

    #[test]
    fn verify_load_private_keys_of_different_types() -> io::Result<()> {
        let rsa_sha256_key = tls_example_key!("rsa_sha256_key.pem");
        let ecdsa_nistp256_sha256_key = tls_example_key!("ecdsa_nistp256_sha256_key_pkcs8.pem");
        let ecdsa_nistp384_sha384_key = tls_example_key!("ecdsa_nistp384_sha384_key_pkcs8.pem");
        let ed2551_key = tls_example_key!("ed25519_key.pem");

        load_private_key(&mut Cursor::new(rsa_sha256_key))?;
        load_private_key(&mut Cursor::new(ecdsa_nistp256_sha256_key))?;
        load_private_key(&mut Cursor::new(ecdsa_nistp384_sha384_key))?;
        load_private_key(&mut Cursor::new(ed2551_key))?;

        Ok(())
    }

    #[test]
    fn verify_load_certs_of_different_types() -> io::Result<()> {
        let rsa_sha256_cert = tls_example_key!("rsa_sha256_cert.pem");
        let ecdsa_nistp256_sha256_cert = tls_example_key!("ecdsa_nistp256_sha256_cert.pem");
        let ecdsa_nistp384_sha384_cert = tls_example_key!("ecdsa_nistp384_sha384_cert.pem");
        let ed2551_cert = tls_example_key!("ed25519_cert.pem");

        load_certs(&mut Cursor::new(rsa_sha256_cert))?;
        load_certs(&mut Cursor::new(ecdsa_nistp256_sha256_cert))?;
        load_certs(&mut Cursor::new(ecdsa_nistp384_sha384_cert))?;
        load_certs(&mut Cursor::new(ed2551_cert))?;

        Ok(())
    }
}
