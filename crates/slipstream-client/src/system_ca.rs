use std::ffi::CString;

/// Locate the OS's default CA bundle file for `--verify-system-ca` mode -- the same well-known
/// paths and `SSL_CERT_FILE`/`SSL_CERT_DIR` env vars that curl/git/OpenSSL itself use.
///
/// Only a single bundle *file* is usable here: picoquic's OpenSSL backend
/// (`picoquic_ptls_openssl.c`'s `picoquic_openssl_get_openssl_certificate_verifier`) loads
/// `cert_root_file_name` via `X509_LOOKUP_file` only, never `X509_LOOKUP_hash_dir` -- a system that
/// only has a hashed cert *directory* (no single bundle file) isn't supported by this path.
pub fn find_system_ca_bundle() -> Result<CString, String> {
    let probe = openssl_probe::probe();
    let path = probe.cert_file.ok_or_else(|| {
        "could not locate a system CA bundle file (checked SSL_CERT_FILE and common paths such as \
         /etc/ssl/certs/ca-certificates.crt); --verify-system-ca needs a single bundle file, which \
         this system doesn't appear to have"
            .to_string()
    })?;
    let path_str = path
        .to_str()
        .ok_or_else(|| format!("system CA bundle path is not valid UTF-8: {}", path.display()))?;
    CString::new(path_str)
        .map_err(|_| format!("system CA bundle path contains a NUL byte: {path_str}"))
}
