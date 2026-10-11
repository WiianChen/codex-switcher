use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};

#[derive(Clone, Serialize, Deserialize)]
pub struct Connection {
    pub origin: String,
    pub certificate_sha256: String,
}
impl Connection {
    pub fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.origin)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            bail!("NAS 必須是 HTTPS 網站根網址");
        }
        if self.certificate_sha256.len() != 64
            || !self
                .certificate_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            bail!("憑證 SHA-256 指紋必須為 64 個十六進位字元");
        }
        Ok(())
    }
}

pub fn identity(auth: &Value) -> Result<String> {
    let tokens = &auth["tokens"];
    let declared = tokens["account_id"].as_str();
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let claim = tokens["id_token"]
        .as_str()
        .and_then(|t| t.split('.').nth(1))
        .and_then(|t| URL_SAFE_NO_PAD.decode(t).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| {
            v["https://api.openai.com/auth"]["chatgpt_account_id"]
                .as_str()
                .map(String::from)
        });
    if let (Some(a), Some(b)) = (declared, claim.as_deref()) {
        if a != b {
            bail!("登入憑證的帳號身分不符");
        }
    }
    declared
        .map(String::from)
        .or(claim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow::anyhow!("登入憑證缺少帳號身分"))
}
pub fn same_identity(expected: &Value, received: &Value) -> Result<()> {
    if identity(expected)? != identity(received)? {
        bail!("NAS 回傳的帳號身分不符，未切換");
    }
    Ok(())
}
pub fn recovery_index(candidates: &[Value], live: &Value) -> Result<usize> {
    let wanted = identity(live)?;
    let matching: Vec<_> = candidates
        .iter()
        .enumerate()
        .filter_map(|(index, auth)| {
            identity(auth)
                .ok()
                .filter(|id| id == &wanted)
                .map(|_| index)
        })
        .collect();
    if matching.len() != 1 {
        bail!("本機憑證無法對應唯一租約；帳號仍保持鎖定");
    }
    Ok(matching[0])
}
pub fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("設定路徑無效"))?;
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.as_file().sync_all()?;
    file.persist(path)
        .map_err(|_| anyhow::anyhow!("無法原子寫入檔案"))?;
    Ok(())
}
#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    pin: String,
}
impl rustls::client::danger::ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        name: &rustls::pki_types::ServerName<'_>,
        ocsp: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let checked = self
            .inner
            .verify_server_cert(end, intermediates, name, ocsp, now)?;
        if format!("{:x}", Sha256::digest(end.as_ref())) != self.pin.to_ascii_lowercase() {
            return Err(rustls::Error::General(
                "NAS certificate fingerprint mismatch".into(),
            ));
        }
        Ok(checked)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub struct NasClient {
    http: reqwest::Client,
    connection: Connection,
    token: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Lease {
    pub lease_id: String,
    pub revision: i64,
    pub expires_at: i64,
    pub auth: Value,
}
impl NasClient {
    pub fn new(connection: Connection, token: String) -> Result<Self> {
        connection.validate()?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        Self::with_roots(connection, token, roots)
    }
    fn with_roots(
        connection: Connection,
        token: String,
        roots: rustls::RootCertStore,
    ) -> Result<Self> {
        connection.validate()?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()?;
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                inner: verifier,
                pin: connection.certificate_sha256.clone(),
            }))
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            http,
            connection,
            token,
        })
    }
    pub async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let url = format!(
            "{}/api/v1{}",
            self.connection.origin.trim_end_matches('/'),
            path
        );
        let mut req = self.http.request(method, url);
        if !self.token.is_empty() {
            req = req.bearer_auth(&self.token);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let response = req
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("NAS 連線或 HTTPS 憑證驗證失敗；保留目前帳號"))?;
        if !response.status().is_success() {
            bail!(
                "NAS 拒絕操作（HTTP {}）；請檢查租約與憑證版本",
                response.status().as_u16()
            );
        }
        response
            .json()
            .await
            .map_err(|_| anyhow::anyhow!("NAS 回應格式錯誤"))
    }
    pub async fn acquire(&self, id: &str) -> Result<Lease> {
        Ok(serde_json::from_value(
            self.request(
                reqwest::Method::POST,
                &format!("/accounts/{id}/lease"),
                None,
            )
            .await?,
        )?)
    }
    pub async fn upload(&self, id: &str, lease: &str, revision: i64, auth: Value) -> Result<i64> {
        let v = self
            .request(
                reqwest::Method::PUT,
                &format!("/accounts/{id}/credentials"),
                Some(json!({"lease_id":lease,"expected_revision":revision,"auth":auth})),
            )
            .await?;
        v["revision"]
            .as_i64()
            .ok_or_else(|| anyhow::anyhow!("NAS 缺少憑證版本"))
    }
    pub async fn heartbeat(&self, id: &str, lease: &str) -> Result<()> {
        self.request(
            reqwest::Method::POST,
            &format!("/accounts/{id}/lease/heartbeat"),
            Some(json!({"lease_id":lease})),
        )
        .await?;
        Ok(())
    }
    pub async fn release(&self, id: &str, lease: &str) -> Result<()> {
        self.request(
            reqwest::Method::DELETE,
            &format!("/accounts/{id}/lease"),
            Some(json!({"lease_id":lease})),
        )
        .await?;
        Ok(())
    }
    pub async fn accounts(&self) -> Result<Value> {
        self.request(reqwest::Method::GET, "/accounts", None).await
    }
    pub async fn pair(&self, code: &str) -> Result<String> {
        let v = self
            .request(
                reqwest::Method::POST,
                "/devices/pair",
                Some(json!({"code":code,"name":"Windows Switcher"})),
            )
            .await?;
        v["token"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("配對失敗"))
    }
}
#[cfg(windows)]
pub fn save_token(origin: &str, token: &str) -> Result<()> {
    keyring::Entry::new("codex-switcher-nas", origin)?.set_password(token)?;
    Ok(())
}
#[cfg(windows)]
pub fn load_token(origin: &str) -> Result<String> {
    Ok(keyring::Entry::new("codex-switcher-nas", origin)?.get_password()?)
}
#[cfg(not(windows))]
pub fn save_token(_: &str, _: &str) -> Result<()> {
    bail!("NAS 同步目前只支援 Windows Credential Manager")
}
#[cfg(not(windows))]
pub fn load_token(_: &str) -> Result<String> {
    bail!("NAS 同步目前只支援 Windows Credential Manager")
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use std::io::{Read, Write};
    async fn exchange(correct_pin: bool) -> (bool, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let pin = format!("{:x}", Sha256::digest(der.as_ref()));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![der],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            )
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(server)).unwrap(),
                socket,
            );
            let mut bytes = vec![0; 8192];
            let n = stream.read(&mut bytes).unwrap_or(0);
            bytes.truncate(n);
            if n > 0 {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
                let _ = stream.flush();
            }
            bytes
        });
        let client = NasClient::with_roots(
            Connection {
                origin: format!("https://localhost:{port}"),
                certificate_sha256: if correct_pin { pin } else { "0".repeat(64) },
            },
            "sentinel-device-secret".into(),
            roots,
        )
        .unwrap();
        let ok = client
            .request(reqwest::Method::GET, "/status", None)
            .await
            .is_ok();
        (ok, handle.join().unwrap())
    }
    #[tokio::test]
    async fn wrong_pin_stops_before_any_bearer_or_http_bytes_are_sent() {
        let (ok, bytes) = exchange(false).await;
        assert!(!ok);
        assert!(bytes.is_empty());
    }
    #[tokio::test]
    async fn trusted_chain_and_matching_pin_allow_authenticated_request() {
        let (ok, bytes) = exchange(true).await;
        assert!(ok);
        assert!(String::from_utf8(bytes)
            .unwrap()
            .contains("Bearer sentinel-device-secret"));
    }
}
