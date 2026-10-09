//! Exercise SDK authorization, PKCE, browser redirects, refresh and persisted device reuse
//! against a local HTTP boundary fixture. No account credentials or desktop browser are needed.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use matrix_sdk::{Client, config::RequestConfig, reqwest::Url};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use crate::{
    api::Api,
    browser::{authorize, check_identity},
    config::Account,
    session,
};

#[derive(Clone, Copy)]
enum Mode {
    Oauth,
    Sso,
    PasswordOnly,
    BadMetadata,
    DeniedRegistration,
}

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let saved = requests.clone();
        let base = url.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                let (status, value) = response(&request, &base, mode);
                saved.lock().unwrap().push(request);
                let body = value.to_string();
                let reply = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\n\
                    Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        Self { url, requests, task }
    }

    fn account(&self) -> Account {
        Account {
            homeserver: self.url.clone(),
            user_id: "@alice:example.org".into(),
            password_env: None,
            verification_device: None,
            recovery_key_env: None,
            import_keys: None,
            import_passphrase_env: None,
        }
    }

    async fn client(&self, path: &std::path::Path) -> Client {
        Client::builder()
            .homeserver_url(&self.url)
            .handle_refresh_tokens()
            .sqlite_store(path.join("store"), Some("test-store-passphrase"))
            .server_versions([matrix_sdk::ruma::api::MatrixVersion::V1_15])
            .request_config(RequestConfig::new().retry_limit(0))
            .build()
            .await
            .unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(socket: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0; 4096];
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&chunk[..count]);
        let text = String::from_utf8_lossy(&bytes);
        if let Some((headers, body)) = text.split_once("\r\n\r\n") {
            let mut length = 0;
            for header in headers.lines() {
                if let Some((name, value)) = header.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse().unwrap();
                }
            }
            if body.len() >= length {
                return text.into_owned();
            }
        }
    }
}

fn response(request: &str, base: &str, mode: Mode) -> (u16, Value) {
    let path = request.split_whitespace().nth(1).unwrap().split('?').next().unwrap();
    if path == "/_matrix/client/versions" {
        return (200, json!({"versions": ["v1.15"]}));
    }
    if path.ends_with("/auth_metadata") {
        return match mode {
            Mode::Oauth | Mode::DeniedRegistration => (
                200,
                json!({
                    "issuer": base, "authorization_endpoint": format!("{base}authorize"),
                    "token_endpoint": format!("{base}token"),
                    "registration_endpoint": format!("{base}register"),
                    "revocation_endpoint": format!("{base}revoke"),
                    "response_types_supported": ["code"],
                    "response_modes_supported": ["query", "fragment"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"]
                }),
            ),
            Mode::Sso | Mode::PasswordOnly => (
                404,
                json!({"errcode": "M_UNRECOGNIZED",
                "error": "OAuth unsupported"}),
            ),
            Mode::BadMetadata => (200, json!({"issuer": "not a URL"})),
        };
    }
    if path == "/register" {
        return match mode {
            Mode::DeniedRegistration => (403, json!({"error": "access_denied"})),
            Mode::Oauth | Mode::Sso | Mode::PasswordOnly | Mode::BadMetadata => {
                (200, json!({"client_id": "test-client"}))
            }
        };
    }
    if path == "/token" {
        let refreshed = request.contains("grant_type=refresh_token");
        return (
            200,
            json!({"access_token": if refreshed { "refreshed" } else { "initial" },
            "refresh_token": if refreshed { "refresh-new" } else { "refresh-initial" },
            "token_type": "Bearer"}),
        );
    }
    if path.ends_with("/login") {
        if request.starts_with("GET ") {
            return match mode {
                Mode::Sso => (
                    200,
                    json!({"flows": [{"type": "m.login.sso"},
                    {"type": "m.login.token"}]}),
                ),
                Mode::Oauth | Mode::PasswordOnly | Mode::BadMetadata | Mode::DeniedRegistration => {
                    (200, json!({"flows": [{"type": "m.login.password"}]}))
                }
            };
        }
        return (
            200,
            json!({"user_id": "@alice:example.org", "device_id": "SSO_DEVICE",
            "access_token": "initial", "refresh_token": "refresh-initial"}),
        );
    }
    if path.ends_with("/whoami") {
        return (200, json!({"user_id": "@alice:example.org"}));
    }
    if path.ends_with("/probe") {
        if request.to_lowercase().contains("authorization: bearer refreshed") {
            return (200, json!({"ready": true}));
        }
        return (401, json!({"errcode": "M_UNKNOWN_TOKEN", "error": "Expired"}));
    }
    (404, json!({"errcode": "M_NOT_FOUND", "error": "Absent"}))
}

async fn emulate_browser(url: Url, denied: bool) -> Result<()> {
    let pairs: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
    let oauth = pairs.contains_key("state");
    let key = if oauth { "redirect_uri" } else { "redirectUrl" };
    let mut redirect = Url::parse(pairs.get(key).context("Browser URL lacks redirect")?)?;
    if oauth {
        ensure!(
            pairs.get("code_challenge_method").map(|s| s.as_ref()) == Some("S256"),
            "PKCE is required"
        );
        ensure!(pairs.contains_key("code_challenge"), "PKCE challenge missing");
        ensure!(
            pairs.get("login_hint").map(|s| s.as_ref()) == Some("mxid:@alice:example.org"),
            "Account login hint missing"
        );
        let state = pairs.get("state").unwrap();
        redirect.query_pairs_mut().append_pair("state", state).append_pair(
            if denied { "error" } else { "code" },
            if denied { "access_denied" } else { "test-code" },
        );
    } else {
        redirect.query_pairs_mut().append_pair("loginToken", "test-sso-token");
    }
    let port = redirect.port().context("Callback port missing")?;
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await?;
    let request = format!(
        "GET {}?{} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n",
        redirect.path(),
        redirect.query().context("Callback query missing")?
    );
    socket.write_all(request.as_bytes()).await?;
    Ok(())
}

#[tokio::test]
async fn oauth_login_refresh_and_rerun_preserve_device_and_registration() {
    let server = Server::start(Mode::Oauth).await;
    let directory = tempfile::tempdir().unwrap();
    let account = server.account();
    let client = server.client(directory.path()).await;
    authorize(&client, &account, |url| emulate_browser(url, false)).await.unwrap();
    check_identity(&client, &account).unwrap();
    let device = client.device_id().unwrap().to_owned();
    session::save(&client, &account, &directory.path().join("session.json")).unwrap();
    client.encryption().wait_for_e2ee_initialization_tasks().await;
    drop(client);
    let client = session::login(&account, directory.path(), "test-store-passphrase").await.unwrap();
    assert_eq!(client.device_id(), Some(device.as_ref()));
    let api = Api::new(&client).unwrap();
    assert_eq!(api.get(&["probe"]).await.unwrap().unwrap()["ready"], true);
    let saved = std::fs::read_to_string(directory.path().join("session.json")).unwrap();
    assert!(saved.contains("refresh-new"));
    assert!(saved.contains("test-client"));
    assert_eq!(client.access_token().as_deref(), Some("refreshed"));
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.iter().filter(|r| r.starts_with("POST /register ")).count(), 1);
    let token = requests.iter().find(|r| r.contains("grant_type=authorization_code")).unwrap();
    assert!(token.contains("code_verifier="));
    assert_eq!(requests.iter().filter(|r| r.contains("grant_type=refresh_token")).count(), 1);
}

#[tokio::test]
async fn sso_login_requests_refresh_and_rejects_wrong_account() {
    let server = Server::start(Mode::Sso).await;
    let directory = tempfile::tempdir().unwrap();
    let mut account = server.account();
    let client = server.client(directory.path()).await;
    authorize(&client, &account, |url| emulate_browser(url, false)).await.unwrap();
    assert_eq!(client.device_id().unwrap().as_str(), "SSO_DEVICE");
    check_identity(&client, &account).unwrap();
    account.user_id = "@wrong:example.org".into();
    assert!(check_identity(&client, &account).is_err());
    let path = directory.path().join("session.json");
    assert!(session::save(&client, &account, &path).is_err());
    assert!(!path.exists());
    assert!(
        server
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.contains("\"refresh_token\":true") && r.contains("test-sso-token"))
    );
}

#[tokio::test]
async fn unsupported_broken_and_denied_logins_do_not_fall_back_to_password() {
    for mode in [Mode::PasswordOnly, Mode::BadMetadata, Mode::DeniedRegistration] {
        let server = Server::start(mode).await;
        let directory = tempfile::tempdir().unwrap();
        let client = server.client(directory.path()).await;
        let result = authorize(&client, &server.account(), |_| async {
            anyhow::bail!("Browser must not open for an unusable server")
        })
        .await;
        assert!(result.is_err());
        assert!(client.session().is_none());
        assert!(
            !server
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|r| r.starts_with("POST /_matrix/client/v3/login "))
        );
    }
    let server = Server::start(Mode::Oauth).await;
    let directory = tempfile::tempdir().unwrap();
    let client = server.client(directory.path()).await;
    assert!(authorize(&client, &server.account(), |url| emulate_browser(url, true)).await.is_err());
    assert!(client.session().is_none());
    assert!(!server.requests.lock().unwrap().iter().any(|r| r.starts_with("POST /token ")));
}
