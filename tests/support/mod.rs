//! Real Synapse instances federate over test-only self-signed TLS on dynamically allocated
//! loopback ports. RAII stops only the Docker containers created by this harness.

use std::{net::TcpListener, path::Path, process::Command, time::Duration};

use anyhow::{Context, Result, ensure};
use matrix_sdk::{Client, config::RequestConfig, reqwest, ruma::RoomId};
use serde_json::{Value, json};
use tempfile::TempDir;

use matrix_migration_tool::{api::Api, config::Account};

pub const PASSWORD: &str = "integration-test-password";
pub const STORE_PASSPHRASE: &str = "integration-test-store-passphrase";
const IMAGE: &str = concat!(
    "matrixdotorg/synapse:v1.162.0@sha256:",
    "6b84a7bbac36f080b2d2e51e0289cf1b08b349598ea44a558df38d558f2c2311"
);

pub struct Server {
    pub url: String,
    pub name: String,
    container: String,
    _directory: TempDir,
}

impl Server {
    pub async fn start() -> Result<Self> {
        let directory = TempDir::new().expect("Allocate test data directory");
        let client_port = port().expect("Allocate test client port");
        let federation_port = port().expect("Allocate test federation port");
        let name = format!("localhost:{federation_port}");
        let config = include_str!("../servers/homeserver.yaml")
            .replace("SERVER_NAME", &name)
            .replace("CLIENT_PORT", &client_port.to_string())
            .replace("FEDERATION_PORT", &federation_port.to_string())
            .replace("DATA_DIR", "/data");
        std::fs::write(directory.path().join("homeserver.yaml"), config)?;
        let openssl = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
            ])
            .arg(directory.path().join("key.pem"))
            .arg("-out")
            .arg(directory.path().join("cert.pem"))
            .output()?;
        ensure!(
            openssl.status.success(),
            "Generate test TLS certificate: {}",
            String::from_utf8_lossy(&openssl.stderr)
        );
        let container = format!("matrix-migration-test-{client_port}");
        let uid = Command::new("id").arg("-u").output()?;
        ensure!(uid.status.success(), "Determine owner for Synapse test volume");
        let uid = String::from_utf8(uid.stdout)?.trim().to_owned();
        let run = Command::new("docker")
            .args([
                "run",
                "-d",
                "--network",
                "host",
                "--user",
                &uid,
                "--name",
                &container,
                "-e",
                "SYNAPSE_CONFIG_PATH=/data/homeserver.yaml",
                "--mount",
            ])
            .arg(format!("type=bind,src={},dst=/data", directory.path().display()))
            .arg(IMAGE)
            .output()
            .context("Start Synapse Docker container; Docker is required")?;
        ensure!(run.status.success(), "Start Synapse: {}", String::from_utf8_lossy(&run.stderr));
        let server = Self {
            url: format!("http://127.0.0.1:{client_port}"),
            name,
            container,
            _directory: directory,
        };
        tokio::time::timeout(Duration::from_secs(90), server.wait_ready())
            .await
            .context("Synapse did not become ready within 90 seconds")??;
        Ok(server)
    }

    async fn wait_ready(&self) -> Result<()> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(2)).build()?;
        loop {
            if let Ok(response) =
                http.get(format!("{}/_matrix/client/versions", self.url)).send().await
                && response.status().is_success()
            {
                return Ok(());
            }
            let inspect = Command::new("docker")
                .args(["inspect", "--format", "{{.State.Running}}", &self.container])
                .output()?;
            if String::from_utf8_lossy(&inspect.stdout).trim() != "true" {
                let logs = Command::new("docker").args(["logs", &self.container]).output()?;
                anyhow::bail!(
                    "Synapse exited before readiness:\n{}\n{}",
                    String::from_utf8_lossy(&logs.stdout),
                    String::from_utf8_lossy(&logs.stderr)
                );
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    pub async fn register(&self, name: &str, directory: &Path) -> Result<Client> {
        let response = reqwest::Client::new()
            .post(format!("{}/_matrix/client/v3/register", self.url))
            .json(
                &json!({"username": name, "password": PASSWORD, "auth": {"type": "m.login.dummy"}}),
            )
            .send()
            .await?;
        let status = response.status();
        let body: Value = response.json().await?;
        ensure!(status.is_success(), "Registration failed ({status}): {}", body["error"]);
        let client = Client::builder()
            .homeserver_url(&self.url)
            .sqlite_store(directory, Some(STORE_PASSPHRASE))
            .request_config(RequestConfig::new().timeout(Duration::from_secs(30)).retry_limit(1))
            .build()
            .await?;
        client.matrix_auth().login_username(name, PASSWORD).await?;
        Ok(client)
    }

    pub fn account(&self, name: &str, password_env: &str) -> Account {
        Account {
            homeserver: self.url.clone(),
            user_id: format!("@{name}:{}", self.name),
            password_env: Some(password_env.into()),
            verification_device: None,
            recovery_key_env: None,
            import_keys: None,
            import_passphrase_env: None,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if std::thread::panicking() {
            match Command::new("docker").args(["logs", "--tail", "80", &self.container]).output() {
                Ok(logs) => eprintln!("Synapse logs:\n{}", String::from_utf8_lossy(&logs.stderr)),
                Err(error) => eprintln!("Read Synapse test logs: {error}"),
            }
        }
        match Command::new("docker").args(["rm", "-f", &self.container]).output() {
            Ok(output) if output.status.success() => (),
            Ok(output) => {
                eprintln!("Stop test server: {}", String::from_utf8_lossy(&output.stderr))
            }
            Err(error) => eprintln!("Stop test server: {error}"),
        }
    }
}

fn port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

pub async fn create_room(client: &Client, content: Value) -> Result<matrix_sdk::Room> {
    let response = reqwest::Client::new()
        .post(format!(
            "{}/_matrix/client/v3/createRoom",
            client.homeserver().as_str().trim_end_matches('/')
        ))
        .bearer_auth(client.access_token().context("Missing test token")?)
        .json(&content)
        .send()
        .await?;
    let status = response.status();
    let body: Value = response.json().await?;
    ensure!(status.is_success(), "Create test room ({status}): {}", body["error"]);
    let id = RoomId::parse(body["room_id"].as_str().context("Create room returned no room_id")?)?;
    client.join_room_by_id(&id).await.map_err(Into::into)
}

pub async fn bootstrap(client: &Client) -> Result<()> {
    use matrix_sdk::ruma::api::client::uiaa;
    if let Err(error) = client.encryption().bootstrap_cross_signing_if_needed(None).await {
        let response =
            error.as_uiaa_response().context("Cross-signing setup failed without UIAA")?;
        let user = client.user_id().context("Test client not authenticated")?;
        let identifier =
            uiaa::UserIdentifier::Matrix(uiaa::MatrixUserIdentifier::new(user.to_string()));
        let mut password = uiaa::Password::new(identifier, PASSWORD.into());
        password.session = response.session.clone();
        client
            .encryption()
            .bootstrap_cross_signing(Some(uiaa::AuthData::Password(password)))
            .await?;
    }
    Ok(())
}

pub async fn state(client: &Client, id: &str, kind: &str) -> Result<Value> {
    Api::new(client)?.get(&["rooms", id, "state", kind, ""]).await?.context("Missing room state")
}

pub fn save_config(path: &Path, from: &Account, to: &Account) -> Result<()> {
    // Serialize account values as JSON strings: this subset also forms valid TOML basic strings.
    let mut text = "store_passphrase_env = \"TEST_STORE_PASSPHRASE\"\n".to_owned();
    for (role, account) in [("from", from), ("to", to)] {
        text.push_str(&format!("\n[{role}]\n"));
        let fields = serde_json::to_value(account)?;
        for (key, value) in fields.as_object().context("Serialize account")? {
            if !value.is_null() {
                text.push_str(&format!("{key} = {value}\n"));
            }
        }
    }
    std::fs::write(path, text)?;
    Ok(())
}
