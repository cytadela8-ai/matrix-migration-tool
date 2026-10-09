//! Persistent SDK devices make retries converge. Session tokens are stored atomically in
//! owner-only files; room keys remain in passphrase-encrypted SQLite stores.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use matrix_sdk::{
    Client,
    authentication::matrix::MatrixSession,
    config::{RequestConfig, SyncSettings},
};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use tokio::task::JoinHandle;

use crate::{
    api::Api,
    config::{Account, secret},
};

#[derive(Deserialize, Serialize)]
struct SavedSession {
    homeserver: String,
    session: MatrixSession,
}

pub struct SyncTask(JoinHandle<matrix_sdk::Result<()>>);

pub struct Connected {
    pub client: Client,
    pub api: Api,
    pub sync: SyncTask,
}

impl Connected {
    /// Authenticate, take an initial snapshot and keep encrypted sync alive.
    pub async fn open(account: &Account, directory: &Path, passphrase: &str) -> Result<Self> {
        let client = login(account, directory, passphrase).await?;
        let sync = start_sync(&client).await?;
        let api = Api::new(&client)?;
        Ok(Self { client, api, sync })
    }
}

impl Drop for SyncTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl SyncTask {
    pub fn ensure_running(&self) -> Result<()> {
        ensure!(!self.0.is_finished(), "Matrix sync stopped; check server connection and rerun");
        Ok(())
    }
}

/// Protect the state directory from concurrent migrations and other local users.
pub fn lock_state(path: &Path) -> Result<File> {
    private_directory(path)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path.join("run.lock"))?;
    file.try_lock()
        .context("Another migration is using this state directory; wait for it to finish")?;
    Ok(file)
}

/// Create a private directory, restricting existing directories to their owner on Unix.
pub fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("Create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Atomically replace a JSON file using a private temporary file in the same directory.
pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut file = NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist(path).with_context(|| format!("Save {}", path.display()))?;
    Ok(())
}

/// Restore the same device or log in once, validating the remote identity before use.
///
/// Args:
///     account: Expected Matrix user and homeserver, with secret environment-variable names.
///     directory: Persistent account-specific state directory.
///     passphrase: Encryption passphrase for the SQLite state and crypto stores.
///
/// Returns:
///     Authenticated Matrix SDK client with a persistent device.
pub async fn login(account: &Account, directory: &Path, passphrase: &str) -> Result<Client> {
    private_directory(directory)?;
    let session_path = directory.join("session.json");
    let saved = read_saved(account, &session_path)?;
    let client = Client::builder()
        .homeserver_url(&account.homeserver)
        .sqlite_store(directory.join("store"), Some(passphrase))
        .request_config(RequestConfig::new().timeout(Duration::from_secs(60)).retry_limit(3))
        .build()
        .await
        .context("Open encrypted Matrix store; check store passphrase and homeserver")?;
    authenticate(&client, account, &session_path, saved).await?;
    validate_identity(&client, account).await?;
    Ok(client)
}

fn read_saved(account: &Account, path: &Path) -> Result<Option<SavedSession>> {
    if !path.exists() {
        return Ok(None);
    }
    let saved: SavedSession = serde_json::from_slice(&fs::read(path)?)
        .context("Read saved session; do not reuse this state directory for other accounts")?;
    ensure!(
        saved.homeserver == account.homeserver
            && saved.session.meta.user_id.as_str() == account.user_id,
        "State directory belongs to another account/server; choose a different --state-dir"
    );
    Ok(Some(saved))
}

async fn authenticate(
    client: &Client,
    account: &Account,
    path: &Path,
    saved: Option<SavedSession>,
) -> Result<()> {
    if let Some(saved) = saved {
        client.restore_session(saved.session).await.context("Restore persistent Matrix device")?;
    } else {
        let password = secret(&account.password_env)?;
        client
            .matrix_auth()
            .login_username(&account.user_id, &password)
            .initial_device_display_name("Matrix account migration")
            .await
            .with_context(|| {
                format!("Login {}; check password and password-login support", account.user_id)
            })?;
        let session = client.matrix_auth().session().context("Login returned no session")?;
        write_json(path, &SavedSession { homeserver: account.homeserver.clone(), session })?;
    }
    Ok(())
}

async fn validate_identity(client: &Client, account: &Account) -> Result<()> {
    let identity =
        Api::new(client)?.get(&["account", "whoami"]).await?.context("Missing whoami")?;
    ensure!(identity["user_id"] == account.user_id, "Server authenticated an unexpected user");
    Ok(())
}

/// Start sync after a successful initial snapshot; failures are visible in logs and checks.
pub async fn start_sync(client: &Client) -> Result<SyncTask> {
    let mut filter = matrix_sdk::ruma::api::client::filter::FilterDefinition::default();
    filter.room.include_leave = true;
    let response = client
        .sync_once(
            SyncSettings::new().filter(filter.clone().into()).timeout(Duration::from_secs(1)),
        )
        .await
        .context("Initial Matrix sync failed")?;
    let client = client.clone();
    let task = tokio::spawn(async move {
        let result = client
            .sync(
                SyncSettings::new()
                    .filter(filter.into())
                    .token(response.next_batch)
                    .timeout(Duration::from_secs(10)),
            )
            .await;
        if let Err(error) = &result {
            tracing::error!(%error, "Matrix sync failed");
        }
        result
    });
    Ok(SyncTask(task))
}

#[cfg(test)]
mod tests {
    use crate::session::{lock_state, write_json};
    use serde_json::json;

    #[test]
    fn concurrent_runs_are_excluded_and_lock_is_released() {
        let directory = tempfile::TempDir::new().unwrap();
        let lock = lock_state(directory.path()).unwrap();
        assert!(lock_state(directory.path()).is_err());
        drop(lock);
        lock_state(directory.path()).unwrap();
    }

    #[test]
    fn json_replacement_is_complete_and_private() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("report.json");
        write_json(&path, &json!({"version": 1})).unwrap();
        write_json(&path, &json!({"version": 2})).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value, json!({"version": 2}));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(write_json(&directory.path().join("absent/report.json"), &json!({})).is_err());
    }
}
