//! Megolm keys are transferred through an encrypted owner-only temporary file, never plaintext.
//! Transfers import into the destination device and its already-enabled backup without resets.

use std::{path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use matrix_sdk::{Client, ruma::RoomId};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::{
    config::{Account, secret},
    report::Outcome,
    verification,
};

/// Acquire available secrets by pairing, recovery, and/or an encrypted key export.
pub async fn prepare(client: &Client, account: &Account) -> Vec<Outcome> {
    let mut outcomes = Vec::new();
    if let Some(device) = &account.verification_device {
        let result = verification::pair(client, device).await;
        outcomes.push(match result {
            Ok(true) => Outcome::Changed(format!("{} paired with {device}", account.user_id)),
            Ok(false) => Outcome::Unchanged(format!("{} already trusts {device}", account.user_id)),
            Err(error) => Outcome::Failed(format!("{} pairing: {error:#}", account.user_id)),
        });
    }
    if let Some(name) = &account.recovery_key_env {
        let result = recover(client, name).await;
        outcomes.push(outcome(result, &format!("{} recover backup secrets", account.user_id)));
    }
    if let Some(path) = &account.import_keys {
        let result = import(client, account, path).await;
        outcomes.push(outcome(result, &format!("{} import encrypted key export", account.user_id)));
    }
    outcomes
}

async fn recover(client: &Client, name: &str) -> Result<usize> {
    let key = secret(name)?;
    client.encryption().recovery().recover(&key).await.context("Recover secret storage")?;
    Ok(0)
}

async fn import(client: &Client, account: &Account, path: &str) -> Result<usize> {
    let name =
        account.import_passphrase_env.as_deref().context("Missing import passphrase variable")?;
    let passphrase = secret(name)?;
    let result = client.encryption().import_room_keys(path.into(), &passphrase).await?;
    Ok(result.imported_count)
}

fn outcome(result: Result<usize>, operation: &str) -> Outcome {
    match result {
        Ok(0) => Outcome::Unchanged(format!("{operation}: ready / no new keys")),
        Ok(count) => Outcome::Changed(format!("{operation}: {count} keys imported")),
        Err(error) => Outcome::Failed(format!("{operation}: {error:#}")),
    }
}

/// Copy all available keys for one room into the destination persistent crypto store.
///
/// Args:
///     from: Source account client.
///     to: Destination account client.
///     room_id: Room that the destination has joined.
///     passphrase: Secret used to protect the transient export.
///
/// Returns:
///     Total exported sessions and the number newly imported or improved.
pub async fn transfer(
    from: &Client,
    to: &Client,
    room_id: &RoomId,
    passphrase: &str,
) -> Result<(usize, usize)> {
    let file = NamedTempFile::new().context("Create private encrypted key-transfer file")?;
    from.encryption()
        .export_room_keys(file.path().to_owned(), passphrase, |s| s.room_id() == room_id)
        .await
        .context("Export source room keys")?;
    let result = to
        .encryption()
        .import_room_keys(file.path().to_owned(), passphrase)
        .await
        .context("Import destination room keys")?;
    Ok((result.total_count, result.imported_count))
}

/// Export destination keys, treating an existing export with equal or better coverage as success.
///
/// Args:
///     client: Destination client with its persistent keys loaded.
///     path: Output file; unrelated, unreadable or outdated files are never overwritten.
///     passphrase: Encryption passphrase for the standard Matrix room-key export.
///
/// Returns:
///     True if a new export was created; false when an existing export covers all current keys.
pub async fn export(client: &Client, path: &Path, passphrase: &str) -> Result<bool> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let file = NamedTempFile::new_in(parent)?;
    client.encryption().export_room_keys(file.path().to_owned(), passphrase, |_| true).await?;
    if path.exists() {
        let existing = path.to_owned();
        let current = file.path().to_owned();
        let passphrase = Zeroizing::new(passphrase.to_owned());
        let covers = tokio::task::spawn_blocking(move || covers(&existing, &current, &passphrase))
            .await
            .context("Compare encrypted exports")??;
        ensure!(covers, "Existing export lacks current keys; choose a new output path");
        return Ok(false);
    }
    file.persist_noclobber(path)
        .context("Export path already exists or is not writable; choose a new path")?;
    Ok(true)
}

fn covers(existing: &Path, current: &Path, passphrase: &str) -> Result<bool> {
    use matrix_sdk_crypto::olm::InboundGroupSession;
    let existing = read_export(existing, passphrase)?;
    let current = read_export(current, passphrase)?;
    let indexes = session_indexes(existing)?;
    for key in current {
        let session = InboundGroupSession::from_export(&key)?;
        let id = (key.room_id, key.sender_key.to_base64(), key.session_id);
        let Some(index) = indexes.get(&id) else {
            return Ok(false);
        };
        if *index > session.first_known_index() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn read_export(
    path: &Path,
    passphrase: &str,
) -> Result<Vec<matrix_sdk_crypto::olm::ExportedRoomKey>> {
    matrix_sdk_crypto::decrypt_room_key_export(std::fs::File::open(path)?, passphrase)
        .context("Output is not a readable Matrix export with this passphrase")
}

type SessionIndexes =
    std::collections::BTreeMap<(matrix_sdk::ruma::OwnedRoomId, String, String), u32>;

fn session_indexes(keys: Vec<matrix_sdk_crypto::olm::ExportedRoomKey>) -> Result<SessionIndexes> {
    use matrix_sdk_crypto::olm::InboundGroupSession;
    let mut indexes = SessionIndexes::new();
    for key in keys {
        let session = InboundGroupSession::from_export(&key)?;
        ensure!(session.session_id() == key.session_id, "Existing export has invalid session ID");
        indexes.insert(
            (key.room_id, key.sender_key.to_base64(), key.session_id),
            session.first_known_index(),
        );
    }
    Ok(indexes)
}

/// Wait for imported keys to upload only when an existing destination backup is enabled.
pub async fn flush_backup(client: &Client) -> Result<bool> {
    let backups = client.encryption().backups();
    if !backups.are_enabled().await {
        return Ok(false);
    }
    tokio::time::timeout(Duration::from_secs(120), backups.wait_for_steady_state())
        .await
        .context("Destination backup upload timed out")??;
    Ok(true)
}
