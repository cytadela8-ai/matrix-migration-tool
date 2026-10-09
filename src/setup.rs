//! Resumable terminal wizard. Draft configuration is saved before login so interruptions
//! reuse the same accounts/devices. Writes are atomic and refuse unexpected external edits.

use std::{fs, io::Write, path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use matrix_sdk::{Client, config::RequestConfig, ruma::UserId};
use tempfile::NamedTempFile;

use crate::{
    config::{Account, Config},
    prompt, session, verification,
};

/// Create or resume configuration without inviting accounts or changing room state.
pub async fn run(path: &Path, state: &Path) -> Result<()> {
    prompt::require_terminal()?;
    let _lock = session::lock_state(state)?;
    let existing = path.exists();
    let mut config = if existing { Config::read(path)? } else { identify_accounts().await? };
    eprintln!("Source:      {} ({})", config.from.user_id, config.from.homeserver);
    eprintln!("Destination: {} ({})", config.to.user_id, config.to.homeserver);
    eprintln!("Config: {}\nState: {}", path.display(), state.display());
    let switch_to_browser = config.from.password_env.is_some()
        || config.to.password_env.is_some()
        || config.store_passphrase_env.is_some();
    if switch_to_browser {
        eprintln!(
            "This wizard will switch password/environment-based login to browser sessions \
            and hidden store prompts. Existing devices, keys and key-import options are retained."
        );
    }
    ensure!(
        prompt::confirm("Set up this migration? No rooms will be changed").await?,
        "Setup cancelled"
    );
    if switch_to_browser {
        config.from.password_env = None;
        config.to.password_env = None;
        config.store_passphrase_env = None;
    }
    let has_store = state.join("from/store").exists() || state.join("to/store").exists();
    let passphrase = prompt::store_passphrase(has_store).await?;
    let mut snapshot =
        if existing { fs::read_to_string(path)? } else { persist(path, &config, None)? };
    let from = session::Connected::open(&config.from, &state.join("from"), &passphrase).await?;
    eprintln!("Source authenticated: {}", config.from.user_id);
    prepare_keys(&from.client, &mut config.from).await?;
    snapshot = persist(path, &config, Some(&snapshot))?;
    from.sync.ensure_running()?;
    let to = session::Connected::open(&config.to, &state.join("to"), &passphrase).await?;
    eprintln!("Destination authenticated: {}", config.to.user_id);
    prepare_keys(&to.client, &mut config.to).await?;
    persist(path, &config, Some(&snapshot))?;
    from.sync.ensure_running()?;
    to.sync.ensure_running()?;
    eprintln!(
        "Setup saved to {}. No rooms were changed.\nRun matrix-migration-tool migrate \
        using the same --config and --state-dir paths shown above.",
        path.display()
    );
    Ok(())
}

async fn identify_accounts() -> Result<Config> {
    let from = identify("Source Matrix ID (@user:server):").await?;
    let to = identify("Destination Matrix ID (@user:server):").await?;
    let config = Config { from, to, store_passphrase_env: None };
    config.validate()?;
    Ok(config)
}

async fn identify(message: &str) -> Result<Account> {
    let id = UserId::parse(prompt::line(message).await?)
        .context("Use a full Matrix ID: @user:server")?;
    eprintln!("Discovering homeserver for {}…", id.server_name());
    let discovered = tokio::time::timeout(
        Duration::from_secs(30),
        Client::builder()
            .server_name(id.server_name())
            .request_config(RequestConfig::new().timeout(Duration::from_secs(10)).retry_limit(1))
            .build(),
    )
    .await;
    let homeserver = match discovered {
        Ok(Ok(client)) => client.homeserver().to_string(),
        Ok(Err(error)) => {
            eprintln!("Homeserver discovery failed: {error}");
            prompt::line("Homeserver HTTPS URL:").await?
        }
        Err(_) => {
            eprintln!("Homeserver discovery timed out.");
            prompt::line("Homeserver HTTPS URL:").await?
        }
    };
    Ok(Account {
        homeserver,
        user_id: id.to_string(),
        password_env: None,
        verification_device: None,
        recovery_key_env: None,
        import_keys: None,
        import_passphrase_env: None,
    })
}

async fn prepare_keys(client: &Client, account: &mut Account) -> Result<()> {
    if let Some(device) = &account.verification_device {
        verification::pair(client, device).await?;
        eprintln!("Existing pairing ready for {}.", account.user_id);
        return Ok(());
    }
    eprintln!(
        "Browser login does not unlock encrypted history. Keep an existing client online.\n\
        Choose: 1) pair an existing device  2) use a recovery key  3) continue with incomplete keys"
    );
    let choice = prompt::line("Key access [1/2/3]:").await?;
    match choice.as_str() {
        "1" => {
            let device = select_device(client).await?;
            verification::pair(client, &device).await?;
            account.verification_device = Some(device);
        }
        "2" => {
            let key = prompt::hidden("Account recovery key or recovery passphrase:").await?;
            client
                .encryption()
                .recovery()
                .recover(&key)
                .await
                .context("Unlock encrypted history using recovery")?;
            eprintln!(
                "Recovery secrets retained in the encrypted local store; input was not saved."
            );
        }
        "3" => ensure!(
            prompt::confirm(
                "Continue knowing encrypted history may be unavailable and reported as incomplete?"
            )
            .await?,
            "Key-access setup cancelled"
        ),
        _ => anyhow::bail!("Choose 1, 2 or 3; rerun init to resume"),
    }
    Ok(())
}

async fn select_device(client: &Client) -> Result<String> {
    let user = client.user_id().context("Not authenticated")?;
    client.encryption().request_user_identity(user).await?;
    let devices = client.encryption().get_user_devices(user).await?;
    let mut choices = Vec::new();
    for device in devices.devices() {
        if Some(device.device_id()) == client.device_id() {
            continue;
        }
        choices.push(device.device_id().to_string());
        eprintln!(
            "{}) {} [{}]{}",
            choices.len(),
            device.display_name().unwrap_or("Unnamed device"),
            device.device_id(),
            if device.is_verified() { " (already verified)" } else { "" }
        );
    }
    ensure!(
        !choices.is_empty(),
        "No other device found. Log into a Matrix client first, \
        or rerun init and choose recovery/incomplete key access"
    );
    let number = prompt::line("Existing device number:")
        .await?
        .parse::<usize>()
        .context("Device selection must be a number")?;
    let index = number.checked_sub(1).context("Choose a listed device number starting at 1")?;
    choices.get(index).cloned().context("Choose a listed device number")
}

fn persist(path: &Path, config: &Config, expected: Option<&str>) -> Result<String> {
    config.validate()?;
    let text = toml::to_string_pretty(config).context("Serialize configuration")?;
    if let Some(expected) = expected {
        ensure!(
            fs::read_to_string(path)? == expected,
            "Configuration changed outside setup; refusing to overwrite it"
        );
        if text == expected {
            return Ok(text);
        }
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut file = NamedTempFile::new_in(parent).context("Config parent directory must exist")?;
    file.write_all(text.as_bytes())?;
    file.as_file().sync_all()?;
    if expected.is_some() {
        file.persist(path).context("Save setup configuration")?;
    } else {
        file.persist_noclobber(path).context("Config already exists; rerun init to resume it")?;
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use crate::{config::Config, setup::persist};

    #[test]
    fn generated_config_omits_secrets_and_preserves_conflicts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let mut config: Config = toml::from_str(include_str!("../config.toml.example")).unwrap();
        config.from.password_env = None;
        config.to.password_env = None;
        config.store_passphrase_env = None;
        let text = persist(&path, &config, None).unwrap();
        assert!(!text.contains("password"));
        assert!(!text.contains("passphrase"));
        Config::read(&path).unwrap();
        assert!(persist(&path, &config, None).is_err());
        assert_eq!(persist(&path, &config, Some(&text)).unwrap(), text);
        std::fs::write(&path, "user edit").unwrap();
        assert!(persist(&path, &config, Some(&text)).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "user edit");
    }
}
