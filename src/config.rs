//! Configuration contains identities and optional secret environment-variable names.
//! Wizard-created configs omit credential names and use browser sessions/terminal unlocking.

use std::{env, path::Path};

use anyhow::{Context, Result, ensure};
use matrix_sdk::{reqwest::Url, ruma::UserId};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub homeserver: String,
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_keys: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_passphrase_env: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub from: Account,
    pub to: Account,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_passphrase_env: Option<String>,
}

impl Config {
    /// Unlock stores from an explicit environment variable or a hidden terminal prompt.
    pub async fn store_passphrase(&self) -> Result<Zeroizing<String>> {
        if let Some(name) = &self.store_passphrase_env {
            return secret(name);
        }
        crate::prompt::hidden("Local store passphrase:").await
    }
    /// Read a config and reject account ambiguity before contacting either server.
    ///
    /// Args:
    ///     path: TOML configuration file containing environment-variable names.
    ///
    /// Returns:
    ///     Validated migration configuration.
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Read config {}", path.display()))?;
        let config: Self = toml::from_str(&text).context("Parse configuration TOML")?;
        config.validate()?;
        Ok(config)
    }

    /// Validate account IDs, URLs and paired key-import options.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.from.user_id != self.to.user_id, "From and To must be different Matrix users");
        for account in [&self.from, &self.to] {
            UserId::parse(&account.user_id).context("Use a full Matrix ID: @user:server")?;
            let url = Url::parse(&account.homeserver).context("Invalid homeserver URL")?;
            ensure!(url.has_host(), "Homeserver URL requires a host");
            ensure!(
                url.username().is_empty() && url.password().is_none(),
                "URL must not contain credentials"
            );
            ensure!(
                url.query().is_none() && url.fragment().is_none(),
                "URL must not contain query or fragment"
            );
            let local =
                ["localhost", "127.0.0.1", "[::1]"].contains(&url.host_str().unwrap_or_default());
            ensure!(
                url.scheme() == "https" || (url.scheme() == "http" && local),
                "Use HTTPS for homeservers; HTTP is allowed only on loopback for tests"
            );
            ensure!(
                account.import_keys.is_some() == account.import_passphrase_env.is_some(),
                "import_keys and import_passphrase_env must be specified together"
            );
        }
        Ok(())
    }
}

/// Obtain a nonempty secret without including its value in diagnostics.
pub fn secret(name: &str) -> Result<Zeroizing<String>> {
    let value =
        env::var(name).with_context(|| format!("Set secret environment variable {name}"))?;
    ensure!(!value.is_empty(), "Secret environment variable {name} must not be empty");
    Ok(Zeroizing::new(value))
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    fn example() -> Config {
        toml::from_str(include_str!("../config.toml.example")).unwrap()
    }

    #[test]
    fn example_validates_and_unknown_fields_fail() {
        example().validate().unwrap();
        let text =
            include_str!("../config.toml.example").replace("password_env =", "pasword_env =");
        assert!(toml::from_str::<Config>(&text).is_err());
        assert!(toml::from_str::<Config>("{bad toml").is_err());
    }

    #[test]
    fn rejects_same_user_invalid_id_and_incomplete_import() {
        let mut config = example();
        config.to.user_id = config.from.user_id.clone();
        assert!(config.validate().is_err());
        config.to.user_id = "alice".into();
        assert!(config.validate().is_err());
        config = example();
        config.from.import_keys = Some("keys.txt".into());
        assert!(config.validate().is_err());
        config.from.import_passphrase_env = Some("KEY_PASSPHRASE".into());
        config.validate().unwrap();
    }

    #[test]
    fn rejects_unsafe_urls_and_allows_loopback() {
        for url in [
            "http://example.org",
            "https://user:secret@example.org",
            "file:///tmp",
            "https://example.org?token=secret",
            "https://example.org#fragment",
            "invalid",
        ] {
            let mut config = example();
            config.from.homeserver = url.into();
            assert!(config.validate().is_err(), "Accepted {url}");
        }
        for url in ["http://127.0.0.1:8008", "http://localhost:8008", "http://[::1]:8008"] {
            let mut config = example();
            config.from.homeserver = url.into();
            config.validate().unwrap();
        }
    }

    #[test]
    fn missing_configuration_has_actionable_path() {
        let error =
            Config::read(std::path::Path::new("/nonexistent/matrix-config.toml")).unwrap_err();
        assert!(error.to_string().contains("/nonexistent/matrix-config.toml"));
    }
}
