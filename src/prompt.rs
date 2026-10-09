//! Terminal prompts never read secret values from piped stdin or command-line arguments.

use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result, ensure};
use zeroize::Zeroizing;

/// Require a terminal before an interactive command creates files or contacts servers.
pub fn require_terminal() -> Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stderr().is_terminal(),
        "Interactive setup/input requires a terminal; run this command locally in a terminal"
    );
    Ok(())
}

/// Read one nonsecret response; EOF cancels instead of accepting a default.
pub async fn line(message: &str) -> Result<String> {
    let message = message.to_owned();
    tokio::task::spawn_blocking(move || line_inner(&message))
        .await
        .context("Read terminal response")?
}

fn line_inner(message: &str) -> Result<String> {
    eprint!("{message} ");
    io::stderr().flush()?;
    let mut value = String::new();
    ensure!(io::stdin().read_line(&mut value)? > 0, "Input closed; setup cancelled");
    Ok(value.trim().to_owned())
}

/// Accept only an explicit yes, never an empty default.
pub async fn confirm(message: &str) -> Result<bool> {
    Ok(line(&format!("{message} [yes/no]:")).await?.eq_ignore_ascii_case("yes"))
}

/// Read a nonempty secret using the platform terminal without echoing it.
pub async fn hidden(message: &str) -> Result<Zeroizing<String>> {
    require_terminal()?;
    let message = message.to_owned();
    tokio::task::spawn_blocking(move || hidden_inner(&message))
        .await
        .context("Read secret terminal response")?
}

fn hidden_inner(message: &str) -> Result<Zeroizing<String>> {
    let value = rpassword::prompt_password(format!("{message} ")).map_err(|error| {
        if error.kind() == io::ErrorKind::Interrupted {
            return anyhow::anyhow!(
                "Input interrupted; rerun the command with the same config/state"
            );
        }
        anyhow::Error::new(error).context("Read hidden terminal input")
    })?;
    let value = Zeroizing::new(value);
    ensure!(!value.is_empty(), "Secret input must not be empty");
    Ok(value)
}

/// Confirm a new store passphrase; existing stores only require the original passphrase.
pub async fn store_passphrase(existing: bool) -> Result<Zeroizing<String>> {
    let value = hidden("Local store passphrase:").await?;
    if !existing {
        let confirmation = hidden("Confirm local store passphrase:").await?;
        ensure!(value == confirmation, "Passphrases differ; no account login was attempted");
    }
    Ok(value)
}

/// Restore POSIX terminal settings if Ctrl-C cancels an outstanding hidden-input reader.
/// The CLI uses a bounded runtime shutdown because OS stdin reads cannot be cancelled.
pub struct TerminalMode {
    #[cfg(unix)]
    value: Option<String>,
}

impl TerminalMode {
    pub fn capture() -> Result<Self> {
        #[cfg(unix)]
        {
            if !io::stdin().is_terminal() {
                return Ok(Self { value: None });
            }
            let output = std::process::Command::new("stty")
                .arg("-g")
                .stdin(std::process::Stdio::inherit())
                .output()
                .context("Interactive input requires POSIX stty for safe terminal restoration")?;
            ensure!(output.status.success(), "Cannot capture terminal settings using stty");
            let value = String::from_utf8(output.stdout)?.trim().to_owned();
            Ok(Self { value: Some(value) })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(value) = &self.value {
            let result = std::process::Command::new("stty")
                .arg(value)
                .stdin(std::process::Stdio::inherit())
                .status();
            match result {
                Ok(status) if status.success() => (),
                Ok(status) => {
                    tracing::warn!(%status, "Restore terminal settings manually: stty sane")
                }
                Err(error) => {
                    tracing::warn!(%error, "Restore terminal settings manually: stty sane")
                }
            }
        }
    }
}
