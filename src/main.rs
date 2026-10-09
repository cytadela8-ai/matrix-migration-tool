//! CLI keeps secrets off command-line arguments and always writes partial migration reports.

use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use matrix_migration_tool::{
    config::{Config, secret},
    crypto, migration, prompt,
    report::Report,
    session, setup,
};

#[derive(Parser)]
#[command(
    version,
    about = "Migrate Matrix accounts with convergent writes and encrypted-history checks"
)]
struct Cli {
    #[arg(long, default_value = "config.toml", global = true)]
    config: PathBuf,
    #[arg(long, default_value = ".matrix-migration", global = true)]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Interactively create/resume config, browser sessions and encrypted-key access.
    Init,
    /// Invite/join, increase power, merge metadata, transfer keys and audit history.
    Migrate {
        #[arg(long, default_value = "migration-report.json")]
        report: PathBuf,
    },
    /// Export destination keys; reruns preserve exports with equal or better key coverage.
    ExportKeys {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "MATRIX_EXPORT_PASSPHRASE")]
        passphrase_env: String,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "matrix_migration_tool=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match run_cli(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            tracing::error!("{error:#}");
            ExitCode::from(1)
        }
    }
}

fn run_cli(cli: Cli) -> Result<u8> {
    let _terminal = prompt::TerminalMode::capture()?;
    let runtime = tokio::runtime::Runtime::new().context("Start async runtime")?;
    let result = runtime.block_on(execute(cli));
    // Cancelled terminal readers may still block in the OS; never hang shutdown on stdin.
    runtime.shutdown_timeout(std::time::Duration::from_millis(100));
    result
}

async fn execute(cli: Cli) -> Result<u8> {
    if let Command::Init = cli.command {
        tokio::select! {
            result = setup::run(&cli.config, &cli.state_dir) => result?,
            signal = tokio::signal::ctrl_c() => {
                signal.context("Listen for interruption")?;
                anyhow::bail!("Setup interrupted; rerun init with the same paths to resume");
            }
        }
        return Ok(0);
    }
    let config = Config::read(&cli.config)?;
    let _lock = session::lock_state(&cli.state_dir)?;
    match cli.command {
        Command::Init => unreachable!("init handled before reading config"),
        Command::Migrate { report } => migrate_command(&config, &cli.state_dir, &report).await,
        Command::ExportKeys { output, passphrase_env } => {
            let export = export_command(&config, &cli.state_dir, &output, &passphrase_env);
            tokio::select! {
                result = export => result,
                signal = tokio::signal::ctrl_c() => {
                    signal.context("Listen for interruption")?;
                    anyhow::bail!("Export interrupted; rerun with the same config/state paths");
                }
            }
        }
    }
}

async fn migrate_command(
    config: &Config,
    state: &std::path::Path,
    path: &std::path::Path,
) -> Result<u8> {
    let mut report = Report::new(config.from.user_id.clone(), config.to.user_id.clone());
    let result = tokio::select! {
        result = migration::run(config, state, &mut report) => result,
        signal = tokio::signal::ctrl_c() => {
            signal.context("Listen for interruption")?;
            Err(anyhow::anyhow!("Interrupted; rerun with the same state directory"))
        }
    };
    if let Err(error) = result {
        report.fatal = Some(format!("{error:#}"));
    }
    session::write_json(path, &report).context("Save migration report")?;
    print_report(&report);
    eprintln!("Full report: {}", path.display());
    if report.fatal.is_some() {
        Ok(1)
    } else if report.complete() {
        Ok(0)
    } else {
        Ok(2)
    }
}

async fn export_command(
    config: &Config,
    state: &std::path::Path,
    output: &std::path::Path,
    passphrase_env: &str,
) -> Result<u8> {
    let store_passphrase = config.store_passphrase().await?;
    let passphrase = if std::env::var_os(passphrase_env).is_some() {
        secret(passphrase_env)?
    } else {
        prompt::hidden("Encrypted key export passphrase:").await?
    };
    let client = session::login(&config.to, &state.join("to"), &store_passphrase).await?;
    let changed = crypto::export(&client, output, &passphrase).await?;
    tracing::info!(path = %output.display(), changed, "Encrypted key export ready");
    Ok(0)
}

fn print_report(report: &Report) {
    eprintln!("{} -> {}", report.from, report.to);
    for preparation in &report.preparation {
        eprintln!("Preparation: {preparation:?}");
    }
    eprintln!("Direct chats: {:?}", report.direct);
    for room in &report.rooms {
        eprintln!(
            "{} ({}) [{}]\n  membership: {:?}\n  power: {:?}\n  tags: {:?}\n  keys: {:?}",
            room.room_id,
            room.name.as_deref().unwrap_or("unnamed"),
            if room.complete() { "complete" } else { "incomplete" },
            room.membership,
            room.power,
            room.tags,
            room.keys
        );
        eprintln!(
            "  history: {}/{} encrypted events decrypted, {} inaccessible, scan complete={}",
            room.history.decrypted_events,
            room.history.encrypted_events,
            room.history.inaccessible_events,
            room.history.scan_complete
        );
        for failure in &room.history.failures {
            eprintln!("  failure: {failure}");
        }
    }
    if let Some(fatal) = &report.fatal {
        eprintln!("Fatal: {fatal}");
    }
}
