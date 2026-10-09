//! Explicit SAS pairing with an existing device requires human comparison of seven emojis.
//! The SDK handles the protocol and secret requests; verification alone is not a key archive.

use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use matrix_sdk::{
    Client,
    encryption::verification::{SasState, SasVerification, Verification, format_emojis},
    ruma::{DeviceId, events::key::verification::VerificationMethod},
};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Pair this tool's device with a known existing device, skipping an already verified pair.
///
/// Args:
///     client: Authenticated, actively syncing SDK client.
///     device_id: Device ID from an existing trusted client of the same user.
///
/// Returns:
///     Whether a verification was performed rather than already being satisfied.
pub async fn pair(client: &Client, device_id: &str) -> Result<bool> {
    tokio::time::timeout(Duration::from_secs(300), pair_inner(client, device_id)).await.context(
        "Pairing timed out after five minutes; accept verification in the existing client",
    )?
}

async fn pair_inner(client: &Client, device_id: &str) -> Result<bool> {
    let device = pairing_device(client, device_id).await?;
    if device.is_verified() {
        return Ok(false);
    }
    let request = device.request_verification_with_methods(vec![VerificationMethod::SasV1]).await?;
    tracing::info!(%device_id, "Accept verification in your existing client");
    let sas = wait_for_sas(client, &request).await?;
    sas.accept().await?;
    verify_sas(&sas).await?;
    Ok(true)
}

async fn pairing_device(
    client: &Client,
    device_id: &str,
) -> Result<matrix_sdk::encryption::identities::Device> {
    let user = client.user_id().context("Not logged in")?;
    ensure!(
        client.device_id().map(|d| d.as_str()) != Some(device_id),
        "Cannot pair a device with itself"
    );
    client.encryption().request_user_identity(user).await?;
    client
        .encryption()
        .get_device(user, <&DeviceId>::from(device_id))
        .await?
        .with_context(|| format!("Device {device_id} was not found for {user}; check its ID"))
}

async fn wait_for_sas(
    client: &Client,
    request: &matrix_sdk::encryption::verification::VerificationRequest,
) -> Result<SasVerification> {
    loop {
        ensure!(!request.is_cancelled(), "Pairing cancelled: {:?}", request.cancel_info());
        if let Some(Verification::SasV1(sas)) =
            client.encryption().get_verification(request.other_user_id(), request.flow_id()).await
        {
            return Ok(sas);
        }
        if request.is_ready()
            && let Some(sas) = request.start_sas().await?
        {
            return Ok(sas);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn verify_sas(sas: &SasVerification) -> Result<()> {
    let mut confirmed = false;
    loop {
        match sas.state() {
            SasState::KeysExchanged { .. } => {
                if !confirmed {
                    confirm_emojis(sas).await?;
                    confirmed = true;
                }
            }
            SasState::Done { .. } => return Ok(()),
            SasState::Cancelled(info) => bail!("Verification cancelled: {}", info.reason()),
            SasState::Created { .. }
            | SasState::Started { .. }
            | SasState::Accepted { .. }
            | SasState::Confirmed => (),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn confirm_emojis(sas: &SasVerification) -> Result<()> {
    let emojis = sas.emoji().context("Peer did not support emoji verification")?;
    eprintln!(
        "Compare with your existing client:\n{}\nType yes only if all seven match:",
        format_emojis(emojis)
    );
    let mut answer = String::new();
    BufReader::new(tokio::io::stdin()).read_line(&mut answer).await?;
    if answer.trim() != "yes" {
        sas.cancel().await?;
        bail!("Emoji comparison rejected; pairing cancelled");
    }
    sas.confirm().await?;
    Ok(())
}
