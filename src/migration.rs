//! Migration converges against live server state and isolates failures to individual operations.
//! It never leaves source rooms, changes history visibility or lowers destination privileges.

use std::{collections::BTreeSet, path::Path, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use matrix_sdk::{Client, RoomState, reqwest::Method, ruma::RoomId};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    api::Api,
    config::Config,
    crypto, history, policy,
    report::{Outcome, Report, RoomReport},
    session,
};

/// Run migration, retaining partial results in the supplied report if a fatal step fails.
///
/// Args:
///     config: Validated configuration for two different Matrix accounts.
///     state: Private directory containing persistent account devices and keys.
///     report: Mutable report; callers save it even when this function returns an error.
///
/// Returns:
///     Success after all rooms were attempted; inspect report.complete() for partial failures.
pub async fn run(config: &Config, state: &Path, report: &mut Report) -> Result<()> {
    let connections = Connections::open(config, state, report).await?;
    report.preparation.extend(crypto::prepare(&connections.from.client, &config.from).await);
    report.preparation.extend(crypto::prepare(&connections.to.client, &config.to).await);
    let accounts = connections.accounts();
    for index in 0..report.rooms.len() {
        connections.ensure_sync()?;
        tracing::info!(room = %report.rooms[index].room_id, "Migrating room");
        migrate_room(&accounts, &mut report.rooms[index], &connections.passphrase).await;
        session::write_json(&state.join("progress.json"), report)?;
    }
    finish(&accounts, report).await?;
    connections.ensure_sync()?;
    Ok(())
}

struct Connections {
    from: session::Connected,
    to: session::Connected,
    passphrase: Zeroizing<String>,
}

impl Connections {
    async fn open(config: &Config, state: &Path, report: &mut Report) -> Result<Self> {
        config.validate()?;
        let passphrase = config.store_passphrase().await?;
        let from = session::Connected::open(&config.from, &state.join("from"), &passphrase).await?;
        report.from_device = from.client.device_id().map(ToString::to_string);
        report.from_rooms = joined_rooms(&from.api).await?;
        report.rooms = discover_rooms(&from.client, &report.from_rooms);
        let to = session::Connected::open(&config.to, &state.join("to"), &passphrase).await?;
        report.to_device = to.client.device_id().map(ToString::to_string);
        report.to_rooms_before = joined_rooms(&to.api).await?;
        Ok(Self { from, to, passphrase })
    }

    fn accounts(&self) -> Accounts<'_> {
        Accounts {
            from: &self.from.client,
            to: &self.to.client,
            from_api: &self.from.api,
            to_api: &self.to.api,
        }
    }

    fn ensure_sync(&self) -> Result<()> {
        self.from.sync.ensure_running()?;
        self.to.sync.ensure_running()
    }
}

async fn finish(accounts: &Accounts<'_>, report: &mut Report) -> Result<()> {
    report.direct = outcome(copy_direct(accounts).await);
    report.preparation.push(match crypto::flush_backup(accounts.to).await {
        Ok(true) => Outcome::Unchanged("Destination backup upload completed".into()),
        Ok(false) => Outcome::Unchanged(
            concat!(
                "Keys retained in destination tool device; backup not enabled. ",
                "Use export-keys to import in another client"
            )
            .into(),
        ),
        Err(error) => Outcome::Failed(format!("Destination key backup: {error:#}")),
    });
    report.to_rooms_after = joined_rooms(accounts.to_api).await?;
    Ok(())
}

struct Accounts<'a> {
    from: &'a Client,
    to: &'a Client,
    from_api: &'a Api,
    to_api: &'a Api,
}

fn discover_rooms(client: &Client, joined: &[String]) -> Vec<RoomReport> {
    let mut ids: BTreeSet<String> = joined.iter().cloned().collect();
    ids.extend(client.rooms().iter().map(|r| r.room_id().to_string()));
    let mut reports = Vec::new();
    for id in ids {
        let room = RoomId::parse(&id).ok().and_then(|id| client.get_room(&id));
        let membership = if joined.contains(&id) {
            "join"
        } else {
            match room.as_ref().map(|room| room.state()) {
                Some(RoomState::Joined) => "join",
                Some(RoomState::Invited) => "invite",
                Some(RoomState::Left) | None => "leave",
                Some(RoomState::Knocked) => "knock",
                Some(RoomState::Banned) => "ban",
            }
        };
        let name = room.and_then(|r| r.name());
        reports.push(RoomReport::new(id, name, membership.into()));
    }
    reports
}

async fn migrate_room(accounts: &Accounts<'_>, report: &mut RoomReport, passphrase: &str) {
    if report.source_membership != "join" {
        report.membership = Outcome::Skipped(format!(
            "Source membership is {}; source cannot invite from this room",
            report.source_membership
        ));
        return;
    }
    let result = ensure_membership(accounts, &report.room_id).await;
    report.membership = outcome(result);
    if report.membership.failed() {
        return;
    }
    report.power = outcome(copy_power(accounts, &report.room_id).await);
    report.tags = outcome(copy_tags(accounts, &report.room_id).await);
    let result = migrate_history(accounts, report, passphrase).await;
    if let Err(error) = result {
        report.history.failures.push(format!("History scan: {error:#}"));
    }
}

async fn ensure_membership(accounts: &Accounts<'_>, id: &str) -> Result<Outcome> {
    if joined_rooms(accounts.to_api).await?.iter().any(|room| room == id) {
        return Ok(Outcome::Unchanged("Destination already joined".into()));
    }
    invite_if_needed(accounts, id).await?;
    let room_id = RoomId::parse(id)?;
    accounts.to.join_room_by_id(&room_id).await.context("Destination failed to join invitation")?;
    Ok(Outcome::Changed("Invited if needed and joined destination".into()))
}

async fn invite_if_needed(accounts: &Accounts<'_>, id: &str) -> Result<()> {
    let to_user = accounts.to.user_id().context("Destination not logged in")?.as_str();
    let member = accounts.from_api.get(&["rooms", id, "state", "m.room.member", to_user]).await?;
    let membership = member.as_ref().and_then(|m| m["membership"].as_str());
    if membership == Some("ban") {
        bail!("Destination is banned; ask a room administrator to unban it");
    }
    if membership == Some("invite") {
        return Ok(());
    }
    accounts
        .from_api
        .write(Method::POST, &["rooms", id, "invite"], &json!({"user_id": to_user}))
        .await
        .context("Source cannot invite destination; check invite power level and room restrictions")
}

async fn copy_power(accounts: &Accounts<'_>, id: &str) -> Result<Outcome> {
    let from = accounts.from.user_id().context("Source not logged in")?.as_str();
    let to = accounts.to.user_id().context("Destination not logged in")?.as_str();
    let power = read_power(accounts.from_api, id, from, to).await?;
    if let Some(outcome) = power.creator_outcome {
        return Ok(outcome);
    }
    let Some(updated) = policy::increase_power(&power.content, from, to)? else {
        return Ok(Outcome::Unchanged("Destination power already equals or exceeds source".into()));
    };
    accounts
        .from_api
        .write(Method::PUT, &["rooms", id, "state", "m.room.power_levels", ""], &updated)
        .await
        .context("Source cannot grant its power level; ask a room administrator")?;
    Ok(Outcome::Changed("Increased destination power to source level".into()))
}

struct Power {
    content: Value,
    creator_outcome: Option<Outcome>,
}

async fn read_power(api: &Api, id: &str, from: &str, to: &str) -> Result<Power> {
    let create = api
        .get(&["rooms", id, "state", "m.room.create", ""])
        .await?
        .context("Room create state missing")?;
    let mut creator_outcome = None;
    if create["room_version"].as_str().unwrap_or("1").parse::<u64>().unwrap_or(0) >= 12 {
        creator_outcome = creator_privileges(api, id, &create, from, to).await?;
    }
    let content = api.get(&["rooms", id, "state", "m.room.power_levels", ""]).await?;
    let content = if let Some(content) = content {
        content
    } else {
        let creator = room_creator(api, id).await?;
        json!({"users": {creator: 100}})
    };
    Ok(Power { content, creator_outcome })
}

async fn room_creator(api: &Api, id: &str) -> Result<String> {
    let state = api.get(&["rooms", id, "state"]).await?.context("Room state missing")?;
    let creator = state
        .as_array()
        .context("State must be an array")?
        .iter()
        .find(|event| event["type"] == "m.room.create")
        .context("Create event missing")?;
    Ok(creator["sender"].as_str().context("Create event sender missing")?.to_owned())
}

async fn creator_privileges(
    api: &Api,
    id: &str,
    create: &Value,
    from: &str,
    to: &str,
) -> Result<Option<Outcome>> {
    let creator = room_creator(api, id).await?;
    let additional = create["additional_creators"].as_array().cloned().unwrap_or_default();
    let from_creator = creator == from || additional.contains(&json!(from));
    let to_creator = creator == to || additional.contains(&json!(to));
    if to_creator {
        return Ok(Some(Outcome::Unchanged("Destination has immutable creator privileges".into())));
    }
    ensure!(
        !from_creator,
        "Room creator has immutable infinite power; cannot transfer to another user"
    );
    Ok(None)
}

async fn copy_tags(accounts: &Accounts<'_>, id: &str) -> Result<Outcome> {
    let from = accounts.from.user_id().context("Source not logged in")?.as_str();
    let to = accounts.to.user_id().context("Destination not logged in")?.as_str();
    let source = read_tags(accounts.from_api, from, id).await?;
    let destination = read_tags(accounts.to_api, to, id).await?;
    let count = write_tags(accounts.to_api, to, id, &source, &destination).await?;
    if count == 0 {
        return Ok(Outcome::Unchanged("Tags already copied".into()));
    }
    Ok(Outcome::Changed(format!("Copied {count} tags; retained destination-only tags")))
}

async fn read_tags(api: &Api, user: &str, id: &str) -> Result<serde_json::Map<String, Value>> {
    let value =
        api.get(&["user", user, "rooms", id, "tags"]).await?.unwrap_or_else(|| json!({"tags": {}}));
    value["tags"].as_object().cloned().context("Room tags must be an object")
}

async fn write_tags(
    api: &Api,
    user: &str,
    id: &str,
    source: &serde_json::Map<String, Value>,
    destination: &serde_json::Map<String, Value>,
) -> Result<usize> {
    let mut count = 0;
    for (name, content) in source {
        if destination.get(name) != Some(content) {
            api.write(Method::PUT, &["user", user, "rooms", id, "tags", name], content).await?;
            count += 1;
        }
    }
    Ok(count)
}

async fn copy_direct(accounts: &Accounts<'_>) -> Result<Outcome> {
    let from = accounts.from.user_id().context("Source not logged in")?.as_str();
    let to = accounts.to.user_id().context("Destination not logged in")?.as_str();
    let source = accounts
        .from_api
        .get(&["user", from, "account_data", "m.direct"])
        .await?
        .unwrap_or_else(|| json!({}));
    let destination = accounts
        .to_api
        .get(&["user", to, "account_data", "m.direct"])
        .await?
        .unwrap_or_else(|| json!({}));
    let merged = policy::merge_direct(&destination, &source)?;
    if merged == destination {
        return Ok(Outcome::Unchanged("m.direct already merged".into()));
    }
    accounts.to_api.write(Method::PUT, &["user", to, "account_data", "m.direct"], &merged).await?;
    Ok(Outcome::Changed("Merged m.direct and retained destination-only entries".into()))
}

async fn migrate_history(
    accounts: &Accounts<'_>,
    report: &mut RoomReport,
    passphrase: &str,
) -> Result<()> {
    let room_id = RoomId::parse(&report.room_id)?;
    let encryption = accounts
        .from_api
        .get(&["rooms", &report.room_id, "state", "m.room.encryption", ""])
        .await?;
    if encryption.is_some() {
        download_keys(accounts.from, &room_id, report).await;
        history::request_missing_keys(accounts.from, &room_id).await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        report.keys = transfer_outcome(
            crypto::transfer(accounts.from, accounts.to, &room_id, passphrase).await,
        );
    } else {
        report.keys = Outcome::Unchanged("Room is unencrypted".into());
    }
    let room = accounts.to.get_room(&room_id).context("Destination room missing from SDK store")?;
    history::audit(accounts.from_api, accounts.to_api, &room, &mut report.history).await
}

async fn download_keys(client: &Client, id: &RoomId, report: &mut RoomReport) {
    if !client.encryption().backups().are_enabled().await {
        return;
    }
    if let Err(error) = client.encryption().backups().download_room_keys_for_room(id).await {
        if error.client_api_error_kind() == Some(&matrix_sdk::ruma::api::error::ErrorKind::NotFound)
        {
            tracing::debug!(room = %id, "Source backup has no sessions for this room");
        } else {
            report.history.failures.push(format!("Source backup download: {error:#}"));
        }
    }
}

fn transfer_outcome(result: Result<(usize, usize)>) -> Outcome {
    match result {
        Ok((0, _)) => Outcome::Unchanged(
            "No stored source keys; history audit determines whether any are needed".into(),
        ),
        Ok((total, 0)) => {
            Outcome::Unchanged(format!("{total} available sessions already imported"))
        }
        Ok((total, imported)) => Outcome::Changed(format!(
            "Imported {imported} of {total} available sessions into destination device"
        )),
        Err(error) => Outcome::Failed(format!("Key transfer: {error:#}")),
    }
}

fn outcome(result: Result<Outcome>) -> Outcome {
    match result {
        Ok(outcome) => outcome,
        Err(error) => Outcome::Failed(format!("{error:#}")),
    }
}

async fn joined_rooms(api: &Api) -> Result<Vec<String>> {
    let response = api.get(&["joined_rooms"]).await?.context("joined_rooms endpoint missing")?;
    let mut rooms = Vec::new();
    for id in response["joined_rooms"].as_array().context("joined_rooms must be an array")? {
        rooms.push(id.as_str().context("Room ID must be a string")?.to_owned());
    }
    rooms.sort();
    Ok(rooms)
}
