//! Audit the source's full paginated timeline against destination server access and decryption.
//! Server access is checked before using an event; source ciphertext is never treated as proof
//! that the destination can retrieve history. Visibility state can change over a room's lifetime.

use std::collections::HashSet;

use anyhow::{Context, Result, ensure};
use matrix_sdk::{
    Client, Room,
    ruma::{RoomId, events::room::encrypted::OriginalSyncRoomEncryptedEvent, serde::Raw},
};
use serde_json::Value;

use crate::{api::Api, report::History};

/// Check all source-visible message-like events, including events older than destination join.
///
/// Args:
///     source: Authenticated source HTTP client.
///     destination: Authenticated destination HTTP client.
///     room: Joined destination SDK room with imported keys.
///     history: Mutable report retained even if pagination fails.
///
/// Returns:
///     Whether pagination completed successfully; per-event failures remain in the report.
pub async fn audit(
    source: &Api,
    destination: &Api,
    room: &Room,
    history: &mut History,
) -> Result<()> {
    let id = room.room_id().as_str();
    history.current_visibility = visibility(source, id).await?;
    backfill(destination, id).await.context("Backfill destination-visible history")?;
    let mut pages = Pages::new(source, id);
    let mut seen_events = HashSet::new();
    while let Some(chunk) = pages.next().await? {
        audit_chunk(destination, room, &chunk, history, &mut seen_events).await?;
    }
    history.scan_complete = true;
    Ok(())
}

async fn audit_chunk(
    destination: &Api,
    room: &Room,
    chunk: &[Value],
    history: &mut History,
    seen: &mut HashSet<String>,
) -> Result<()> {
    for event in chunk {
        if event.get("state_key").is_some() {
            continue;
        }
        let id = event["event_id"].as_str().context("History event has no event_id")?;
        if seen.insert(id.to_owned()) {
            check_event(destination, room, event, history).await;
        }
    }
    Ok(())
}

async fn check_event(api: &Api, room: &Room, event: &Value, history: &mut History) {
    history.checked_events += 1;
    let id = event["event_id"].as_str().unwrap_or_default();
    let encrypted = event["type"] == "m.room.encrypted";
    if encrypted {
        history.encrypted_events += 1;
    }
    let fetched = api.get(&["rooms", room.room_id().as_str(), "event", id]).await;
    let fetched = match fetched {
        Ok(Some(event)) => event,
        Ok(None) => {
            history.inaccessible_events += 1;
            history.failures.push(format!(
                concat!(
                    "{}: destination cannot fetch event (M_NOT_FOUND); ",
                    "history_visibility, federation or retention may limit access"
                ),
                id
            ));
            return;
        }
        Err(error) => {
            history.inaccessible_events += 1;
            history.failures.push(format!(
                "{id}: destination cannot fetch event: {error:#}; current history_visibility={:?}",
                history.current_visibility
            ));
            return;
        }
    };
    if is_redacted(&fetched) {
        history.redacted_events += 1;
        return;
    }
    if !encrypted {
        return;
    }
    record_decryption(room, &fetched, history).await;
}

async fn record_decryption(room: &Room, event: &Value, history: &mut History) {
    let id = event["event_id"].as_str().unwrap_or_default();
    let result = decrypt(room, event).await;
    match result {
        Ok(()) => history.decrypted_events += 1,
        Err(error) => {
            history.undecryptable_events += 1;
            history.failures.push(format!(
                concat!(
                    "{}: destination decryption: {:#}; ",
                    "acquire source keys via pairing, recovery or import and rerun"
                ),
                id, error
            ));
        }
    }
}

/// Attempt real SDK decryption and reject its successful-but-unable-to-decrypt response variant.
pub async fn decrypt(room: &Room, event: &Value) -> Result<()> {
    let raw: Raw<OriginalSyncRoomEncryptedEvent> =
        Raw::from_json_string(serde_json::to_string(event)?)?;
    let decrypted = room.decrypt_event(&raw, None).await?;
    ensure!(
        decrypted.encryption_info().is_some(),
        "Missing session key, invalid ciphertext or sender trust failure"
    );
    Ok(())
}

/// Request source key recovery by decrypting ciphertext; SDK queues missing-key requests.
pub async fn request_missing_keys(client: &Client, room_id: &RoomId) -> Result<()> {
    let api = Api::new(client)?;
    let room = client.get_room(room_id).context("Source room missing from SDK store")?;
    let mut pages = Pages::new(&api, room_id.as_str());
    while let Some(chunk) = pages.next().await? {
        for event in chunk {
            warm_key(&room, &event).await?;
        }
    }
    Ok(())
}

async fn warm_key(room: &Room, event: &Value) -> Result<()> {
    if event["type"] != "m.room.encrypted" || is_redacted(event) {
        return Ok(());
    }
    let raw = Raw::from_json_string(serde_json::to_string(event)?)?;
    let result = room.decrypt_event(&raw, None).await?;
    if result.encryption_info().is_none() {
        tracing::debug!(room = %room.room_id(), event = %event["event_id"],
            "Requested missing source key");
    }
    Ok(())
}

fn is_redacted(event: &Value) -> bool {
    event["unsigned"].get("redacted_because").is_some()
}

async fn visibility(api: &Api, id: &str) -> Result<Option<String>> {
    let state = api.get(&["rooms", id, "state", "m.room.history_visibility", ""]).await?;
    Ok(Some(
        state
            .and_then(|s| s["history_visibility"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "shared".to_owned()),
    ))
}

async fn backfill(api: &Api, id: &str) -> Result<()> {
    let mut pages = Pages::new(api, id);
    while pages.next().await?.is_some() {}
    Ok(())
}

struct Pages<'a> {
    api: &'a Api,
    room_id: &'a str,
    token: Option<String>,
    seen: HashSet<String>,
    finished: bool,
}

impl<'a> Pages<'a> {
    fn new(api: &'a Api, room_id: &'a str) -> Self {
        Self { api, room_id, token: None, seen: HashSet::new(), finished: false }
    }

    async fn next(&mut self) -> Result<Option<Vec<Value>>> {
        if self.finished {
            return Ok(None);
        }
        let mut query = vec![("dir", "b"), ("limit", "100")];
        if let Some(token) = self.token.as_deref() {
            query.push(("from", token));
        }
        let page = self.api.query(&["rooms", self.room_id, "messages"], &query).await?;
        let chunk = page["chunk"].as_array().context("messages response missing chunk array")?;
        match page["end"].as_str() {
            Some(next) => {
                self.finished = !self.seen.insert(next.to_owned());
                ensure!(
                    !self.finished || chunk.is_empty(),
                    "Server repeated history pagination token"
                );
                self.token = Some(next.to_owned());
            }
            None => self.finished = true,
        }
        Ok(Some(chunk.clone()))
    }
}
