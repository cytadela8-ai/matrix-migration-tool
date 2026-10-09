//! End-to-end tests use real Synapse federation, SAS, recovery, Megolm ciphertext and reruns.
//! Run with `cargo test --test federation -- --ignored --nocapture`; Docker and OpenSSL required.

#![recursion_limit = "256"]

#[path = "federation/bulk.rs"]
mod bulk;
#[path = "federation/imports.rs"]
mod imports;
mod support;

use std::{path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use matrix_migration_tool::{
    api::Api,
    report::{Outcome, Report},
    session,
};
use matrix_sdk::{
    Client,
    reqwest::Method,
    ruma::events::{
        key::verification::request::ToDeviceKeyVerificationRequestEvent,
        room::message::RoomMessageEventContent,
    },
};
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::support::{Server, bootstrap, create_room, migrate, save_config, state};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts two real Synapse containers and performs TLS federation"]
async fn migration_federates_recovers_keys_and_converges() -> Result<()> {
    let work = TempDir::new()?;
    let from_server = Server::start().await.expect("Test operation failed");
    let to_server = Server::start().await.expect("Test operation failed");
    let source = from_server
        .register("alice", &work.path().join("existing-source"))
        .await
        .expect("Test operation failed");
    let target = to_server
        .register("alice", &work.path().join("existing-target"))
        .await
        .expect("Test operation failed");
    let source_sync = session::start_sync(&source).await.expect("Test operation failed");
    let target_sync = session::start_sync(&target).await.expect("Test operation failed");
    bootstrap(&source).await.expect("Test operation failed");
    bootstrap(&target).await.expect("Test operation failed");
    let recovery_from =
        source.encryption().recovery().enable().await.expect("Test operation failed");
    let recovery_to = target.encryption().recovery().enable().await.expect("Test operation failed");
    let rooms = fixtures(&source, &target).await.expect("Test operation failed");
    let extra = additional_fixtures(&source, &target, &from_server, work.path(), &rooms)
        .await
        .expect("Test operation failed");
    source.encryption().backups().wait_for_steady_state().await.expect("Test operation failed");
    let peer = emulate_verification(&source);
    let mut from = from_server.account("alice", "TEST_FROM_PASSWORD");
    let mut to = to_server.account("alice", "TEST_TO_PASSWORD");
    from.verification_device = source.device_id().map(ToString::to_string);
    from.recovery_key_env = Some("TEST_FROM_RECOVERY".into());
    to.recovery_key_env = Some("TEST_TO_RECOVERY".into());
    save_config(&work.path().join("config.toml"), &from, &to)?;
    let first =
        migrate(work.path(), &recovery_from, &recovery_to, 2).await.expect("Test operation failed");
    assert_first(&first, &rooms).expect("First migration assertions");
    assert_additional(&first, &extra).expect("Additional room assertions");
    let to_user = target.user_id().context("No destination user")?.as_str();
    Api::new(&target)?
        .write(
            Method::PUT,
            &["user", to_user, "rooms", &rooms.shared, "tags", "custom.keep"],
            &json!({"order": 0.75}),
        )
        .await
        .expect("Test operation failed");
    assert_metadata(&source, &target, &rooms).await.expect("Test operation failed");
    let before =
        state(&source, &rooms.shared, "m.room.power_levels").await.expect("Test operation failed");
    let second =
        migrate(work.path(), &recovery_from, &recovery_to, 2).await.expect("Test operation failed");
    assert_converged(&first, &second, &rooms).expect("Rerun convergence assertions");
    assert_metadata(&source, &target, &rooms).await.expect("Test operation failed");
    assert_eq!(
        before,
        state(&source, &rooms.shared, "m.room.power_levels").await.expect("Test operation failed")
    );
    assert_backup_decrypts(&target, &rooms.shared, &rooms.encrypted_event)
        .await
        .expect("Test operation failed");
    assert_export_converges(&target, work.path()).await.expect("Test operation failed");
    source_sync.ensure_running()?;
    target_sync.ensure_running()?;
    peer.await.context("Existing SAS peer task failed")?;
    println!(
        "Verified SAS, federation, old encrypted history, backup, failures and rerun convergence"
    );
    Ok(())
}

struct Rooms {
    shared: String,
    restricted: String,
    blocked: String,
    creator: String,
    prejoined: String,
    encrypted_event: String,
}

struct ExtraRooms {
    plain: String,
    invited: String,
    no_invite: String,
    missing_keys: String,
}

async fn additional_fixtures(
    source: &Client,
    target: &Client,
    server: &Server,
    directory: &Path,
    rooms: &Rooms,
) -> Result<ExtraRooms> {
    let api = Api::new(source)?;
    let plain = create_room(
        source,
        json!({"name": "Paginated plaintext", "room_version": "11",
        "preset": "private_chat"}),
    )
    .await
    .expect("Test operation failed");
    for index in 0..105 {
        api.write(
            Method::PUT,
            &[
                "rooms",
                plain.room_id().as_str(),
                "send",
                "m.room.message",
                &format!("page-{index}"),
            ],
            &json!({"msgtype": "m.text", "body": format!("Message {index}")}),
        )
        .await
        .expect("Test operation failed");
    }
    let invited = create_room(
        target,
        json!({"name": "Source invitation", "room_version": "11",
        "preset": "private_chat"}),
    )
    .await
    .expect("Test operation failed");
    invited
        .invite_user_by_id(source.user_id().context("No source user")?)
        .await
        .expect("Test operation failed");
    let admin =
        server.register("admin", &directory.join("admin")).await.expect("Test operation failed");
    let admin_sync = session::start_sync(&admin).await.expect("Test operation failed");
    let no_invite = create_room(
        &admin,
        json!({"name": "Source lacks invite authority",
        "room_version": "11", "preset": "private_chat", "power_level_content_override": {
            "invite": 50
        }}),
    )
    .await
    .expect("Test operation failed");
    no_invite
        .invite_user_by_id(source.user_id().context("No source user")?)
        .await
        .expect("Test operation failed");
    source.join_room_by_id(no_invite.room_id()).await.expect("Test operation failed");
    let missing = create_room(source, room("Unavailable historical key", "shared", "11"))
        .await
        .expect("Test operation failed");
    let event = api
        .get(&["rooms", &rooms.shared, "event", &rooms.encrypted_event])
        .await
        .expect("Test operation failed")
        .context("Missing fixture ciphertext")?;
    api.write(
        Method::PUT,
        &["rooms", missing.room_id().as_str(), "send", "m.room.encrypted", "missing-key"],
        &event["content"],
    )
    .await
    .expect("Test operation failed");
    admin_sync.ensure_running()?;
    Ok(ExtraRooms {
        plain: plain.room_id().to_string(),
        invited: invited.room_id().to_string(),
        no_invite: no_invite.room_id().to_string(),
        missing_keys: missing.room_id().to_string(),
    })
}

fn assert_additional(report: &Report, extra: &ExtraRooms) -> Result<()> {
    let plain =
        report.rooms.iter().find(|r| r.room_id == extra.plain).context("Missing plain room")?;
    assert!(plain.complete(), "Plain history migration: {plain:?}");
    assert_eq!(plain.history.checked_events, 105);
    let invited =
        report.rooms.iter().find(|r| r.room_id == extra.invited).context("Missing invite")?;
    assert_eq!(invited.source_membership, "invite");
    assert!(matches!(invited.membership, Outcome::Skipped(_)));
    let denied = report
        .rooms
        .iter()
        .find(|r| r.room_id == extra.no_invite)
        .context("Missing denied room")?;
    assert!(matches!(denied.membership, Outcome::Failed(_)));
    let missing = report
        .rooms
        .iter()
        .find(|r| r.room_id == extra.missing_keys)
        .context("Missing key room")?;
    assert!(missing.history.undecryptable_events > 0, "Missing key was not reported: {missing:?}");
    Ok(())
}

async fn fixtures(source: &Client, target: &Client) -> Result<Rooms> {
    let shared = create_room(source, room("Encrypted shared", "shared", "11"))
        .await
        .expect("Test operation failed");
    let restricted = create_room(source, room("Encrypted joined", "joined", "11"))
        .await
        .expect("Test operation failed");
    let blocked = create_room(source, room("Banned destination", "shared", "11"))
        .await
        .expect("Test operation failed");
    let creator = create_room(source, room("Immutable creator", "shared", "12"))
        .await
        .expect("Test operation failed");
    let prejoined = create_room(source, room("Already joined and higher power", "shared", "11"))
        .await
        .expect("Test operation failed");
    let api = Api::new(source)?;
    let target_api = Api::new(target)?;
    let from = source.user_id().context("No source user")?.as_str();
    let to = target.user_id().context("No target user")?.as_str();
    let encrypted_event = shared
        .send(RoomMessageEventContent::text_plain("Before migration: encrypted hello"))
        .await
        .expect("Test operation failed")
        .response
        .event_id
        .to_string();
    restricted
        .send(RoomMessageEventContent::text_plain("Hidden before destination join"))
        .await
        .expect("Test operation failed");
    api.write(Method::POST, &["rooms", blocked.room_id().as_str(), "ban"], &json!({"user_id": to}))
        .await
        .expect("Test operation failed");
    api.write(
        Method::PUT,
        &["user", from, "rooms", shared.room_id().as_str(), "tags", "m.favourite"],
        &json!({"order": 0.25}),
    )
    .await
    .expect("Test operation failed");
    api.write(
        Method::PUT,
        &["user", from, "account_data", "m.direct"],
        &json!({to: [shared.room_id()]}),
    )
    .await
    .expect("Test operation failed");
    target_api
        .write(
            Method::PUT,
            &["user", to, "account_data", "m.direct"],
            &json!({from: ["!retained:example.org"]}),
        )
        .await
        .expect("Test operation failed");
    shared
        .send(RoomMessageEventContent::text_plain("Another encrypted hello"))
        .await
        .expect("Test operation failed");
    prejoined
        .invite_user_by_id(target.user_id().context("No target user")?)
        .await
        .expect("Test operation failed");
    target.join_room_by_id(prejoined.room_id()).await.expect("Test operation failed");
    let mut power = state(source, prejoined.room_id().as_str(), "m.room.power_levels")
        .await
        .expect("Test operation failed");
    power["users"][to] = json!(100);
    power["users"][from] = json!(50);
    api.write(
        Method::PUT,
        &["rooms", prejoined.room_id().as_str(), "state", "m.room.power_levels", ""],
        &power,
    )
    .await
    .expect("Test operation failed");
    Ok(Rooms {
        shared: shared.room_id().to_string(),
        restricted: restricted.room_id().to_string(),
        blocked: blocked.room_id().to_string(),
        creator: creator.room_id().to_string(),
        prejoined: prejoined.room_id().to_string(),
        encrypted_event,
    })
}

fn room(name: &str, visibility: &str, version: &str) -> Value {
    json!({"name": name, "preset": "private_chat", "room_version": version,
    "initial_state": [
        {"type": "m.room.encryption", "state_key": "",
            "content": {"algorithm": "m.megolm.v1.aes-sha2"}},
        {"type": "m.room.history_visibility", "state_key": "",
            "content": {"history_visibility": visibility}}
    ]})
}

fn emulate_verification(client: &Client) -> tokio::task::JoinHandle<()> {
    let client = client.clone();
    tokio::spawn(async move {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        client.add_event_handler(move |event: ToDeviceKeyVerificationRequestEvent| {
            let sender = sender.clone();
            async move {
                sender.send(event).await.expect("Send test verification request");
            }
        });
        let event = receiver.recv().await.expect("Receive verification request");
        let request = client
            .encryption()
            .get_verification_request(&event.sender, &event.content.transaction_id)
            .await
            .expect("Verification request exists");
        request.accept().await.expect("Accept test request");
        loop {
            if let Some(matrix_sdk::encryption::verification::Verification::SasV1(sas)) =
                client.encryption().get_verification(&event.sender, request.flow_id()).await
            {
                sas.accept().await.expect("Accept SAS");
                while sas.emoji().is_none() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                sas.confirm().await.expect("Confirm test SAS");
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
}

fn assert_first(report: &Report, rooms: &Rooms) -> Result<()> {
    assert_eq!(report.rooms.len(), 9);
    ensure!(
        !report.preparation.iter().any(Outcome::failed),
        "Preparation failed: {:?}",
        report.preparation
    );
    let shared =
        report.rooms.iter().find(|r| r.room_id == rooms.shared).context("Missing shared room")?;
    assert!(shared.complete(), "Shared room failed: {shared:?}");
    assert_eq!(shared.history.decrypted_events, 2);
    let restricted = report
        .rooms
        .iter()
        .find(|r| r.room_id == rooms.restricted)
        .context("Missing restricted room")?;
    assert!(
        restricted.history.inaccessible_events > 0,
        "Restricted history was not reported: {restricted:?}"
    );
    let blocked =
        report.rooms.iter().find(|r| r.room_id == rooms.blocked).context("Missing banned room")?;
    assert!(blocked.membership.failed());
    let creator =
        report.rooms.iter().find(|r| r.room_id == rooms.creator).context("Missing creator room")?;
    assert!(creator.power.failed());
    assert!(!creator.membership.failed());
    Ok(())
}

fn assert_converged(first: &Report, second: &Report, rooms: &Rooms) -> Result<()> {
    assert_eq!(first.from_device, second.from_device);
    assert_eq!(first.to_device, second.to_device);
    assert_eq!(first.to_rooms_after, second.to_rooms_after);
    assert!(matches!(second.direct, Outcome::Unchanged(_)));
    for id in [&rooms.shared, &rooms.prejoined] {
        let room = second.rooms.iter().find(|r| &r.room_id == id).context("Missing rerun room")?;
        assert!(matches!(room.membership, Outcome::Unchanged(_)), "{room:?}");
        assert!(matches!(room.power, Outcome::Unchanged(_)), "{room:?}");
        assert!(matches!(room.tags, Outcome::Unchanged(_)), "{room:?}");
        assert!(matches!(room.keys, Outcome::Unchanged(_)), "{room:?}");
    }
    Ok(())
}

async fn assert_metadata(source: &Client, target: &Client, rooms: &Rooms) -> Result<()> {
    let from = source.user_id().context("No source user")?.as_str();
    let to = target.user_id().context("No target user")?.as_str();
    let power =
        state(source, &rooms.shared, "m.room.power_levels").await.expect("Test operation failed");
    assert_eq!(power["users"][to], power["users"][from]);
    let api = Api::new(target)?;
    let tags = api
        .get(&["user", to, "rooms", &rooms.shared, "tags"])
        .await
        .expect("Test operation failed")
        .context("Missing tags")?;
    assert_eq!(tags["tags"]["m.favourite"]["order"], 0.25);
    assert_eq!(tags["tags"]["custom.keep"]["order"], 0.75);
    let direct = api
        .get(&["user", to, "account_data", "m.direct"])
        .await
        .expect("Test operation failed")
        .context("Missing m.direct")?;
    assert_eq!(direct[to], json!([rooms.shared]));
    assert_eq!(direct[from], json!(["!retained:example.org"]));
    let power = state(source, &rooms.prejoined, "m.room.power_levels")
        .await
        .expect("Test operation failed");
    assert_eq!(power["users"][to], 100);
    Ok(())
}

async fn assert_backup_decrypts(client: &Client, id: &str, event_id: &str) -> Result<()> {
    let room_id = matrix_sdk::ruma::RoomId::parse(id)?;
    client
        .encryption()
        .backups()
        .download_room_keys_for_room(&room_id)
        .await
        .expect("Test operation failed");
    let api = Api::new(client)?;
    let event = api
        .get(&["rooms", id, "event", event_id])
        .await
        .expect("Test operation failed")
        .context("Destination history missing")?;
    let room = client.get_room(&room_id).context("Destination room missing")?;
    matrix_migration_tool::history::decrypt(&room, &event).await
}

async fn assert_export_converges(client: &Client, directory: &Path) -> Result<()> {
    let path = directory.join("destination.keys");
    assert!(
        matrix_migration_tool::crypto::export(client, &path, "test-export-passphrase")
            .await
            .expect("Test operation failed")
    );
    let original = std::fs::read(&path)?;
    assert!(
        !matrix_migration_tool::crypto::export(client, &path, "test-export-passphrase")
            .await
            .expect("Test operation failed")
    );
    assert_eq!(original, std::fs::read(&path)?);
    assert!(
        matrix_migration_tool::crypto::export(client, &path, "wrong-passphrase").await.is_err()
    );
    assert_eq!(original, std::fs::read(&path)?);
    Ok(())
}
