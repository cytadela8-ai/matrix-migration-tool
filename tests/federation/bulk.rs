//! Large migrations cross pagination boundaries with real plaintext and Megolm payloads.
//! File imports supply source keys; each case reruns against the same persistent devices.

use std::{collections::BTreeSet, path::Path};

use anyhow::{Context, Result, ensure};
use matrix_migration_tool::{
    api::Api,
    report::{Outcome, Report},
    session,
};
use matrix_sdk::{Client, Room, reqwest::Method, ruma::serde::Raw};
use serde_json::{Value, json};

use crate::support::{self, Server, bootstrap, create_room, migrate, save_config, state};

const MESSAGES: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    PlainShared,
    EncryptedShared,
    RotatedPublic,
    PlainJoined,
    RedactedEncrypted,
}

impl Kind {
    fn encrypted(self) -> bool {
        match self {
            Self::PlainShared | Self::PlainJoined => false,
            Self::EncryptedShared | Self::RotatedPublic | Self::RedactedEncrypted => true,
        }
    }

    fn visibility(self) -> &'static str {
        match self {
            Self::PlainJoined => "joined",
            Self::RotatedPublic => "world_readable",
            Self::PlainShared | Self::EncryptedShared | Self::RedactedEncrypted => "shared",
        }
    }
}

struct Fixture {
    kind: Kind,
    room: Room,
    messages: Vec<(String, String)>,
    redacted: BTreeSet<String>,
    sessions: BTreeSet<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts two real Synapse containers and migrates 1,000 messages"]
async fn thousand_messages_complete_and_converge() -> Result<()> {
    run(true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts two real Synapse containers and audits 200 restricted historical messages"]
async fn thousand_messages_isolate_restricted_history_and_converge() -> Result<()> {
    run(false).await
}

async fn run(prejoin_restricted: bool) -> Result<()> {
    let work = tempfile::tempdir().expect("Create bulk fixture directory");
    let from_server = Server::start().await.expect("Start bulk Synapse server");
    let to_server = Server::start().await.expect("Start bulk Synapse server");
    let source = from_server
        .register("bulk", &work.path().join("existing-source"))
        .await
        .expect("Register source");
    let target = to_server
        .register("bulk", &work.path().join("existing-target"))
        .await
        .expect("Register destination");
    let source_sync = session::start_sync(&source).await.expect("Start source sync");
    let target_sync = session::start_sync(&target).await.expect("Start destination sync");
    bootstrap(&source).await.expect("Bootstrap source encryption");
    bootstrap(&target).await.expect("Bootstrap destination encryption");
    let recovery =
        target.encryption().recovery().enable().await.expect("Enable destination recovery");
    let fixtures =
        fixtures(&source, &target, prejoin_restricted).await.expect("Populate bulk rooms");
    let mut from = from_server.account("bulk", "TEST_FROM_PASSWORD");
    let mut to = to_server.account("bulk", "TEST_TO_PASSWORD");
    let export = work.path().join("source.keys");
    source
        .encryption()
        .export_room_keys(export.clone(), support::IMPORT_PASSPHRASE, |_| true)
        .await
        .expect("Export source fixture keys");
    from.import_keys = Some(export.to_str().expect("UTF8 test path").into());
    from.import_passphrase_env = Some("TEST_IMPORT_PASSPHRASE".into());
    to.recovery_key_env = Some("TEST_TO_RECOVERY".into());
    save_config(&work.path().join("config.toml"), &from, &to).expect("Save bulk config");
    let expected_exit = if prejoin_restricted { 0 } else { 2 };
    let first = migrate(work.path(), "", &recovery, expected_exit).await?;
    assert_history(&first, &fixtures, prejoin_restricted)?;
    assert!(matches!(first.preparation[0], Outcome::Changed(_)), "{:?}", first.preparation);
    assert_memberships(&source, &target, &fixtures).await.expect("Verify memberships");
    let second = migrate(work.path(), "", &recovery, expected_exit).await?;
    assert_history(&second, &fixtures, prejoin_restricted)?;
    assert_convergence(&first, &second);
    verify_payloads(&to, work.path(), &fixtures, prejoin_restricted).await?;
    source_sync.ensure_running().expect("Source sync remains running");
    target_sync.ensure_running().expect("Destination sync remains running");
    println!("Verified 1,000 messages / five rooms; prejoined restricted={prejoin_restricted}");
    Ok(())
}

async fn fixtures(source: &Client, target: &Client, prejoin: bool) -> Result<Vec<Fixture>> {
    let mut fixtures = Vec::new();
    for kind in [
        Kind::PlainShared,
        Kind::EncryptedShared,
        Kind::RotatedPublic,
        Kind::PlainJoined,
        Kind::RedactedEncrypted,
    ] {
        let room = create_room(source, room_content(kind)).await.expect("Create bulk room");
        if kind == Kind::PlainJoined && prejoin {
            room.invite_user_by_id(target.user_id().context("Missing target identity")?).await?;
            target.join_room_by_id(room.room_id()).await?;
        }
        let mut fixture = Fixture {
            kind,
            room,
            messages: Vec::new(),
            redacted: BTreeSet::new(),
            sessions: BTreeSet::new(),
        };
        populate(source, &mut fixture).await?;
        fixtures.push(fixture);
    }
    Ok(fixtures)
}

fn room_content(kind: Kind) -> Value {
    let mut initial_state = vec![json!({"type": "m.room.history_visibility", "state_key": "",
        "content": {"history_visibility": kind.visibility()}})];
    if kind.encrypted() {
        initial_state.push(json!({"type": "m.room.encryption", "state_key": "",
            "content": {"algorithm": "m.megolm.v1.aes-sha2"}}));
    }
    json!({"name": format!("Bulk {kind:?}"), "room_version": "11",
        "preset": "private_chat", "initial_state": initial_state})
}

async fn rotate_if_due(fixture: &Fixture, index: usize) -> Result<()> {
    if fixture.kind == Kind::RotatedPublic && index > 0 && index.is_multiple_of(50) {
        fixture.room.discard_room_key().await.context("Rotate bulk Megolm session")?;
    }
    Ok(())
}

async fn populate(source: &Client, fixture: &mut Fixture) -> Result<()> {
    let api = Api::new(source).expect("Create source fixture API");
    let id = fixture.room.room_id().as_str();
    for index in 0..MESSAGES {
        rotate_if_due(fixture, index).await?;
        let body = format!("{:?} message {index:04}: café 🦀", fixture.kind);
        let event_id = fixture
            .room
            .send(matrix_sdk::ruma::events::room::message::RoomMessageEventContent::text_plain(
                &body,
            ))
            .await
            .expect("Send bulk fixture message")
            .response
            .event_id
            .to_string();
        if fixture.kind.encrypted() && index.is_multiple_of(50) {
            let event = api
                .get(&["rooms", id, "event", &event_id])
                .await
                .expect("Read fixture ciphertext")
                .expect("Fixture event exists");
            ensure!(event["type"] == "m.room.encrypted", "Fixture must contain real ciphertext");
            fixture.sessions.insert(
                event["content"]["session_id"]
                    .as_str()
                    .expect("Fixture ciphertext has a Megolm session ID")
                    .to_owned(),
            );
        }
        if fixture.kind == Kind::RedactedEncrypted && index.is_multiple_of(50) {
            api.write(
                Method::PUT,
                &["rooms", id, "redact", &event_id, &format!("redact-{index}")],
                &json!({"reason": "Bulk redaction fixture"}),
            )
            .await
            .expect("Redact bulk fixture message");
            fixture.redacted.insert(event_id.clone());
        }
        fixture.messages.push((event_id, body));
    }
    if fixture.kind == Kind::RotatedPublic {
        assert_eq!(fixture.sessions.len(), 4, "Four distinct Megolm sessions required");
    }
    Ok(())
}

fn assert_history(report: &Report, fixtures: &[Fixture], prejoined: bool) -> Result<()> {
    assert_eq!(report.complete(), prejoined, "{report:?}");
    assert_eq!(report.rooms.len(), 5);
    assert!(!report.preparation.iter().any(Outcome::failed), "{:?}", report.preparation);
    let mut checked_messages = 0;
    for fixture in fixtures {
        let room = report
            .rooms
            .iter()
            .find(|r| r.room_id == fixture.room.room_id().as_str())
            .context("Fixture absent from report")?;
        let restricted = fixture.kind == Kind::PlainJoined && !prejoined;
        assert_eq!(room.complete(), !restricted, "{room:?}");
        assert!(!room.membership.failed() && !room.power.failed() && !room.tags.failed());
        assert!(!room.keys.failed());
        assert!(room.history.scan_complete, "{room:?}");
        assert_eq!(room.history.current_visibility.as_deref(), Some(fixture.kind.visibility()));
        assert_eq!(room.history.checked_events, MESSAGES + fixture.redacted.len(), "{room:?}");
        assert_eq!(room.history.redacted_events, fixture.redacted.len(), "{room:?}");
        assert_eq!(
            room.history.encrypted_events,
            if fixture.kind.encrypted() { MESSAGES } else { 0 },
            "{room:?}"
        );
        assert_eq!(
            room.history.decrypted_events,
            if fixture.kind.encrypted() { MESSAGES - fixture.redacted.len() } else { 0 },
            "{room:?}"
        );
        assert_eq!(room.history.undecryptable_events, 0, "{room:?}");
        let inaccessible = if restricted { MESSAGES } else { 0 };
        assert_eq!(room.history.inaccessible_events, inaccessible, "{room:?}");
        assert_eq!(room.history.failures.len(), inaccessible, "{room:?}");
        if restricted {
            assert_restricted_events(&room.history.failures, fixture);
        }
        checked_messages += room.history.checked_events - fixture.redacted.len();
    }
    assert_eq!(checked_messages, 1000);
    Ok(())
}

fn assert_restricted_events(failures: &[String], fixture: &Fixture) {
    for (event_id, _) in &fixture.messages {
        assert!(
            failures.iter().any(|failure| failure.starts_with(&format!("{event_id}:"))),
            "Restricted event {event_id} must have an explicit failure"
        );
    }
}

fn assert_convergence(first: &Report, second: &Report) {
    assert_eq!(first.from_device, second.from_device);
    assert_eq!(first.to_device, second.to_device);
    assert_eq!(first.to_rooms_after, second.to_rooms_after);
    assert!(matches!(second.direct, Outcome::Unchanged(_)));
    for room in &second.rooms {
        for operation in [&room.membership, &room.power, &room.tags, &room.keys] {
            assert!(matches!(operation, Outcome::Unchanged(_)), "{room:?}");
        }
    }
    assert!(second.preparation.iter().all(|o| matches!(o, Outcome::Unchanged(_))));
}

async fn assert_memberships(source: &Client, target: &Client, fixtures: &[Fixture]) -> Result<()> {
    let source_api = Api::new(source)?;
    let target_api = Api::new(target)?;
    for fixture in fixtures {
        let id = fixture.room.room_id().as_str();
        for (api, client) in [(&source_api, source), (&target_api, target)] {
            let user = client.user_id().expect("Fixture identity exists").as_str();
            let member = api
                .get(&["rooms", id, "state", "m.room.member", user])
                .await?
                .context("Missing membership")?;
            assert_eq!(member["membership"], "join");
        }
        let power = state(source, id, "m.room.power_levels").await?;
        assert_eq!(
            power["users"][target.user_id().expect("Destination identity exists").as_str()],
            100
        );
        assert_eq!(
            state(source, id, "m.room.history_visibility").await?["history_visibility"],
            fixture.kind.visibility()
        );
    }
    Ok(())
}

async fn verify_payloads(
    account: &matrix_migration_tool::config::Account,
    directory: &Path,
    fixtures: &[Fixture],
    prejoined: bool,
) -> Result<()> {
    let destination =
        session::Connected::open(account, &directory.join("state/to"), support::STORE_PASSPHRASE)
            .await?;
    for fixture in fixtures {
        let id = fixture.room.room_id();
        let room = destination.client.get_room(id).expect("Destination room exists");
        for (event_id, body) in &fixture.messages {
            if fixture.kind == Kind::PlainJoined && !prejoined {
                continue;
            }
            let event = destination
                .api
                .get(&["rooms", id.as_str(), "event", event_id])
                .await?
                .expect("Destination can retrieve migrated event");
            if fixture.redacted.contains(event_id) {
                assert!(event["unsigned"].get("redacted_because").is_some());
                continue;
            }
            verify_message(&room, event, fixture.kind, body, event_id)
                .await
                .expect("Preserve destination message payload");
        }
    }
    destination.sync.ensure_running()
}

async fn verify_message(
    room: &Room,
    event: Value,
    kind: Kind,
    expected: &str,
    event_id: &str,
) -> Result<()> {
    let event = if kind.encrypted() {
        let raw = Raw::from_json_string(event.to_string())?;
        let decrypted = room.decrypt_event(&raw, None).await?;
        ensure!(decrypted.encryption_info().is_some(), "{event_id} did not decrypt");
        decrypted.raw().deserialize_as::<Value>()?
    } else {
        event
    };
    assert_eq!(event["content"]["body"], expected, "Payload changed for {event_id}");
    Ok(())
}
