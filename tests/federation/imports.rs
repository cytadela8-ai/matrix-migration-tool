//! Invalid key-file imports remain explicit preparation failures with a saved partial report.
//! Existing export files must survive missing-file, malformed-file and wrong-passphrase cases.

use anyhow::Result;
use matrix_migration_tool::report::Outcome;

use crate::support::{Server, migrate, save_config};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts two real Synapse containers and exercises failed encrypted-key imports"]
async fn invalid_key_imports_preserve_files_and_write_partial_reports() -> Result<()> {
    let work = tempfile::tempdir().expect("Create import fixture directory");
    let from_server = Server::start().await.expect("Start source server");
    let to_server = Server::start().await.expect("Start destination server");
    let source = from_server
        .register("imports", &work.path().join("source"))
        .await
        .expect("Register source");
    let _target = to_server
        .register("imports", &work.path().join("target"))
        .await
        .expect("Register destination");
    source.encryption().wait_for_e2ee_initialization_tasks().await;
    let malformed = work.path().join("malformed.keys");
    std::fs::write(&malformed, "Not a Matrix encrypted key export")
        .expect("Write malformed export");
    let encrypted = work.path().join("wrong-passphrase.keys");
    source
        .encryption()
        .export_room_keys(encrypted.clone(), "different-test-passphrase", |_| true)
        .await
        .expect("Write export protected by another passphrase");
    let original = std::fs::read(&encrypted).expect("Read encrypted export");
    let mut from = from_server.account("imports", "TEST_FROM_PASSWORD");
    from.import_passphrase_env = Some("TEST_IMPORT_PASSPHRASE".into());
    let to = to_server.account("imports", "TEST_TO_PASSWORD");
    for path in [work.path().join("missing.keys"), malformed.clone(), encrypted.clone()] {
        from.import_keys = Some(path.to_str().expect("UTF8 fixture path").into());
        save_config(&work.path().join("config.toml"), &from, &to).expect("Save import config");
        let report = migrate(work.path(), "", "", 2).await?;
        assert!(!report.complete());
        assert!(report.rooms.is_empty());
        assert!(
            matches!(&report.preparation[0], Outcome::Failed(detail)
            if detail.contains("import encrypted key export")),
            "{:?}",
            report.preparation
        );
        assert!(!report.direct.failed(), "Unrelated operations must still run: {report:?}");
    }
    assert!(!work.path().join("missing.keys").exists());
    assert_eq!(
        std::fs::read_to_string(malformed).expect("Read malformed export"),
        "Not a Matrix encrypted key export"
    );
    assert_eq!(std::fs::read(encrypted).expect("Read encrypted export"), original);
    Ok(())
}
