# Export interruption and federation scenarios

Goal: Restore the terminal when export is interrupted and verify large mixed-room migrations.

Implementation stays within the existing Rust/Synapse harness and adds no dependencies.
Config editing during interactive setup is outside scope.

- [x] Generalize the pseudo-terminal helper to invoke init or export with quoted file paths.
- [x] Add regressions interrupting both export password prompts. Require exit 1, restored
      echo/canonical input/signals, hidden secrets, no export, and a released state lock.
- [x] Run those tests against the original CLI and confirm failure; add export cancellation
      handling in src/main.rs, then rerun the terminal tests.
- [x] Move the existing federation CLI runner into tests/support/mod.rs with explicit expected
      exit code, recovery inputs, and a bounded subprocess timeout. Keep the existing failure test.
- [x] Add tests/federation/bulk.rs, imported by tests/federation.rs, with five rooms of 200
      messages: plaintext/shared; encrypted/shared; encrypted/world-readable with rotated
      sessions; plaintext/joined with destination prejoined; encrypted/shared with redactions.
- [x] Recover source keys from an encrypted file import, retain destination backup recovery,
      and assert exact event/decryption/redaction counts, preserved source membership,
      exit 0, unchanged devices/metadata/keys on rerun, and all messages accessible.
- [x] Add a separate 1,000-message restricted-history case without prejoining the destination
      to the joined-only room. Verify exit 2 and exactly 200 inaccessible events, with explicit
      failures for all their IDs, without preventing the other rooms from completing.
- [x] Run formatting, strict Clippy, default tests, and all Docker federation tests. Temporarily
      stop pagination after the first page and confirm the large test fails; restore and rerun.
- [x] Update README testing instructions to describe implemented scenarios; inspect final diff.

- [x] Verify missing, malformed and wrong-passphrase imports in tests/federation/imports.rs.

Verification: 33 default tests and all four real federation scenarios passed. The export
regression failed before the fix and passed after it. Truncating pagination produced 97
checked messages instead of 200 and failed the bulk test; pagination was restored and both
bulk scenarios passed again. Formatting, strict Clippy, source metrics and shell checks passed.
