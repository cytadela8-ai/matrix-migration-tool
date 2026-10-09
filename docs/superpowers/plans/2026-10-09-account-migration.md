# Matrix Account Migration Implementation Plan

**Goal:** Migrate memberships, increasing power levels, direct chats, tags, and available
Megolm keys, with resumable devices and a verifiable result for every source room.

**Architecture:** Use the official Matrix Rust SDK for encrypted persistent stores, login,
SAS verification, room key import/export and decryption. Use authenticated live Client-Server
API reads for membership, state and account data so reruns do not depend on stale SDK caches.
Preserve unrelated destination state; compare before every write. Execute inline in this fresh
repository and publish through a feature branch and PR.

**Tech Stack:** Rust nightly-2026-10-09, matrix-sdk 0.19.1, Tokio, Clap, Serde, Synapse 1.162.0.

## Constraints

- Never lower destination power or replace its unrelated direct chats/tags.
- Do not reset cross-signing, replace server backups, leave rooms, or deactivate accounts.
- SAS requires human confirmation; verification does not guarantee historical key acquisition.
- Keys grant decryption, not server access to hidden ciphertext. Audit actual destination access.
- Persistent devices and operation comparisons provide convergent reruns; concurrency is locked.
- Secrets come from environment variables; encrypted stores and private session files stay local.
- Every discovered source room receives a status, including invited/left rooms.

## Tasks

- [x] Configure rustfmt/clippy and CI before implementation.
- [x] Implement validated TOML configuration, secret lookup, persistent login and authenticated API.
  Files: src/config.rs, src/session.rs, src/api.rs. Test malformed URLs, identical accounts,
  missing secrets, account mismatch, API errors and persistent device reuse.
- [x] Implement convergence rules and serializable per-step/per-room reports.
  Files: src/policy.rs, src/report.rs. Test power boundaries and lossless metadata union.
- [x] Implement SAS pairing, backup recovery and encrypted key transfer.
  Files: src/crypto.rs, src/verification.rs. Test real SAS and encrypted old/new messages.
- [x] Implement room migration and full historical event audit, continuing after room failures.
  Files: src/migration.rs, src/history.rs. Test invite/join failures, bans, tags and history limits.
- [x] Implement CLI, examples and user documentation.
  Files: src/main.rs, config.toml.example, README.md. Test exit codes and JSON reports.
- [x] Run federated two-Synapse integration tests twice to verify convergence and device reuse.
  Files: tests/federation.rs, tests/support/mod.rs, tests/servers/*.
- [ ] Run formatting, clippy, tests, dependency audit and self-review; publish feature branch,
  create PR, verify GitHub checks, and merge the authorized finished repository.

## Verification commands

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo test --locked --test federation -- --ignored --nocapture
cargo deny check
```

The integration test must compare actual server state and decrypt ciphertext originating
before migration. A second run must create no membership, power or metadata changes and
must reuse both device IDs. Denied historical events must remain reported on both runs.
