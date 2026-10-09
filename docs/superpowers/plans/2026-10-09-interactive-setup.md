# Interactive Browser Setup Implementation Plan

> **For agentic workers:** Execute inline, task by task; no delegated workers are needed.

**Goal:** Create configuration and reusable sessions interactively without copied tokens.

**Architecture:** `init` discovers homeservers, authenticates using SDK OAuth or SSO, then
pairs existing devices. Configuration contains account identities and no credentials;
session persistence supports both authentication APIs and atomic refresh-token updates.

**Tech Stack:** Existing pinned Rust and Matrix SDK, Tokio loopback callbacks, `rpassword`
for hidden input, `open` for browser launching, TOML serialization.

## Global Constraints

- Never change rooms during setup or silently replace configuration/account state.
- Never downgrade OAuth errors to password login; support browser-capable servers only in init.
- Reuse existing devices and preserve encrypted stores on retries.
- Keep explicit password environment configuration for unattended/test workflows.
- Login requires a browser on the CLI computer; encrypted history requires pairing or recovery.

### Task 1: Session and prompt foundation

Files: `src/config.rs`, `src/session.rs`, `src/prompt.rs`, `src/api.rs`, `Cargo.toml`.
Interfaces: `Config::store_passphrase()` returns a zeroizing environment secret or hidden input;
`session::login` restores SDK Matrix/OAuth sessions; `session::save` persists current tokens.

- [x] Add serialization tests for browser configuration and both session types.
- [x] Make password/store environment names optional; omit unset fields when serializing TOML.
- [x] Implement terminal-only hidden prompts and reject empty/mismatched passphrases.
- [x] Persist synchronous SDK refresh callbacks; REST reads the latest SDK token and retries
  M_UNKNOWN_TOKEN once after refresh, never refreshes arbitrary authentication errors.
- [x] Run `cargo test --locked` and clippy.

### Task 2: Browser authentication

Files: `src/browser.rs`, `src/callback.rs`, `src/session.rs`.
Interface: `browser::login(&Client, &Account)` authenticates with OAuth or legacy SSO.

- [x] Test loopback callback method/path/state checks, malformed requests and cancellation.
- [x] Discover OAuth metadata; only explicit unsupported OAuth selects SSO discovery.
- [x] Register native OAuth client, use SDK PKCE/state validation and bounded localhost callback.
- [x] Request refresh tokens and persist registration/user session; reject wrong identities
  before saving anything, and retain actionable registration/browser errors.
- [x] Run callback/session tests and clippy.

### Task 3: Wizard and CLI

Files: `src/setup.rs`, `src/main.rs`, `src/verification.rs`, `src/lib.rs`, `tests/cli.rs`.
Interface: `setup::run(config_path, state_dir)` creates or resumes confirmed configuration.

- [x] Test `init --help`, noninteractive refusal, existing malformed config preservation,
  config creation without secrets and no-clobber writes.
- [x] Discover from Matrix IDs, prompt explicit homeserver fallback, reject identical accounts.
- [x] Confirm direction before login and save config atomically without overwriting existing files.
- [x] Select existing devices by numbered names; pair with explicit emoji comparison, or offer
  hidden recovery input / explicit incomplete-key-access acknowledgement.
- [x] Reuse sessions on rerun and prompt local passphrase on migrate/export for wizard configs.
- [x] Run CLI/unit tests, rustfmt and clippy.

### Task 4: Documentation and publication

Files: `README.md`, browser/SSO boundary integration tests, lockfile.

- [x] Document exact interactive inputs, restrictions, storage and rerun behavior.
- [x] Run browser-flow boundary tests and real two-server federation regression.
- [x] Run cargo-deny, rustfmt, clippy and hooks; inspect diff for accidental secrets.
- [ ] Commit feature branch, push, open PR and verify GitHub CI before merging.
