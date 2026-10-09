# Matrix migration tool

A Rust CLI that migrates an existing Matrix account to another account, including across
federated homeservers. It invites and joins rooms, increases destination power, copies room
tags, merges direct-chat mappings, imports available encryption keys, and checks historical
messages from the destination account. Each source room receives an independent report.

## Build and run

The repository pins `nightly-2026-10-09` (Rust 1.101.0-nightly), including rustfmt and clippy.
Both accounts must already exist. Public servers require HTTPS; loopback HTTP is allowed
for local testing. Interactive setup requires OAuth or legacy SSO browser authentication.

```sh
cargo build --locked --release
./target/release/matrix-migration-tool init
./target/release/matrix-migration-tool migrate --report migration-report.json
```

`init` runs in a local terminal on the same computer as your browser. On Unix, `stty`
must be installed so terminal echo can be restored safely after interruption:

1. Enter source and destination full Matrix IDs (`@user:server`). Homeservers are discovered;
   enter a HTTPS server URL only if discovery fails. Confirm the direction and file locations.
2. Enter and confirm a new local store passphrase in hidden prompts. Keep it for subsequent
   runs; it is not an account password and cannot be recovered by this tool.
3. Log into each account in your browser, including server-required SSO/MFA and authorization.
   A temporary IPv4 localhost receiver gets the response automatically. Confirm the actual
   account identity in the terminal. No passwords, access tokens or session keys are pasted
   into the tool. If browser launch fails, open the displayed login URL on the same computer.
4. For each account, select pairing and choose an existing device by its displayed name/number.
   Keep that client online, accept verification, compare all seven emojis and explicitly type
   `yes`. Alternatively, enter a recovery key in a hidden prompt or explicitly acknowledge
   incomplete key access. Browser authentication alone does not unlock historical chat keys.

The wizard creates `config.toml` automatically, with identities and selected pairing devices,
but no secret values or password environment-variable setup. `migrate` and `export-keys` prompt
for the local store passphrase. Setup only authenticates/verifies devices and writes local
files: it never invites users, joins rooms or changes room metadata.

A draft config is saved before login so interrupted setup can resume. Rerun `init` with the
same config/state paths: valid sessions and verified devices are reused. Existing configs
are never replaced with different accounts, and unexpected external edits are rejected.
For an existing password/environment config, the wizard explicitly announces a switch to
browser sessions and hidden store prompts before asking for confirmation. Existing devices,
keys and optional environment-based recovery/import settings are retained.
Malformed configs, wrong passphrases and revoked sessions fail visibly; preserve the original
state, and use a new state directory if a fresh device is necessary. A mistakenly authenticated
account is not saved, though the server may already have created its device.

OAuth uses authorization code + PKCE and checked state; legacy SSO uses a random callback
path. Callbacks expire after five minutes. OAuth failures are not silently downgraded to SSO
or password login. Password-only servers cannot use browser setup; some OAuth servers require
administrator approval for native-client registration. Remote/SSH callbacks and manually
registered OAuth client IDs are not supported. Saved refresh tokens are managed automatically.

For unattended/password-login workflows, the existing explicit environment configuration is
still supported. Copy `config.toml.example`, edit the account IDs/server URLs, and read secrets
without echoing or adding them to shell history:

```sh
cp config.toml.example config.toml
read -rsp 'Source password: ' MATRIX_FROM_PASSWORD; echo
read -rsp 'Destination password: ' MATRIX_TO_PASSWORD; echo
read -rsp 'New strong local store passphrase: ' MATRIX_STORE_PASSPHRASE; echo
export MATRIX_FROM_PASSWORD MATRIX_TO_PASSWORD MATRIX_STORE_PASSPHRASE
./target/release/matrix-migration-tool migrate --report migration-report.json
```

Keep the same store passphrase and state directory for retries. The default is
`.matrix-migration/`; select another with `--state-dir PATH`. A directory is bound to the
two accounts. Restored sessions do not require password variables, but the store passphrase
remains necessary (hidden prompt for wizard configs, configured environment variable otherwise).
Exit codes: `0` for complete migration and history checks; `2` for a run
with reported room/preparation failures; `1` for a fatal setup/runtime error.

## Pairing and historical encryption keys

Set `from.verification_device` to the ID of an existing source device, found in that client's
security/session settings. Keep it online, accept verification, compare all seven emojis, and
type `yes` only if they match. An already verified pair is reused. The destination supports
the same options.

Pairing allows a trusted existing client to share secrets and answer missing-key requests.
It does **not** guarantee that all historical room keys arrive. The tool asks for missing
source keys, downloads keys from an enabled source backup, transfers available sessions,
and attempts real destination decryption. Obtain missing keys and rerun when necessary.
Recovery and a standard encrypted room-key export (such as Element's) are also supported:

```toml
[from]
homeserver = "https://matrix.old.example"
user_id = "@alice:old.example"
password_env = "MATRIX_FROM_PASSWORD"
recovery_key_env = "MATRIX_FROM_RECOVERY_KEY"
import_keys = "/absolute/path/to/encrypted-room-keys.txt"
import_passphrase_env = "MATRIX_IMPORT_PASSPHRASE"
```

The recovery value is the account's secret-storage recovery key or configured recovery
passphrase. Export and store passphrases are separate. Options can be combined; a failed
requested acquisition remains reported even if another mechanism supplies enough keys.

Joining may trigger key sharing for new messages; it is insufficient for old ones. This
tool explicitly copies available Megolm sessions into its persistent **destination device**.
Destination-only keys are retained. An existing enabled destination backup receives imported
keys so other clients can recover them. Pair or supply the destination recovery key to unlock
that backup. The tool never creates or replaces a server backup or cross-signing identity.

If no destination backup is enabled, import an encrypted export into your normal client:

```sh
./target/release/matrix-migration-tool export-keys --output destination.keys
```

The export passphrase is prompted without echo. Unattended exports can set
`MATRIX_EXPORT_PASSPHRASE` (or the variable named by `--passphrase-env`).

Keep the state directory until you verify decryption in your normal client. The source Olm
account and cross-signing identity belong to another Matrix user and are not copied.
Rerunning `export-keys` with the same path/passphrase succeeds without rewriting an export
that already covers all current keys. An outdated, unrelated or unreadable file is preserved;
choose a new output path in that case.

## Migration behavior and reporting

| Operation | Rerun behavior | Limits reported |
| --- | --- | --- |
| Login | Restores the same device/store | Invalid credentials, revoked sessions, wrong store |
| Membership | Skips joined rooms and existing invites | Bans, insufficient invite power, join restrictions |
| Power | Writes only when destination power is lower | Insufficient authority, immutable v12 creator power |
| `m.direct` | Unions mappings without duplicates | Invalid account data, server errors |
| `m.tag` | Copies source values, retains destination-only tags | Invalid data or write failures |
| Keys | Imports new or more complete sessions | Missing source keys, invalid exports |
| History | Audits again without room-state changes | Hidden events, missing ciphertext or decryption keys |

Terminal and JSON reports list all discovered source rooms and each operation's status/reason.
Joined room inventories are recorded for both accounts before migration and the destination
afterwards. Source invitations and known left/banned rooms are reported as skipped: the source
cannot invite from them. The tool does not accept source invitations for you.

The history audit paginates all source-visible messages and backfills destination-visible
history, then fetches each message-like event as the destination and decrypts encrypted events.
The report records current `m.room.history_visibility`, event counts, scan completion and
individual failed event IDs. `joined` and `invited` visibility generally restrict earlier
events; importing keys cannot make a homeserver serve hidden ciphertext. Current visibility
is not proof about older events: it can change, and retention/federation failures can also
make history unavailable. The report records actual API failures without assuming their cause.

Messages stay in their original rooms with original authors/timestamps. The tool does not
repost history, change visibility, leave source rooms, unban users or deactivate accounts.
Matrix state writes have no compare-and-swap; avoid concurrent edits to power/metadata.
Only one migration may use a state directory at a time. Calls have bounded timeouts and
rate-limit retries. Successfully applied changes and devices are reused after interruption.
Reports are saved atomically and omit message bodies, tokens, passwords and keys.

## Local storage

SDK state and keys live in passphrase-encrypted SQLite stores. On Unix, directories are `0700`
and session files `0600`. Session files contain access/refresh tokens and OAuth client IDs,
protected by permissions,
not store encryption; use an encrypted disk and protect state backups. Transient key files
are encrypted, owner-only and removed after transfer. Owned secret buffers are zeroized on
drop (SDK token storage has its own lifecycle). Debug logging is opt-in with `RUST_LOG`;
review SDK logs before sharing them. Git ignores
local config, state, exports, reports and `.env`.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo test --locked --test federation -- --ignored --nocapture
cargo deny check
# Install rust-code-analysis-cli 0.0.25 for the same parameter/source-width checks as CI:
bash scripts/check-metrics.sh
prek install
prek run --all-files
```

The integration test starts two digest-pinned Synapse 1.162.0 containers with dynamic loopback
ports and Docker host networking. Linux, Docker and OpenSSL are required. Self-signed TLS and
disabled federation certificate checks are confined to test configuration. It creates users
and encrypted rooms, emulates a SAS peer, recovers backups, migrates across servers, decrypts
pre-migration ciphertext, checks bans and history restrictions, and repeats the migration to
verify device reuse and no repeated state/metadata writes. It also tests higher destination
power and immutable room-version 12 creators. Containers and data are temporary.
Additional fixtures cover 105 paginated plaintext messages, missing historical keys,
source invitations, insufficient invite power and repeated encrypted exports.

CI runs formatting, clippy, unit tests, federation tests and dependency auditing. Dependencies
are exactly pinned, with committed `Cargo.lock`. `deny.toml` documents a maintenance exception:
the current official SDK depends on unmaintained `anymap2`; upstream has replaced it with
`anymap3`, pending release. No vulnerability advisory is waived. Actions are pinned by SHA;
Dependabot groups updates with seven-day cooldowns.

Protocol references: [Client-Server API](https://spec.matrix.org/latest/client-server-api/),
[room version 12](https://spec.matrix.org/latest/rooms/v12/),
[SDK encryption](https://docs.rs/matrix-sdk/0.19.1/matrix_sdk/encryption/index.html).
