# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Git integration.** When the vault is a git repository, `add` / `member add` / `member rm`
  / `rekey` now **auto-commit** the change locally with a descriptive message (e.g.
  `sshare: add secret db-prod`), so you can't forget. New `sshare git <args…>` runs git
  inside the vault (`sshare git push` / `pull` / `log`, and composes with `--vault`). Network
  happens only on an explicit `sshare git push`/etc.; reads (`get`/`ls`/`vaults`) stay
  git-free. Disable autocommit for a one-shot batch with `SSHARE_NO_AUTOCOMMIT=1`.

## [0.2.0] - 2026-06-23

### Added

- **Signed members list (tamper-evidence).** A maintainer signs the member set with their
  SSH key (SSHSIG); other machines pin that authority on first use (TOFU) and verify it
  before encrypting, so a repo committer can no longer silently add a recipient key.
  - `sshare trust` shows a vault's signing authority and pin status; `sshare trust accept
    [<fingerprint>]` pins (TOFU) or re-pins (rotation).
  - `sshare member add` / `member rm` re-sign the member list and accept `--identity` (the
    signing key, default your `~/.ssh` key). Only the pinned maintainer may change membership.

### Changed

- **BREAKING:** `add` / `rekey` now refuse to encrypt unless the member list is signed by
  this machine's pinned authority. A vault from before this must be re-signed (`sshare
  member add`) and trusted (`sshare trust accept`). `init` now writes a vault id (`.sshare/id`).

### Notes

- Adds the `ssh-key` (SSHSIG) and `getrandom` crates — both pure-Rust, so the single static
  binary is preserved. `ssh-key` is isolated to `src/sign.rs` (as `age` is to `crypto.rs`).

## [0.1.3] - 2026-06-23

### Added

- Connected-vault registry so a vault can be used by name from anywhere:
  - `sshare connect [<path>] [--name <n>]` registers an existing local vault (it does **not**
    clone — sshare still runs no git and no network); `sshare init` auto-connects.
  - `sshare disconnect <name>` unregisters (never deletes files); `sshare vaults` lists them.
  - A global `--vault <name>` flag (and `SSHARE_VAULT` env) targets a connected vault;
    otherwise the vault in the current directory is used, as before.
  - Registry lives in `~/.config/sshare/vaults` (honors `$XDG_CONFIG_HOME` /
    `$SSHARE_CONFIG_HOME`) and stores only names and local paths — never secrets.

## [0.1.2] - 2026-06-22

### Fixed

- Secret writes are now atomic (temp file + rename), so an interrupted `add`/`rekey` never
  leaves a half-written secret on disk.

## [0.1.1] - 2026-06-22

### Fixed

- `get`/`rekey` now give actionable errors when an SSH key can't be read instead of a
  cryptic "cannot parse SSH key": legacy PEM keys suggest converting with `ssh-keygen -p`,
  pointing `--identity` at a `.pub` file is called out, and unsupported key types name the
  supported ones (ed25519, rsa).

## [0.1.0] - 2026-06-21

### Added

- Initial release — SSH-key-based team secret sharing built on the embedded
  [`age`](https://github.com/FiloSottile/age) format (no external `age`/`gpg` binary).
- `sshare init` — create a vault in the current directory.
- `sshare member add|ls|rm` — manage members, each identified by an SSH public key.
- `sshare add` — store/update a secret from stdin, `--file`, or `--value`, encrypted to
  every member's public key.
- `sshare get` — decrypt a secret to stdout with your SSH private key; passphrase-protected
  keys are supported (prompted on the terminal).
- `sshare ls` — list stored secrets.
- `sshare rekey` — re-encrypt every secret for the current member set.
- Path-traversal-safe, nestable secret names (e.g. `prod/api-token`).

[Unreleased]: https://github.com/misteral/sshare/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/misteral/sshare/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/misteral/sshare/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/misteral/sshare/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/misteral/sshare/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/misteral/sshare/releases/tag/v0.1.0
