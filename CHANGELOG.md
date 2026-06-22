# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/misteral/sshare/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/misteral/sshare/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/misteral/sshare/releases/tag/v0.1.0
