# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`sshare` is a Rust CLI that shares team secrets by encrypting them to members' SSH
**public** keys (via the `age` format) and storing the ciphertext in a git repo. Only a
matching SSH **private** key can decrypt — that *is* the access control. No server, no
accounts, no external `age`/`gpg` binary (the `age` crate is embedded).

This is a small crate (4 source files, ~700 lines). This single file is the agent
entrypoint — there is no `docs/` tree. If the project grows past ~3k lines or gains
subsystems, graduate the "Architecture" and "Golden principles" sections below into a
`docs/` structure with a thin pointer here (harness-engineering Mode A).

## Commands

```sh
cargo build --release          # -> target/release/sshare
cargo install --path .         # install to ~/.cargo/bin
cargo test                     # all 10 unit tests (inline in src modules)
cargo test wrong_key_cannot_decrypt   # run a single test by name (substring match)
cargo clippy --all-targets     # MUST stay clean — pedantic lints are enabled (see below)
cargo fmt                      # format before committing
```

Requires Rust 1.85+ (the crate uses **edition 2024**; current toolchain is 1.96).
Tests live inside `src/*.rs` under `#[cfg(test)]` — this is a binary crate, so there is
no `tests/` directory and no `--lib`.

## CI & release

- **CI** (`.github/workflows/ci.yml`) runs on push to `main` and PRs: `fmt --check`,
  `clippy --all-targets -- -D warnings` (so pedantic lints fail the build), and `cargo
  test` on Linux + macOS. Keep it green; `--locked` means `Cargo.lock` must be committed
  and current.
- **Release** (`.github/workflows/release.yml`) fires on a `v*` tag. It cross-builds four
  targets (macOS Intel/ARM, Linux x86_64/aarch64), publishes a GitHub Release with
  tarballs + `.sha256`, and **regenerates `Formula/sshare.rb` and commits it back to
  `main`**. To cut a release: add a `## [x.y.z]` section to `CHANGELOG.md`, bump
  `Cargo.toml` version, then `git tag vX.Y.Z && git push origin vX.Y.Z`.
- `Formula/sshare.rb` is a generated artifact — edit the heredoc in `release.yml`, not the
  formula directly. Its checksums are placeholders until the first tag fills them in.

## Architecture

Strict one-directional layering — **`main.rs` → `vault.rs` → `crypto.rs`**, never the
reverse:

- **`main.rs`** — clap CLI, all stdin/stdout/file I/O, and `~/.ssh` default-key
  resolution (`default_identity`, `default_pubkey`). The only layer that talks to the
  user or the environment. Each subcommand is a thin `cmd_*` function.
- **`vault.rs`** — on-disk layout and the `Vault` type. Knows the directory structure;
  knows nothing about encryption beyond turning member pubkeys into recipients. All
  filesystem paths flow through here.
- **`crypto.rs`** — the **only** file that imports `age` types. `encrypt`, `decrypt`,
  `parse_recipient`, and the passphrase prompt. Keep all `age` knowledge contained here.
- **`test_keys.rs`** — throwaway ed25519 keypairs, `#[cfg(test)]` only. Not real
  credentials; never used at runtime.

On-disk vault layout (a vault is any dir containing `.sshare/`):

```
<root>/.sshare/config.toml        # marks the vault root; `discover()` walks up to find it
<root>/.sshare/members/<name>.pub # one SSH public key per member
<root>/secrets/<name>.age         # age ciphertext; nestable, e.g. secrets/prod/api-token.age
```

Key flows to understand before changing behavior:

- **Access control is the crypto.** There is no permission check in code. `add` encrypts
  to **every** member's pubkey; `get` decrypts only if the caller's private key is a
  recipient. A non-recipient's `get` simply fails — that failure is the access boundary.
- **v0.1 model: every secret → all members.** There is no per-secret/group granularity
  yet. `rekey` decrypts each secret with the caller's key and re-encrypts to the current
  member set (so the caller must still be a recipient). Adding/removing a member is not
  effective for existing secrets until `rekey` runs.
- **No git automation.** The CLI never shells out to git or commits — the user commits
  and pushes manually. (`README.md` is correct on this; `PRD.md` §5 says "then commits"
  but that is aspirational, not implemented.)

## Golden principles (mechanical invariants — keep these true)

- **Crypto isolation**: `age` types appear only in `crypto.rs`. Don't leak them into
  `vault.rs`/`main.rs`. Don't add a second encryption path.
- **Path-traversal guard**: every secret name passes `validate_name` and every member
  name passes `validate_component` *before* touching the filesystem. New
  filesystem-writing code must route through these.
- **Fail fast on bad keys**: reject unusable SSH pubkeys at `member add` time
  (`parse_recipient`), not at encrypt time.
- **Secrets never leak**: plaintext is written only to `get`'s raw stdout. Never log,
  `print`, or include secret bytes in error messages. Private keys are read only inside
  `crypto::decrypt`; passphrases come via `rpassword` (never echoed).
- **Errors**: use `anyhow` with `.context(...)` carrying a user-actionable message; the
  binary returns `Result<()>` from `main`.
- **Lints are gates**: `clippy::all` + `clippy::pedantic` and the rust lints in
  `Cargo.toml` are `warn` — keep the tree warning-free.
- **Test the security boundary**: changes to crypto/vault should keep (and extend) the
  round-trip, wrong-key-rejection, and path-traversal tests.

## Not yet implemented (described in PRD.md, absent from code)

`grant` / `revoke` / groups (per-secret recipients), `--clip` clipboard, `sshare exec`,
signed members list, and any git automation. Don't assume these exist; they are the
planned roadmap, not current behavior.
