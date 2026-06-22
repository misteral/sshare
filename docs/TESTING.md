# Testing

## Running checks (the CI gates, locally)

```sh
cargo fmt --all -- --check                       # formatting
cargo clippy --all-targets --locked -- -D warnings   # pedantic lints fail the build
cargo test --locked                              # all unit tests
```

Run all three before pushing — they are exactly what `.github/workflows/ci.yml` runs, so a
clean local run means a green CI. `--locked` requires `Cargo.lock` to be committed and
current.

## Running a single test

```sh
cargo test wrong_key_cannot_decrypt   # by name (substring match)
cargo test vault::tests               # a module's tests
```

## Test layout

**Unit tests** live inline under `#[cfg(test)] mod tests` in each source file (this is a
binary crate, so there is no `--lib`):

- `crypto.rs` — round-trip with matching key, wrong-key rejection, multi-recipient decrypt,
  empty-recipients error, invalid-pubkey rejection, and unreadable-key error messages
  (legacy-PEM → convert hint, `.pub`-path hint).
- `vault.rs` — init layout + double-init rejection, member add/list/remove, invalid-key
  rejection, nested+sorted secret listing, **path-traversal rejection**, atomic write
  (overwrite + no temp leftover).
- `test_keys.rs` — throwaway ed25519 keypairs (`ALICE`, `MALLORY`) plus a legacy EC-PEM key.
  These are NOT real credentials and are compiled only under `#[cfg(test)]`.

**Integration tests** live in `tests/cli.rs` — they spawn the built binary
(`env!("CARGO_BIN_EXE_sshare")`) and drive the real CLI through `init → member add → add →
get → ls`, plus the `.pub`-path error case. They embed their own throwaway ed25519 key
(crate-internal `test_keys` isn't visible to integration tests).

## Writing tests

- Use `tempfile::tempdir()` for any test that touches the filesystem; never write to the
  developer's real `~/.ssh` or cwd.
- The security-critical invariants — encrypt/decrypt round-trip, **wrong-key rejection**,
  and **path traversal** — must keep passing and should grow with any change to
  `crypto.rs`/`vault.rs`. A change there without a corresponding test is incomplete.
- Generate new test keys with `ssh-keygen -t ed25519 -N '' -C tag -f /tmp/k` and paste the
  pub/priv into `test_keys.rs` (test-only, so embedding the private key is fine).

## Manual / end-to-end testing

The automated end-to-end flow lives in `tests/cli.rs` (above). To exercise it interactively
in a throwaway dir against your own key:

```sh
cd "$(mktemp -d)"
sshare init
sshare member add me --key ~/.ssh/id_ed25519.pub
printf 'hunter2' | sshare add db-prod
sshare get db-prod          # -> hunter2
sshare ls && sshare member ls
```

The Homebrew formula's `test do` block runs `sshare --version` on `brew test sshare`.
