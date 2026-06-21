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

This is a **binary crate**, so there is no `tests/` directory and no `--lib`. Tests live
inline under `#[cfg(test)] mod tests` in each source file:

- `crypto.rs` — round-trip with matching key, wrong-key rejection, multi-recipient decrypt,
  empty-recipients error, invalid-pubkey rejection.
- `vault.rs` — init layout + double-init rejection, member add/list/remove, invalid-key
  rejection, nested+sorted secret listing, **path-traversal rejection**.
- `test_keys.rs` — throwaway ed25519 keypairs (`ALICE`, `MALLORY`) used by the above.
  These are NOT real credentials and are compiled only under `#[cfg(test)]`.

## Writing tests

- Use `tempfile::tempdir()` for any test that touches the filesystem; never write to the
  developer's real `~/.ssh` or cwd.
- The security-critical invariants — encrypt/decrypt round-trip, **wrong-key rejection**,
  and **path traversal** — must keep passing and should grow with any change to
  `crypto.rs`/`vault.rs`. A change there without a corresponding test is incomplete.
- Generate new test keys with `ssh-keygen -t ed25519 -N '' -C tag -f /tmp/k` and paste the
  pub/priv into `test_keys.rs` (test-only, so embedding the private key is fine).

## Manual / end-to-end testing

There is no automated CLI integration test yet (see
[QUALITY_SCORE.md](QUALITY_SCORE.md)). To exercise the real flow in a throwaway dir:

```sh
cd "$(mktemp -d)"
sshare init
sshare member add me --key ~/.ssh/id_ed25519.pub
printf 'hunter2' | sshare add db-prod
sshare get db-prod          # -> hunter2
sshare ls && sshare member ls
```

The Homebrew formula's `test do` block runs `sshare --version` on `brew test sshare`.
