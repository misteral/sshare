# Architecture

## Overview

`sshare` is a single-binary Rust CLI that shares team secrets by encrypting them to
members' SSH **public** keys (via the embedded [`age`](https://github.com/FiloSottile/age)
format) and storing the ciphertext in a git repo. Only a matching SSH **private** key can
decrypt — that *is* the access control. No server, no accounts, no external `age`/`gpg`.

It is a small crate (~700 lines of logic across 4 source files). The whole program is a
clap-driven command dispatcher over a `Vault` abstraction backed by the filesystem.

## Module map

| Module | Responsibility | Imports `age`? |
|---|---|---|
| `src/main.rs` | clap CLI, all stdin/stdout/file I/O, `~/.ssh` default-key resolution, one thin `cmd_*` per subcommand | no |
| `src/vault.rs` | `Vault` type: on-disk layout, member files, secret blobs, name validation | only to build recipients |
| `src/crypto.rs` | `encrypt` / `decrypt` / `parse_recipient`, passphrase prompt — the only place `age` types live | **yes (exclusively)** |
| `src/test_keys.rs` | throwaway ed25519 keypairs, `#[cfg(test)]` only — never compiled into the binary | no |

## Dependency rules

Strict one-directional layering — **`main.rs` → `vault.rs` → `crypto.rs`**, never the
reverse:

- `main.rs` is the only layer that talks to the user or the environment (argv, stdin,
  stdout, `$HOME`). It never touches `age` types.
- `vault.rs` owns every filesystem path under a vault. It knows nothing about encryption
  beyond calling `crypto::parse_recipient` to turn a stored pubkey into a recipient.
- `crypto.rs` is the **only** module that imports `age`. All encryption knowledge is
  contained here so the format can be swapped or audited in one place.

Mechanical check: `grep -rl '\bage::' src/` must return only `src/crypto.rs` (and
`src/vault.rs` for the `age::ssh::Recipient` return type — keep that the single
exception). Do not introduce a second encryption path or leak `age` types into `main.rs`.

## On-disk layout

A vault is any directory containing a `.sshare/` folder. `Vault::discover()` walks up
parent directories looking for `.sshare/config.toml`.

```text
<root>/.sshare/config.toml        # marks the vault root (version = 1)
<root>/.sshare/members/<name>.pub # one SSH public key per member (file stem = member name)
<root>/secrets/<name>.age         # age ciphertext; nestable, e.g. secrets/prod/api-token.age
```

The repo itself is the transport: users `git commit` + `git push`/`pull`. **The CLI does
no git operations** — see [SECURITY.md](SECURITY.md) and the note in
[design-docs/index.md](design-docs/index.md).

## Key data flows

- **`add`**: read plaintext (stdin / `--file` / `--value`) → `vault.recipients()` (all
  members) → `crypto::encrypt` to every recipient → `vault.write_secret`. v0.1 encrypts
  every secret to **all** members; there is no per-secret granularity yet.
- **`get`**: `vault.read_secret` → resolve identity (`--identity` or first of
  `~/.ssh/{id_ed25519,id_rsa}`) → `crypto::decrypt` → raw bytes to stdout. A non-recipient
  key simply fails to decrypt — that failure is the access boundary.
- **`rekey`**: for each secret, decrypt with the caller's key then re-encrypt to the
  current member set. The caller must still be a recipient of every secret. Run after
  `member add`/`member rm` to propagate membership changes to existing secrets.

## Access control is the crypto

There is **no permission-check code**. Authorization is an emergent property of who holds
a recipient private key. Any feature that appears to "check access" must do so by changing
the recipient set and re-encrypting — never by gating on a flag or role. See
[SECURITY.md](SECURITY.md).
