# Architecture

## Overview

`sshare` is a single-binary Rust CLI that shares team secrets by encrypting them to
members' SSH **public** keys (via the embedded [`age`](https://github.com/FiloSottile/age)
format) and storing the ciphertext in a git repo. Only a matching SSH **private** key can
decrypt — that *is* the access control. No server, no accounts, no external `age`/`gpg`.

It is a small crate (~5 source files). The whole program is a clap-driven command
dispatcher over a `Vault` abstraction backed by the filesystem.

## Module map

| Module | Responsibility | Imports `age`? |
|---|---|---|
| `src/main.rs` | clap CLI, all stdin/stdout/file I/O, `~/.ssh` default-key resolution, **vault resolution** (`resolve_vault`), one thin `cmd_*` per subcommand | no |
| `src/vault.rs` | `Vault` type: on-disk layout, member files, secret blobs, name validation; `discover`/`find_from`/`open` | only to build recipients |
| `src/crypto.rs` | `encrypt` / `decrypt` / `parse_recipient`, passphrase prompt — the only place `age` types live | **yes (exclusively)** |
| `src/sign.rs` | SSHSIG `sign`/`verify`/`fingerprint_of` over the member set — the only place `ssh-key` types live | no (`ssh-key`, exclusively) |
| `src/registry.rs` | `Registry` of *connected* vaults (name → local path) in the user's config dir; `connect`/`disconnect`/`list`/`path_of` | no |
| `src/trust.rs` | `TrustStore` — TOFU pin store (vault id → authority fingerprint) in the config dir | no |
| `src/test_keys.rs` | throwaway ed25519 keypairs, `#[cfg(test)]` only — never compiled into the binary | no |

`age` lives only in `crypto.rs` and `ssh-key` lives only in `sign.rs` — the two crypto
libraries are each isolated to one module. Mechanical check: `grep -rl 'ssh_key::' src/`
returns only `src/sign.rs`.

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
no git operations and no network I/O** — see [SECURITY.md](SECURITY.md) and the note in
[design-docs/index.md](design-docs/index.md). This holds even for `connect`, which only
*registers* an already-cloned local repo (see below).

## Vault resolution & the connected-vault registry

A second, machine-global piece of state lives **outside** any vault: a registry of
*connected* vaults at `$SSHARE_CONFIG_HOME` / `$XDG_CONFIG_HOME/sshare` / `~/.config/sshare`
(`src/registry.rs`). It is a dependency-free `name<TAB>path` file holding **only names and
local paths — no secrets, no git**. It exists so an agent or user can target a vault by name
from anywhere instead of searching the filesystem.

`main::resolve_vault` is the single entry point every vault-using command goes through; its
order is: `--vault <name>` / `$SSHARE_VAULT` → registry lookup → `Vault::discover()` from
cwd (legacy behavior) → the only connected vault → else an error listing connected vaults.
`init` and `connect` write the registry — the **only** writes sshare makes outside a vault.
`connect` registers an existing local vault (it does not clone); `disconnect` only
unregisters and never deletes files.

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

## Tamper-evidence (signed members list)

The member set is authenticated, not just trusted-because-it's-in-the-repo. A maintainer
signs the canonical member set (`vault.canonical_members()`) with their SSH key via
`sign::sign`; the signature is stored in `.sshare/members.sig`. `add`/`rekey` call
`verify_members_trusted` *before* encrypting: it verifies the signature (`sign::verify`)
and checks the signer's fingerprint against the per-vault authority pinned in `trust.rs`
(TOFU). Membership changes (`member add`/`rm`) re-sign and may only be made by the pinned
maintainer. The pin lives in the config dir, **outside the repo**, so a committer can't
forge both. See [design-docs/signed-members-list.md](design-docs/signed-members-list.md).

## Access control is the crypto

There is **no permission-check code**. Authorization is an emergent property of who holds
a recipient private key. Any feature that appears to "check access" must do so by changing
the recipient set and re-encrypting — never by gating on a flag or role. (The signed members
list above authenticates *which* recipient set is legitimate; it is not a permission gate.)
See [SECURITY.md](SECURITY.md).
