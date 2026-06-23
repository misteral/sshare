# sshare

[![CI](https://github.com/misteral/sshare/actions/workflows/ci.yml/badge.svg)](https://github.com/misteral/sshare/actions/workflows/ci.yml)

Share team secrets — passwords, API tokens, `.env` files — using the **SSH keys your
team already has**. Secrets are encrypted to members' SSH **public** keys and stored in
a shared git repository; a secret can only be decrypted by someone holding a matching
SSH **private** key.

No server, no new accounts, no extra infrastructure — just a git repo and SSH keys.

Built on the audited [`age`](https://github.com/FiloSottile/age) encryption format
(embedded as a Rust library, so there is **no external `age` dependency**).

See [`PRD.md`](./PRD.md) for the full product spec.

## How it works

```
.sshare/
  config.toml          # marks the vault root
  id                   # stable vault id (used for trust pinning)
  members/alice.pub    # one SSH public key per member
  members.sig          # maintainer's signature over the member set (tamper-evidence)
secrets/
  db-prod.age          # age-encrypted secret blobs
```

- `sshare add` encrypts a secret to **every** member's SSH public key.
- `sshare get` decrypts it with your SSH private key (`~/.ssh/id_ed25519` or `id_rsa`).
- If your key is not a recipient, decryption fails — that *is* the access control.
- The **member list is signed** by a maintainer and verified before encrypting, so a
  committer can't silently add themselves as a recipient (see *Tamper-evidence* below).
- **Commit and `git push`** after changes; teammates `git pull` to sync. sshare runs no git
  itself, but it remembers vaults you *connect* so you can use them by name from anywhere
  (see *Connected vaults*).

## Install

### Homebrew

```sh
brew tap misteral/sshare https://github.com/misteral/sshare
brew trust misteral/sshare   # Homebrew 6+ requires trusting third-party taps
brew install sshare
```

### Prebuilt binary

Download a tarball for your platform from the
[latest release](https://github.com/misteral/sshare/releases/latest) and put `sshare`
on your `PATH`. Each release ships macOS (Intel + Apple Silicon) and Linux (x86_64 +
aarch64) builds plus `.sha256` checksums.

### From source

```sh
cargo install --path .
# or build a release binary:
cargo build --release   # -> target/release/sshare
```

## Quickstart

```sh
# 1. create a vault (inside a git repo)
sshare init

# 2. add yourself, then teammates (share their *.pub files)
sshare member add alice --key ~/.ssh/id_ed25519.pub
sshare member add bob   --key ./bob_ed25519.pub

# 3. store a secret (read from stdin — keeps it out of shell history)
printf 'super-secret-password' | sshare add db-prod

# 4. read it back
sshare get db-prod

# 5. list what's there
sshare ls
sshare member ls

# 6. after adding/removing a member, re-encrypt everything
sshare rekey
```

`get` writes the raw secret to stdout, so it pipes cleanly:

```sh
sshare get prod/.env > .env
export DB_PASSWORD="$(sshare get db-prod)"
```

## Commands

| Command | Description |
|---|---|
| `sshare init` | Create a vault in the current directory (and connect it). |
| `sshare connect [<path>] [--name <n>]` | Register an existing local vault so you can use it by name from anywhere. |
| `sshare disconnect <name>` | Unregister a connected vault (does not delete files). |
| `sshare vaults` | List connected vaults. |
| `sshare trust` | Show the vault's signing authority and pin status. |
| `sshare trust accept [<fingerprint>]` | Pin (first use) or re-pin the trusted signing authority. |
| `sshare member add <name> [--key <path\|->] [--identity <path>]` | Register a member's SSH public key and re-sign the member list. |
| `sshare member ls` | List members. |
| `sshare member rm <name> [--identity <path>]` | Remove a member and re-sign (then run `rekey`). |
| `sshare add <name> [--file <path>\|--value <v>]` | Store/update a secret (stdin by default). |
| `sshare get <name> [--identity <path>]` | Decrypt a secret to stdout. |
| `sshare ls` | List stored secrets. |
| `sshare rekey [--identity <path>]` | Re-encrypt all secrets for the current members. |

Any command that operates on a vault also accepts a global **`--vault <name>`** (or the
`SSHARE_VAULT` env var) to target a connected vault from anywhere — otherwise sshare uses
the vault containing the current directory.

## Connected vaults

So you don't have to `cd` into a vault (or hunt for it) every time, sshare keeps a small
registry of vaults you've connected, in `~/.config/sshare/vaults` (honors
`$XDG_CONFIG_HOME` / `$SSHARE_CONFIG_HOME`). It stores **only names and local paths — never
secrets, never git remotes**. `connect` registers a vault you've **already cloned** — sshare
itself never runs git or touches the network.

```sh
git clone git@github.com:team/secrets.git   # you clone it the normal way
sshare connect ./secrets --name team        # register it (init does this automatically)
sshare vaults                               # team   ok   /abs/path/to/secrets
sshare get db-prod --vault team > .env       # use it from anywhere, no cd
```

## Tamper-evidence (signed members)

The member set *is* the recipient set, so sshare makes it tamper-evident. A maintainer signs
the member list with their SSH key; every machine pins that authority on first use (TOFU)
and verifies it **before encrypting**, so a teammate with repo write access can't silently
add their own key as a recipient.

```sh
# maintainer: member changes are signed automatically with your key
sshare member add bob --key ./bob.pub        # signs the member list
# a teammate, first time on this vault:
sshare trust                                 # shows the signing authority's fingerprint
sshare trust accept                          # pin it (verify the fingerprint out-of-band first!)
```

If the member list is changed without a valid signature by the pinned authority, `add` and
`rekey` refuse with an error. See
[docs/design-docs/signed-members-list.md](docs/design-docs/signed-members-list.md).

## Security notes

- **Confidentiality** comes from `age` encryption to SSH public keys. The repo host
  (GitHub, etc.) only ever sees ciphertext.
- **Private keys never leave your machine.** Passphrase-protected keys are supported
  (you'll be prompted).
- **Visible to anyone with repo access:** secret *names* and the *set of member keys* —
  but not secret *values* unless their key is a recipient.
- **Revocation needs rotation.** Removing a member and running `rekey` stops *future*
  access, but they may already have copies of secrets they could read. Rotate those.
- Prefer piping secrets via **stdin** over `--value`, which is visible in shell history
  and the process list.

## Status

v0.2 — core flow (init / members / add / get / ls / rekey), **connected vaults**
(`connect` / `vaults` / global `--vault`), and a **signed, tamper-evident member list**
(TOFU — `trust` / `trust accept`). Every secret is still encrypted to **all** members.
Planned next (see [`PRD.md`](./PRD.md) and
[the tech-debt tracker](docs/exec-plans/tech-debt-tracker.md)): per-secret recipients and
groups (`grant`/`revoke`), multi-maintainer signing, and supply-chain hardening (release
provenance + signed tags).

## Development

```sh
cargo test --locked                                  # unit + integration tests
cargo clippy --all-targets --locked -- -D warnings   # pedantic lints are a CI gate
cargo fmt --all -- --check                           # formatting is a CI gate
```

Contributor and agent docs live in [`AGENTS.md`](./AGENTS.md) and [`docs/`](./docs).

## License

MIT © Bobrov Aleksandr
