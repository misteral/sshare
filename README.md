# sshare

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
  members/alice.pub    # one SSH public key per member
secrets/
  db-prod.age          # age-encrypted secret blobs
```

- `sshare add` encrypts a secret to **every** member's SSH public key.
- `sshare get` decrypts it with your SSH private key (`~/.ssh/id_ed25519` or `id_rsa`).
- If your key is not a recipient, decryption fails — that *is* the access control.
- Commit the repo and `git push`; teammates `git pull` to sync.

## Install

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
| `sshare init` | Create a vault in the current directory. |
| `sshare member add <name> [--key <path\|->]` | Register a member's SSH public key. |
| `sshare member ls` | List members. |
| `sshare member rm <name>` | Remove a member (then run `rekey`). |
| `sshare add <name> [--file <path>\|--value <v>]` | Store/update a secret (stdin by default). |
| `sshare get <name> [--identity <path>]` | Decrypt a secret to stdout. |
| `sshare ls` | List stored secrets. |
| `sshare rekey [--identity <path>]` | Re-encrypt all secrets for the current members. |

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

v0.1 — core flow (init / members / add / get / ls / rekey). Every secret is encrypted
to **all** members. Planned next (see PRD open questions): per-secret recipients and
groups (`grant`/`revoke`), and a signed members list to prevent tampering.

## Development

```sh
cargo test            # unit tests (round-trip, wrong-key rejection, vault flow)
cargo clippy --all-targets
cargo fmt
```

## License

MIT © Global Concordia Solutions
