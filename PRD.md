# sshare — Product Requirements Document

> **Status:** Draft v0.1 · **Owner:** a.bobrov@g-concordia.com · **Date:** 2026-06-21
> **Company:** GCS — Global Concordia Solutions

## 1. One-liner

`sshare` is a command-line tool for sharing secrets (passwords, API tokens, `.env`
files) inside a team using the **SSH keys people already have**. Encrypted secrets
live in a **shared git repository**; you can decrypt a secret **only if your SSH
private key is one of its recipients**. No server, no new accounts, no extra infra.

## 2. Problem

Teams constantly need to share secrets, and today they do it badly:

- Pasting passwords into Slack / Telegram / email.
- Plaintext `.env` files committed "by accident".
- Shared password-manager vaults that not everyone uses, or that live outside the
  team's git workflow.
- Heavy solutions (HashiCorp Vault) require infrastructure, operations, and buy-in
  that small teams don't want for "just share these 10 secrets".

Meanwhile, **everyone on the team already has an SSH key** (for git push). We can use
that existing trust anchor as the access-control mechanism.

## 3. Goals

- **Zero new infrastructure** — a git repo + SSH keys are the entire system.
- **Access control by SSH public key** — decryption requires the matching private key.
- **Simple, memorable CLI** — `init`, `add`, `get`, `ls`, `member`, `grant`, `revoke`.
- **Auditable** — every change is a git commit; history shows who changed what, when.
- **Self-contained binary** — no runtime dependency on an external `age`/`gpg` install.
- **Cross-platform** — macOS and Linux first.

## 4. Non-goals (v1)

- Not a dynamic-secrets engine or a Vault replacement (no leasing, no DB credential
  generation).
- No central server, no web UI, no SaaS.
- No automated secret rotation (manual in v1; we document when rotation is needed).
- Not a general SSH key-management tool.

## 5. How it works (mechanism)

`sshare` is built on the **`age`** encryption format, which can encrypt to SSH public
keys and decrypt with SSH private keys.

1. A **vault** is just a git repo (or a folder inside one) with an `.sshare/` config
   directory.
2. Each **member** registers their SSH **public** key in the vault
   (e.g. `.sshare/members/alice.pub`).
3. `sshare add db-prod` reads a value (from stdin/flag/file), encrypts it to the SSH
   public keys of all authorized members, and writes `secrets/db-prod.age`, then commits.
4. `sshare get db-prod` decrypts `secrets/db-prod.age` using the caller's SSH private
   key (`~/.ssh/id_ed25519`, or via the SSH agent) and prints/copies the value.
5. If the caller's key is **not** a recipient, decryption simply fails — that *is* the
   access control.

```
┌──────────────┐   git push/pull   ┌──────────────────────┐
│  Alice's CLI │ ───────────────►  │  shared git repo      │
│  id_ed25519  │ ◄───────────────  │  secrets/*.age (enc)  │
└──────────────┘                   │  .sshare/members/*.pub│
                                   └──────────────────────┘
        ▲ decrypt with private key          ▲
        │ (only if recipient)               │ everyone can pull,
        └───────────────────────────────────┘ nobody reads what they can't decrypt
```

## 6. Core concepts

| Concept    | Meaning                                                              |
|------------|---------------------------------------------------------------------|
| **Vault**  | The git repo / folder holding encrypted secrets and config.         |
| **Member** | A person, identified by an SSH public key.                          |
| **Secret** | An encrypted blob — a single value or a whole file.                 |
| **Group**  | A named set of members; a secret is encrypted to a group's keys.    |

## 7. CLI surface (v1)

```
sshare init                      # initialize a vault in the current repo/folder
sshare member add <name> --key <path|->   # register a member's SSH public key
sshare member ls                 # list members
sshare member rm <name>          # remove a member (then rekey)

sshare add <name>                # create/update a secret (stdin, --value, or --file)
sshare get <name> [--clip]       # decrypt & print (or copy to clipboard)
sshare ls                        # list secrets and who can read each

sshare grant <name> --to <member|group>   # give access, re-encrypt
sshare revoke <name> --from <member>      # remove access, re-encrypt
sshare rekey                     # re-encrypt all secrets to current recipients
```

## 8. Security model

- **Confidentiality** comes from `age` encryption to SSH public keys. The repo can be
  hosted anywhere (GitHub, GitLab, a bare repo on a server) — a host compromise leaks
  only ciphertext.
- **Private keys never leave the user's machine**; SSH-agent is supported.
- **What's visible to anyone with repo access:** metadata — secret *names* and *which
  members are recipients*. Secret *values* are not, unless you're a recipient.
- **Revocation caveat:** removing a member and re-keying re-encrypts secrets without
  them, but they may have already read/cached old values. Truly sensitive secrets
  should be **rotated** after revocation. We surface this clearly.
- **Threat model — protects against:** repo/host leaks, accidental plaintext commits,
  teammates without the right key.
  **Does not protect against:** a compromised endpoint that holds a valid private key.
- **Trust bootstrap (open question):** who is allowed to add members / approve keys?
  Candidate: a maintainer-signed members file.

## 9. Proposed tech stack

- **Language:** Rust (GCS house language).
- **Crypto:** the **`age`** crate with the `ssh` feature — embedded, so `sshare` ships
  as a single static binary with **no external `age` dependency**.
- **CLI:** `clap`.
- **Git ops:** `git2` (libgit2) or shelling out to `git`.
- **Output:** single self-contained binary for macOS + Linux.

## 10. Open questions

1. **Recipient granularity:** per-secret recipients vs. groups vs. whole-vault.
   *Proposed default:* groups, with per-secret overrides.
2. **Tamper-resistance of the members list:** sign `.sshare/members` so a malicious
   committer can't silently add their own key as a recipient.
3. **Bootstrapping / admin:** how the first member is established and who can add others.
4. **Convenience features (maybe v1.1):** `sshare exec -- <cmd>` to inject secrets as
   env vars; `.env` import/export; clipboard auto-clear.
5. **Key types:** support `ssh-ed25519` first; decide whether to allow `ssh-rsa`.

## 11. Success criteria (v1)

- A new teammate can be granted access to a secret in **under a minute**, using only
  their existing SSH key.
- A teammate without a recipient key **cannot** decrypt, with a clear error message.
- All operations leave a clean, reviewable git history.
- One binary, no external crypto dependencies to install.
