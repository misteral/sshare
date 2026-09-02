---
name: sshare
description: Install, set up, and operate the `sshare` CLI to manage a team's shared secrets (passwords, API tokens, `.env` files) that are encrypted to members' SSH public keys and stored in a git repo. Use whenever the user wants to store, retrieve, list, or rotate a team secret, inject a secret into a `.env` or environment variable, create a secrets vault, connect/register an already-cloned secrets repo, list connected vaults, or onboard/offboard a teammate — e.g. "get the prod DB password into my .env", "save this token as a team secret", "connect our secrets repo", "which secret vaults do I have", "give Bob access to our secrets". Triggers in any language.
---

# sshare — operating a team secret vault

`sshare` shares team secrets by encrypting them to members' **SSH public keys** (embedded
`age` format) and storing the ciphertext in a **git repo**. A secret can only be decrypted
by someone holding a matching SSH **private** key — that *is* the access control. There is
no server: the git repo is the transport.

## Mental model

- A **vault** = a directory containing `.sshare/` (usually the team's git repo). Members'
  public keys live in `.sshare/members/<name>.pub`; encrypted secrets in
  `secrets/<name>.age`.
- **Storing** (`add`) encrypts a value to **every** member's public key.
- **Reading** (`get`) decrypts with *your* private key (`~/.ssh/id_ed25519` or `id_rsa`).
  If your key isn't a recipient, it fails — that failure is the access boundary.
- **sshare auto-commits** every change locally when the vault is a git repo. Publish with
  `sshare git push`; fetch teammates' changes with `sshare git pull` before reading. Reads
  themselves never touch the network.

## 0. Make sure sshare is installed

```sh
command -v sshare && sshare --version || echo "not installed"
```

If missing, install via Homebrew (preferred):

```sh
brew tap misteral/sshare https://github.com/misteral/sshare
brew trust misteral/sshare      # Homebrew 6+ requires trusting third-party taps
brew install sshare
```

Or from source with Cargo: `cargo install --git https://github.com/misteral/sshare`.

## 1. Find or create the vault

**Don't go hunting the filesystem for a vault — ask sshare.** It keeps a registry of
*connected* vaults, so run `sshare vaults` first to see what's available:

```sh
sshare vaults          # e.g.  team   ok   /Users/you/work/team-secrets
```

Then target one by name from **anywhere** with the global `--vault <name>` flag (or the
`SSHARE_VAULT` env var) — no need to `cd` in:

```sh
sshare get db-prod --vault team
```

If you don't pass `--vault`, sshare uses the vault in the current directory (walking up to
find `.sshare/`), then falls back to the single connected vault if there's exactly one.

- **`sshare vaults` is empty but the user has a secrets repo cloned?** Connect it once:
  `sshare connect <path-to-repo> --name team` (this only *registers* it — it does **not**
  clone and never touches git). Afterwards it's usable by name everywhere.
- **Starting fresh?** See "Bootstrap a new vault" below — `sshare init` auto-connects.

## Command reference (the full surface)

Every vault command also accepts a global **`--vault <name>`** (or `SSHARE_VAULT` env) to
target a connected vault from anywhere.

| Command | What it does |
|---|---|
| `sshare init` | Create a vault (`.sshare/` + `secrets/`) in the current dir, and connect it. |
| `sshare connect [<path>] [--name <n>]` | Register an already-present local vault (default: the vault at/above the current dir). Does **not** clone. |
| `sshare disconnect <name>` | Unregister a connected vault (does not delete files). |
| `sshare vaults` | List connected vaults (name, status, path). |
| `sshare trust` | Show the vault's signing authority fingerprint and pin status. |
| `sshare trust accept [<fp>]` | Pin (first use / TOFU) or re-pin the trusted signing authority. |
| `sshare member add <name> [--key <path\|->] [--identity <path>]` | Register a member's SSH **public** key and re-sign the member list (only the maintainer may). |
| `sshare member ls` | List members. |
| `sshare member rm <name> [--identity <path>]` | Remove a member and re-sign (then `rekey`, then rotate). |
| `sshare member sign [--yes] [--identity <path>]` | Review and explicitly sign the member list **as-is**. Prints every member + key fingerprint and asks to confirm; `--yes` skips the prompt (non-interactive shells need it). Only for a vault that predates signing or whose `members.sig` was removed — `member add`/`rm` sign automatically. |
| `sshare add <name> [--file <path>] [--value <v>] [--description <text>]` | Store/update a secret. **Prompts (hidden) when interactive**; else reads stdin / `--file` / `--value`. Name may nest: `prod/api-token`. `--description` stores an **encrypted** note (omit to keep an existing one; `--description ""` clears it). |
| `sshare get <name> [--identity <path>]` | Decrypt a secret to **stdout** (raw bytes, no added newline). |
| `sshare ls [--descriptions] [--identity <path>]` | List stored secret names. With `--descriptions` (`-d`), also decrypt and show each secret's description (needs your SSH key). |
| `sshare rm <name>` | Remove a stored secret (auto-commits). |
| `sshare rekey [--migrate-legacy] [--identity <path>]` | Re-encrypt every secret for the current member set. Run after add/rm member. If it stops listing blobs that "carry no vault binding" (pre-0.7 secrets), **show the user the names**; only if every name is expected, re-run with `--migrate-legacy`. |
| `sshare git <args…>` | Run git inside the vault: `sshare git push`, `git pull`, `git log`. The only command that touches the network. |

## Safety rules — read before handling any secret

1. **Never echo a secret value back to the user or into the chat.** When retrieving,
   write it straight to its destination (file / env) and confirm *by name only*
   ("wrote `db-prod` to `.env`").
2. **Keep secrets out of shell history and the process list.** Easiest at a terminal: run
   `sshare add <name>` and type the value at the **hidden prompt**. Otherwise use `--file`
   or stdin; **avoid `--value`** (visible in history and `ps`). Non-interactive value →
   pipe via stdin: `printf %s "$secret" | sshare add <name>`.
3. **Publish & fetch via sshare.** Changes **auto-commit locally** — no manual
   `git add/commit` needed. Run **`sshare git push`** to publish after changes, and
   **`sshare git pull`** before reading to get teammates' latest. (Set `SSHARE_NO_AUTOCOMMIT=1`
   only for batch scripts that want a single manual commit.)
4. **After `member add` or `member rm`, run `sshare rekey`** so existing secrets match the
   new member set. After **removing** a member, tell the user to **rotate** the secrets
   that person could read — they may already have copies.
5. **You must be a member** (recipient) to `get`/`rekey`. If not, add your own key first.
6. **The member list is signed (tamper-evidence).** Changing membership (`member add`/`rm`)
   first **verifies** the current signed list, then changes and re-signs it, and is only
   allowed for the vault's **maintainer** — pass their key with `--identity`. If it refuses
   with "tampered" / "no signature", **stop and tell the user**: someone changed
   `.sshare/members/` outside sshare. Never "fix" that by running `member sign` on your own —
   that command deliberately signs whatever is on disk and is for the maintainer to run after
   reviewing the printed list. The **first time** you use a vault on a machine, `add`/`rekey`
   refuse until you run `sshare trust accept` (verify the authority fingerprint out-of-band
   first). `get` (decrypt) is unaffected by trust.
7. **Never re-encrypt blobs you can't account for.** If `rekey` stops because some blobs
   "carry no vault binding", or `get`/`rekey` say a blob is "bound to a different vault",
   show the user the names — a blob nobody added may be ciphertext planted from another
   vault. `--migrate-legacy` is only for confirmed pre-0.7 secrets; `sshare rm <name>` removes
   a planted one.

## Task recipes (plain request → commands)

**"Get/pull secret X into my `.env`"** (e.g. "достань пароль db-prod мне в .env"):
```sh
sshare git pull   # get teammates' latest (optional but recommended)
printf '%s=%s\n' "DB_PASSWORD" "$(sshare get db-prod)" >> .env   # pick a sensible KEY name
```
If the stored secret *is itself* a full `.env` file: `sshare get prod/.env > .env`.
To export into the current shell instead: `export DB_PASSWORD="$(sshare get db-prod)"`.

**"Save/fix this token as a team secret"** (e.g. "зафиксируй токен в секретик команды"):
```sh
# Simplest at a terminal — type/paste the value at the hidden prompt:
sshare add github/ci-token
# Or from a file (keeps it out of shell history):
sshare add github/ci-token --file ./token.txt
# Or via stdin (for scripts):
printf '%s' '<the-token>' | sshare add github/ci-token
# Optionally attach a note (stored encrypted): add --description "CI token, rotate quarterly"
sshare git push        # the add auto-committed locally; this publishes it
```

**"Delete secret X"** (e.g. "удали секрет db-prod"):
```sh
sshare rm db-prod
sshare git push        # the rm auto-committed locally; this publishes it
```

**"Store this existing `.env` as a secret"**:
```sh
sshare add prod/.env --file .env
sshare git push
```

**"What secrets / members do we have?"**: `sshare ls` · `sshare member ls`
(Note: in the current version every member can read **every** secret — see Gotchas.)
To also see what each secret is for: `sshare ls --descriptions` (decrypts notes with your key).

**"Give <teammate> access"** (onboard — must be run by the maintainer, whose key signs):
```sh
sshare git pull
sshare member add bob --key ./bob.pub --identity ~/.ssh/id_ed25519   # re-signs + auto-commits
sshare rekey --identity ~/.ssh/id_ed25519   # re-encrypt all secrets to include Bob
sshare git push
```

**"Revoke <teammate>'s access"** (offboard — maintainer only):
```sh
sshare git pull
sshare member rm bob --identity ~/.ssh/id_ed25519
sshare rekey --identity ~/.ssh/id_ed25519
sshare git push
# Then ROTATE any secrets Bob could read — re-add them with new values; he may have copies.
```

**"First time using this vault on my machine"** (TOFU): if `add`/`rekey` says the authority
isn't trusted yet:
```sh
sshare trust            # shows the signing authority's fingerprint
# verify that fingerprint with the maintainer out-of-band (Slack/in person), then:
sshare trust accept
```

## Multi-step workflows

**Bootstrap a new vault** (e.g. "set up team secrets here"):
```sh
git init                                            # if not already a repo (enables autocommit)
sshare init                                         # creates AND connects the vault
sshare member add me --key ~/.ssh/id_ed25519.pub    # add yourself first (becomes maintainer)
sshare git remote add origin git@github.com:team/secrets.git
sshare git push -u origin main                      # publish (init/member add auto-committed)
```
Then add teammates (onboard recipe) and store the first secrets.

**Connect a team vault you've already cloned** (so you can use it by name from anywhere):
```sh
git clone git@github.com:team/secrets.git           # you clone it (sshare never does)
sshare connect ./secrets --name team
sshare get db-prod --vault team                      # now works from any directory
```

**Add yourself to an existing team vault**: ask a current member to run the onboard recipe
with your `~/.ssh/id_ed25519.pub`, then `sshare git pull` — now `sshare get` works for you.

## Gotchas (from the tool's actual behavior)

- **Every secret is encrypted to ALL members** in this version. There is *no* way to share
  a secret with only a subset; adding a member grants them read access to **everything**.
  If the user asks to share with just one person, say so honestly.
- **Passphrase-protected keys prompt on the terminal** (`ssh-agent is NOT used` — the key
  file is read directly). In a non-interactive agent shell the prompt will hang. If `get`
  /`rekey` blocks or fails on a passphrase, ask the user to run that one command themselves
  via the `!` prefix (e.g. `! sshare get db-prod`), or to use an unencrypted/`--identity`
  key.
- **`get` writes raw bytes to stdout** with no trailing newline — ideal for piping; add
  your own `=`/newline when composing a `.env` line.
- **Mutations auto-commit locally** when the vault is a git repo (you don't run `git
  add/commit`), but **push is explicit**: run `sshare git push` to publish, `sshare git pull`
  to fetch. Network happens *only* on `sshare git push`/`pull`/`fetch` — never on `add`/`get`.
  `SSHARE_NO_AUTOCOMMIT=1` disables autocommit for batch scripts.
- **`change saved but not committed`** means autocommit failed (usually no git identity, or a
  pre-commit hook). The secret is safely written **and staged** — set the identity with
  `sshare git config user.email you@example.com` (and `user.name`), then
  `sshare git commit -m "sshare: …"`. The data is never at risk; only the commit is pending.
- **Default keys**: decryption tries `~/.ssh/id_ed25519` then `~/.ssh/id_rsa`; pass
  `--identity <path>` for anything else. Member pubkeys default to your `~/.ssh/*.pub`.
- **Secret/member names** allow `[A-Za-z0-9._-]`; secrets may nest with `/`
  (`prod/api-token`). Names and the member key set are visible to anyone with repo
  access — only secret *values* are protected. Don't put sensitive data in a name.
- **Descriptions are encrypted** (unlike names), so a note *may* hold sensitive context. The
  trade-off: `sshare ls --descriptions` must decrypt with your SSH key, and descriptions are
  invisible to non-recipients (web review, CI). They re-encrypt on `rekey`, so a newly added
  member can read them and a removed one cannot. Only their existence/length leaks to the repo.
- **The member list is signed; changes need the maintainer key.** `member add`/`rm` verify
  the current signature, then re-sign with `--identity`; only the pinned maintainer may change
  membership. The first signer of a vault becomes its authority. On a new machine, `add`/
  `rekey` require `sshare trust accept` first (TOFU). Bootstrapping a vault you created
  (`init` + first `member add`) auto-pins you. A vault with members but **no** signature
  (pre-signing, or `members.sig` deleted) refuses `member add`/`rm` until the maintainer runs
  `sshare member sign` (interactive; `--yes` for scripts) after reviewing the printed list.
- **Secrets are bound to their vault (0.7+).** Every blob carries the vault id inside the
  encrypted payload; `get`/`rekey`/`ls -d` refuse a blob "bound to a different vault". Blobs
  from before 0.7 have no binding: `get` reads them fine, but `rekey` stops and lists them
  until run with `--migrate-legacy` (one-time, after checking the names). **All clients on a
  vault must upgrade together** — an old `sshare get` would print the header along with a new
  secret's value.
- Common errors: `not inside a vault — pass --vault <name>` (run `sshare vaults`, then use
  `--vault`, or `cd` into the repo); `no connected vault named '<n>'` (run `sshare vaults`
  to see the real names, or `sshare connect` it); `not yet trusted … run 'sshare trust
  accept'` (first use on this machine — verify out-of-band, then accept); `member list … may
  have been tampered with` (the members changed without a valid maintainer signature — also
  refuses `member add`/`rm`; tell the user, don't work around it); `has members but no
  signature … 'sshare member sign'` (unsigned legacy vault or deleted `members.sig` — the
  maintainer reviews and signs explicitly); `only this vault's maintainer … can change
  membership` (you signed with a non-authority key); `decryption failed — is your SSH key a
  recipient?` (not a member / wrong key); `blob(s) carry no vault binding … --migrate-legacy`
  (pre-0.7 secrets — show the names, then migrate once if all are expected); `bound to a
  different vault` (ciphertext copied in from another vault — `sshare rm` it).
- **The registry stores only names + local paths** in `~/.config/sshare/vaults` — never
  secrets, never git remotes. A `missing` status in `sshare vaults` means the path moved or
  was deleted; reconnect it with `sshare connect <new-path> --name <n>`.
