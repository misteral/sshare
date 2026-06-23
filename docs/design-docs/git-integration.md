# Git Integration (autocommit + `git` passthrough)

**Status:** Implemented — 2026-06-23 (ships in v0.3.0) · **Date:** 2026-06-23

## Problem

Every mutation (`add`, `member add/rm`, `rekey`) leaves uncommitted changes in the vault
repo, and the CLI does nothing about it — the user must remember `git add/commit/push` (and
`git pull` before reading). Forgetting to push means teammates don't get the secret;
forgetting to pull means decrypting stale data. It's the tool's biggest day-to-day friction.

Precedent: `pass` (and its age-based fork `passage`) solve exactly this by **shelling out to
the system `git`** — auto-committing on every change and exposing a `pass git …` passthrough.
We adopt the same model.

## Decision (locked)

1. **`sshare git [args…]`** — passthrough: run `git` inside the resolved vault. Gives
   push/pull/log/status/remote/init — *all* of git — through one command, composing with
   `--vault` (`sshare git --vault team push` from anywhere).
2. **Autocommit, default-on** — after a successful mutation, if the vault is a git repo,
   automatically stage sshare's files and `git commit` locally with a generated message.
3. **Network stays explicit.** Autocommit is **local only**. Push/pull/fetch happen **only**
   when the user runs `sshare git push` / `pull` / … There is **no** auto-push and **no**
   auto-pull (so reads, scripts, and agents never hit the network or an auth prompt
   unexpectedly).
4. **Shell out to the system `git`** — never embed a git library or network stack. (git is
   already present: the vault is a git repo the user cloned.) Isolated in one module,
   `src/git.rs`, the way `age` is isolated to `crypto.rs` and `ssh-key` to `sign.rs`.

## `sshare git [args…]`

- Runs `git -C <vault-root> <args…>` with inherited stdio (so pagers, auth prompts, and
  `git`'s own output work normally); the child's exit code is propagated.
- Vault is resolved the usual way (`--vault` / `SSHARE_VAULT` / cwd / sole connected vault).
- This is the **only** path that can touch the network, and only on the user's explicit
  `push`/`pull`/`fetch`/`clone`.
- If `git` is not installed, fail with a clear message.

## Autocommit

- **When:** after `init`, `member add`, `member rm`, `add`, `rm`, `rekey` complete
  successfully.
- **Repo check:** `git -C <root> rev-parse --is-inside-work-tree`. If the vault is **not** a
  git repo, silently skip (a local-only vault still works — autocommit is a convenience, not
  a requirement).
- **Stage only sshare's files:** `git -C <root> add -- .sshare secrets` (never `git add -A` —
  don't sweep up unrelated files if the vault shares a repo with other content).
- **Commit:** detect changes scoped to our paths
  (`git diff --cached --quiet -- .sshare secrets`); if nothing is staged (e.g. re-adding an
  identical secret), skip. Otherwise `git -C <root> commit -m "<generated>"` — *unscoped*,
  because only sshare's paths were staged, and a commit pathspec would error when `secrets/`
  is still empty.
- **Failure is non-fatal (warn, don't fail).** The mutation already succeeded and is on
  disk; if the commit fails (no `user.email` configured, a pre-commit hook rejects it, etc.)
  print a warning to stderr and exit 0 — exactly the state you'd be in today, so the user can
  commit manually. Never lose the primary result over a commit hiccup.
- **Escape hatch:** `SSHARE_NO_AUTOCOMMIT=1` disables autocommit for that invocation — for
  scripts that add many secrets and want a single manual commit. (Default remains on.)

For `member add`/`rm`, autocommit runs **after** the re-sign, so the member file *and*
`members.sig` land in one commit.

### Generated commit messages

| Command | Message |
|---|---|
| `init` | `sshare: initialize vault` |
| `member add <name>` | `sshare: add member <name>` |
| `member rm <name>` | `sshare: remove member <name>` |
| `add <name>` (new) | `sshare: add secret <name>` |
| `add <name>` (existing) | `sshare: update secret <name>` |
| `rm <name>` | `sshare: remove secret <name>` |
| `rekey` | `sshare: rekey <N> secret(s) for <M> member(s)` |

Deterministic, templated per command (add-vs-update is decided by whether the `.age` file
existed before the write; `rekey` knows its counts). No AI, no free-text.

## Module

`src/git.rs` — the only place that shells out to `git`:
- `is_repo(root) -> bool`
- `autocommit(root, message) -> Result<()>` (stage `.sshare`+`secrets`, skip if clean)
- `passthrough(root, args) -> Result<ExitCode>` (inherit stdio, propagate status)

`main.rs` calls `git::autocommit` at the end of each mutating `cmd_*` (warn on error) and
routes `sshare git` to `git::passthrough`.

## Revised invariant

The documented invariant changes from "the CLI does no git operations and no network I/O" to:

> The CLI makes **no network calls by default**. It auto-creates **local** git commits when
> the vault is a git repo (no network). Network (push/pull/fetch) happens **only** via an
> explicit `sshare git <…>`. We shell out to the system `git`; we never embed a git library
> or a network stack. Read paths (`get`, `ls`, `vaults`) never commit or use the network.

ARCHITECTURE.md, SECURITY.md, and design-docs/index.md will be updated to this wording.

## Scripting & agent safety

- `get`/`ls`/`vaults` stay commit-free and network-free — pipelines and agents are unaffected.
- Autocommit is local, so mutations never hang on auth.
- Network is only ever an explicit `sshare git push`/`pull`, so an agent triggers it only
  when told to. The `sshare` skill's recipes switch from the manual git dance to
  `sshare git push` after changes.
- `SSHARE_NO_AUTOCOMMIT=1` lets a batch script make one commit instead of many.

## Risks & limits

- **No `user.email` / hooks failing** → autocommit warns and the change stays uncommitted
  (same as today). Documented.
- **`git push` auth in a non-interactive agent shell** can prompt/hang — but only on an
  explicit `sshare git push`, never implicitly. The skill notes to run it where auth works.
- **Confidentiality unchanged:** git only ever moves ciphertext (the repo is all `.age` +
  public keys), exactly as when the user pushes by hand.
- **Many commits** in a tight add-loop (one per secret) — acceptable (pass does the same);
  `SSHARE_NO_AUTOCOMMIT=1` is the batch escape hatch.

## Out of scope (v1)

- `sshare sync` (one-shot add+commit+pull+push) — sugar; `sshare git push`/`pull` + autocommit
  already cover it. Add later if wanted.
- Auto-pull / merge strategy beyond what the user's `git pull` does.
- Commit signing (`git commit -S`) — separate from our SSHSIG members signature.
