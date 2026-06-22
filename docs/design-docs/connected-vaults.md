# Connected Vaults

**Status:** Active · **Date:** 2026-06-22

## Problem

A vault is found only by walking up from the current directory, so to use one you must be
inside it, and nothing on the machine knows which vaults exist. An agent acting on the
user's behalf would have to search the filesystem for `.sshare/` directories.

## Decision

Maintain a **global registry** of vaults the user has *connected*, and let any command
target one by name. `connect` registers an **already-present local vault** — it does **not**
clone a repo or use the network. The user clones the team secrets repo the normal way
(`git clone`); sshare only records that it exists.

This keeps sshare's core invariant intact: **the CLI performs no git operations and no
network I/O.** Git stays the transport the user drives; `connect` is pure local bookkeeping.

## Model

- Registry file: `$SSHARE_CONFIG_HOME` → `$XDG_CONFIG_HOME/sshare` → `~/.config/sshare`,
  file `vaults`. Format: a header comment plus one `name<TAB>absolute-path` line per vault.
- It stores **only names and local paths**. No secrets (those stay encrypted in the vault),
  no remote URLs, no git state. The file is non-sensitive but does reveal where vaults live
  on disk — so it lives in the user's config dir, not in any shared repo.

## Resolution order (vault-using commands)

1. `--vault <name>` flag, or `SSHARE_VAULT` env → registry lookup.
2. Discover from the current directory (existing behavior — unchanged).
3. If exactly one vault is connected → use it.
4. Otherwise → error listing the connected vaults.

## Commands

- `sshare connect [PATH] [--name N]` — register the vault discovered from `PATH` (default:
  cwd). Idempotent: re-connecting updates the name.
- `sshare disconnect <name>` — unregister. Never deletes files (sshare didn't create them).
- `sshare vaults` — list connected vaults with status (`ok` / `current` / `missing`).
- `sshare init` also auto-connects the new vault (default name = directory name).

## Notes

- Stale entries (moved/deleted paths) are surfaced, not hidden: `vaults` shows `missing` and
  the resolver tells the user to reconnect.
- Paths are canonicalized at connect time. Paths containing a tab/newline, or non-UTF-8
  paths, are rejected (they'd break the line format) — pathological on real systems.
