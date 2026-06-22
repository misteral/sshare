# Connected Vaults Execution Plan

## Goal

Let sshare remember vaults you've connected, so any command can target one by name from
anywhere — no walking the filesystem to find a `.sshare/`. **Git-free**: `connect`
registers an *already-cloned* local vault; it does not clone or touch the network.

## Design

- **Registry** at `$SSHARE_CONFIG_HOME` / `$XDG_CONFIG_HOME/sshare` / `~/.config/sshare`,
  file `vaults`, one `name<TAB>absolute-path` line per vault. Stores **only names + local
  paths — no secrets, no remotes, no git**.
- **Resolution order** for vault-using commands: `--vault <name>` (or `SSHARE_VAULT`) →
  registry lookup; else discover from cwd (today's behavior, unchanged); else if exactly
  one vault is connected, use it; else error that lists the connected vaults.
- New commands: `connect [PATH]` (register; PATH defaults to the vault discovered from cwd),
  `disconnect <name>` (unregister; never deletes files), `vaults` (list with status). `init`
  auto-connects the new vault.

## Sub-tasks

- [x] `registry.rs`: `Registry` with `load`/`load_from`/`save`, `connect`/`disconnect`,
  `path_of`/`list`; config-dir resolution honoring `SSHARE_CONFIG_HOME`/`XDG_CONFIG_HOME`.
  — unit tests via `load_from(tempdir)` (no env).
- [x] `vault.rs`: add `Vault::open(dir)` (exact) and `find_from(start)` (walk up); refactor
  `discover` onto `find_from`. — `open` test.
- [x] `main.rs`: global `--vault` flag; `Connect`/`Disconnect`/`Vaults` subcommands;
  `resolve_vault(selector)`; `cmd_init` auto-connect; route vault commands through resolver.
- [x] `tests/cli.rs`: connect → `vaults` → `get --vault NAME` from outside the vault;
  disconnect; all with `SSHARE_CONFIG_HOME` set to a temp dir (no real `~/.config`).
- [x] Docs: README commands, ARCHITECTURE (registry module + resolution + still-no-git),
  QUALITY_SCORE, CHANGELOG, the `sshare` skill, design-doc + index.
- [x] Gates green (`fmt`, `clippy -D warnings`, `test`), PR.

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-06-22 | `connect` registers an existing local vault, does **not** clone | Preserves the "CLI does no git / no network" invariant; git stays the user's job. |
| 2026-06-22 | Top-level `connect`/`disconnect`/`vaults` | Matches how the feature is spoken about; `member` stays the only group. |
| 2026-06-22 | Dependency-free `name<TAB>path` file, not TOML | Avoids a serde/toml dep for a 2-field index; fits the minimal-deps ethos. |
| 2026-06-22 | Config dir overridable via `SSHARE_CONFIG_HOME` | Makes the registry testable without touching real `~/.config`. |

## Known Risks

- **Stale entries** (path moved/deleted): `vaults` flags `missing`; resolver errors with a
  "reconnect it" hint instead of a confusing failure.
- **Non-UTF-8 / tab-containing paths** break the line format: rejected at `connect` time
  with a clear error (pathological on real systems).
- **New side effect of `init`** (writes the registry outside cwd): intended; documented.

## Outcome

Implemented on branch `feat/connected-vaults`. `src/registry.rs` added; `Vault::open`/
`find_from` added; `main.rs` gained `connect`/`disconnect`/`vaults`, the global `--vault`
flag, `resolve_vault`, and `init` auto-connect. 6 new unit tests + 1 e2e test
(`connect → vaults → get --vault → disconnect`); all gates green. Stayed strictly git-free
and dependency-free (no toml/serde). Docs updated (README, ARCHITECTURE, QUALITY_SCORE,
design-doc + index, CHANGELOG). Ships in v0.1.3. The `sshare` usage skill will be updated to
teach `vaults`/`--vault` once v0.1.3 is released.
