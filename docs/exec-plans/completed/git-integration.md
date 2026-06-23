# Git Integration Execution Plan

Implements [../../design-docs/git-integration.md](../../design-docs/git-integration.md).
Shipped in **v0.3.0**.

## Goal

Stop the "forgot to commit/push" footgun: auto-commit vault changes locally, and expose
`sshare git` as a passthrough to the system git — without breaking the no-network-by-default
and single-binary properties.

## Sub-tasks

- [x] `src/git.rs` (sole git shell-out): `is_repo`, `autocommit` (stage `.sshare`+`secrets`,
  scoped change-detection, unscoped commit, no-op when clean), `passthrough` (inherit stdio,
  propagate exit code). Unit tests: repo detection, scoped commit, no-op-when-clean.
- [x] `vault.rs`: `has_secret` (for add-vs-update commit messages).
- [x] `main.rs`: `Git { args }` (trailing-var-arg passthrough) + `cmd_git`; `maybe_autocommit`
  (default-on, skip if not a repo or `SSHARE_NO_AUTOCOMMIT`, warn-not-fail) wired into
  `init`/`member add`/`member rm`/`add`/`rekey` with templated messages.
- [x] `tests/cli.rs`: autocommit happens, visible via `sshare git log`, clean tree;
  `SSHARE_NO_AUTOCOMMIT=1` leaves it uncommitted.
- [x] Docs: README (commands + Git integration section, fixed the stale "runs no git" line),
  ARCHITECTURE (git.rs + revised invariant), CODING_STANDARDS (git isolated to git.rs),
  QUALITY_SCORE, CHANGELOG, design-doc + index.
- [x] Gates green (27 unit + 7 integration, clippy `-D warnings`, fmt). No new dependency.

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-06-23 | Both `sshare git` passthrough AND autocommit in v1 | Mirrors `pass`; covers push/pull/log without enumerating commands. |
| 2026-06-23 | Autocommit default-on when the vault is a git repo | What the owner asked; local commit is low-risk (no network). |
| 2026-06-23 | Push/pull stay explicit; no auto-push/auto-pull | Keeps reads/scripts/agents off the network and away from auth hangs. |
| 2026-06-23 | Shell out to system `git`, isolated in `git.rs` | Preserves single static binary; delegates auth/remotes/hooks to the user's git. |
| 2026-06-23 | Unscoped `git commit` after scoped `git add` | A commit pathspec errors when `secrets/` is empty; scoped add already limits the commit. |

## Outcome

Landed on branch `feat/git-integration`. Autocommit is local-only; the network is touched
only on an explicit `sshare git push`/`pull`/`fetch`. The documented invariant was revised to
"no network by default; local autocommit for git repos; explicit `sshare git` for the
network; system git shelled out, never embedded." The `sshare` skill update (teach
`sshare git push` instead of the manual git dance) is deferred until v0.3.0 is released.
