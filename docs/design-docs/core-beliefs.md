# Core Beliefs

Agent-first operating principles for `sshare`.

1. **Repository is the system of record.** Decisions, plans, and context live in the repo
   (`docs/`, `CHANGELOG.md`, git history), not in chat or external trackers.
2. **AGENTS.md is a map, not a manual.** A short table of contents with pointers into
   `docs/`. Every token there competes with the task in context.
3. **Legibility over cleverness.** Code must be understandable to a future agent run. The
   one-directional `main → vault → crypto` layering exists for exactly this reason.
4. **Enforce invariants mechanically.** `clippy --pedantic -D warnings`, `fmt --check`, and
   the path-traversal/round-trip tests are the guardrails — prose reminders are backup, not
   primary.
5. **Corrections are cheap; waiting is expensive.** Short-lived PRs, minimal blocking gates,
   automated releases.
6. **Golden principles over ad-hoc cleanup.** Encode taste once (see below), enforce
   continuously.

## Project-specific beliefs

7. **Access control is the crypto, never a code path.** Authorization is "who holds a
   recipient private key." Never add a role/flag gate that could be bypassed by editing a
   file — express access as recipient membership + re-encryption. See
   [../SECURITY.md](../SECURITY.md).
8. **`age` lives in one module.** All encryption knowledge is contained in `crypto.rs` so it
   can be audited or swapped in one place.
9. **Validate at the boundary.** User-supplied names are parsed/validated before any path is
   built; bad SSH keys are rejected at `member add` time, not at encrypt time.
10. **Secrets never leak through the program.** Plaintext exits only via `get`'s stdout —
    never logs, errors, or shell-history-visible flags.
11. **No new infrastructure.** A git repo + SSH keys are the entire system; the CLI stays
    offline and dependency-light (pure-Rust, single static binary).
