# Encrypted Secret Descriptions Execution Plan

Implements [../../design-docs/descriptions.md](../../design-docs/descriptions.md).
Targets **v0.6.0** (additive, non-breaking).

## Goal

Give each secret an optional human-readable note, stored as its own `age` blob encrypted to
the same members as the value — so the git host only ever sees ciphertext, `get` stays
byte-exact, and revocation via `rekey` applies to notes too.

## Sub-tasks

- [x] `src/vault.rs`: `descriptions_dir()`/`desc_path()` (`.sshare/descriptions/<name>.age`,
  via the shared `sshare_dir()` helper); `write_description`/`read_description` (→
  `Option<Vec<u8>>`, `None` when absent)/`remove_description` (idempotent). Extract the
  atomic temp-file+rename out of `write_secret` into a shared `write_atomic` and reuse it.
  `remove_secret` cascades to `remove_description`.
- [x] `src/main.rs`:
  - `add` gains `--description`: `Some(text)` (re)writes an encrypted note, `Some("")`
    clears it, `None` leaves any existing one untouched.
  - `ls` gains `--descriptions`/`-d` + `--identity`/`-i`: lazily resolves the identity (no
    key needed unless a note must be decrypted), degrades per-secret on an undecryptable
    note (warn on stderr, still list the name), and collapses newlines for the aligned table.
  - `rekey` re-encrypts each description alongside its secret.
- [x] Unit tests (`vault.rs`): description round-trips and is not a secret; remove cascades
  and is idempotent.
- [x] E2E (`tests/cli.rs`): encrypted + listed + survives rekey (new member can read);
  set/keep/clear semantics; `ls --descriptions` degrades when one note can't be decrypted.
- [x] Docs: README + skill (command surface), ARCHITECTURE (vault layout), SECURITY
  (encrypted-note trade-off), design-doc + this plan, TESTING + QUALITY_SCORE, CHANGELOG.
- [x] Gates green; PR (#8); ships in v0.6.0.

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-06-25 | Encrypted sidecar blob (not plaintext, not in-blob envelope) | Same confidentiality/revocation as the value; keeps `get` byte-exact; no new dep. |
| 2026-06-25 | Separate `.sshare/descriptions/` tree (not `secrets/<name>.desc.age`) | Avoids collision with a secret named `<name>.desc`; keeps `secret_names()` a plain walk of `secrets/`. |
| 2026-06-25 | `ls --descriptions` degrades per-secret on a bad note | Mirrors per-fetch `get`; avoids a partial-list-then-abort listing. |
| 2026-06-25 | Lazy identity resolution in `ls --descriptions` | A vault with no notes never prompts for a key. |

## Known Risks

- **Description existence + length leak** to the repo (the value already leaks the same) —
  documented in SECURITY.md; values/notes both need rotation after a removal.
- **Stale notes before a `rekey`** are unreadable by a newly added member until `rekey`
  runs — same staleness window as secret values; handled by degrading the listing.

## Outcome

Implemented on branch `feat/secret-descriptions` (PR #8, squashed to `main`). `vault.rs`
gained the `descriptions/` accessors and the extracted `write_atomic`; `main.rs` gained
`--description` on `add`, `--descriptions`/`--identity` on `ls`, and description
re-encryption in `rekey`; `rm` cascades. A follow-up review hardened `ls --descriptions`
(per-secret degrade + newline collapse) and switched `members_dir`/`descriptions_dir` to the
shared `sshare_dir()` helper. 2 new unit tests + 3 e2e tests; all gates green. No new
dependencies, `get` untouched. Ships in **v0.6.0**.
