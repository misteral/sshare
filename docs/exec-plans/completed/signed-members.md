# Signed Members List Execution Plan

Implements [../../design-docs/signed-members-list.md](../../design-docs/signed-members-list.md)
(TOFU). Targets **v0.2.0** (breaking: signing becomes mandatory).

## Goal

Make the member set tamper-evident: a committer can't add/swap a recipient key without
detection. A maintainer signs the member set (SSHSIG, reusing their SSH key); clients pin
the authority fingerprint on first use (TOFU) and verify before encrypting.

## Sub-tasks

- [x] Deps: add `ssh-key` (features `ed25519`, `rsa`, `encryption`) and `getrandom`. Build
  to confirm the fetch works in this environment.
- [x] `src/sign.rs` (sole `ssh-key` importer): `sign(canonical, identity_path) -> armored
  SSHSIG` (namespace `sshare-members`, passphrase via the existing `rpassword` path);
  `verify(canonical, armored) -> signer fingerprint` (validates the embedded pubkey's
  signature, returns its SHA256 fingerprint). Unit tests: round-trip, tamper → fail,
  wrong-namespace → fail.
- [x] `src/vault.rs`: `vault_id()` (read/create `.sshare/id`), `canonical_members()`
  (vault-id + sorted `name\0pubkey`), `read/write_members_sig()` (`.sshare/members.sig`).
- [x] `src/trust.rs` (config dir, like the registry): pin store `vault-id -> SHA256:fp`;
  `pinned(id)`, `pin(id, fp)`; honors `$SSHARE_CONFIG_HOME`. Unit tests via `load_from`.
- [x] `src/main.rs`:
  - `init` writes `.sshare/id`.
  - `member add`/`rm` gain `--identity` (signing key); establish authority on first signing
    (pin it), else require the signer == pinned authority; re-sign + write `members.sig`.
  - `add`/`rekey`: **verify** `members.sig` signer == pinned authority before encrypting;
    hard-fail otherwise (missing/invalid/unpinned).
  - `trust` (show authority + pin status) and `trust accept [<fp>]` (pin / re-pin).
- [x] `tests/cli.rs`: maintainer signs → second user TOFU-pins → tamper (inject a `.pub`,
  re-sign with a different key) is rejected by `add`/`rekey`; `trust accept` re-pins.
- [x] Docs: README (commands + a "Tamper-evidence / trust" note), ARCHITECTURE (sign/trust
  modules + verify-before-encrypt), SECURITY (close the unauthenticated-members gap),
  QUALITY_SCORE, CHANGELOG, the `sshare` skill; move this plan to `completed/`.
- [x] Gates green; PR.

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-06-23 | TOFU trust model | Matches SSH host-key UX; pin lives outside the repo so a committer can't touch it. |
| 2026-06-23 | `ssh-key` crate for SSHSIG | Pure Rust, keeps the single static binary; isolated in `sign.rs`. |
| 2026-06-23 | Single authority; mandatory signing | No vaults in the wild; simplest correct v1. |
| 2026-06-23 | Reuse the maintainer's SSH key | Already present; SSHSIG is built for it. |
| 2026-06-23 | vault-id in `.sshare/id` (not config.toml) | Avoids adding a TOML parser. |

## Known Risks

- **TOFU first-fetch** is the trust assumption — document out-of-band fingerprint check;
  not enforceable in code.
- **New deps** (`ssh-key`, `getrandom`): adding the first non-`age` crypto crate. Pure-Rust,
  flagged in CODING_STANDARDS terms; confirm the fetch works in CI.
- **Breaking change**: vaults without a signature stop working with `add`/`rekey`. Acceptable
  pre-1.0 with no external users.
- **Decrypt (`get`) is not gated** — it doesn't use the member set; protection is at
  encrypt time. Documented.

## Outcome

Implemented on branch `feat/signed-members`. New modules `src/sign.rs` (sole `ssh-key`
importer: SSHSIG sign/verify/fingerprint) and `src/trust.rs` (TOFU pin store). `vault.rs`
gained `vault_id`/`canonical_members`/`read|write_members_sig`; `main.rs` gained the `trust`
command, `--identity` on `member add`/`rm`, `sign_and_pin_members`, and
`verify_members_trusted` (gating `add`/`rekey`). Deps `ssh-key` + `getrandom` added (pure
Rust). 6 new unit tests (sign + trust) and the e2e suite covers happy-path, tamper-rejection,
TOFU `trust accept`, and non-maintainer-blocked. All gates green; smoke-tested with the real
binary. Docs updated (README, ARCHITECTURE, SECURITY, CODING_STANDARDS, QUALITY_SCORE,
CHANGELOG). Ships in **v0.2.0**. Skill update deferred until v0.2.0 is released.
