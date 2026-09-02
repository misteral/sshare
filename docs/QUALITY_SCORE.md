# Quality Score

Per-module quality grade and known gaps. Update on a recurring cadence and whenever a
module changes materially. Grades: A (solid, tested, legible) → D (fragile, untested).

_Last reviewed: 2026-08-30 (post security review: verify-before-mutate membership,
vault-bound ciphertext, symlink/name/encoding hardening of the trust root)._

| Module | Grade | Notes |
|---|---|---|
| `src/crypto.rs` | A | `age` isolated here; round-trip, wrong-key, multi-recipient, and unreadable-key (legacy-PEM / `.pub`) paths tested. Gap: the `PassphrasePrompt` callback (encrypted-key path) is not unit-tested. |
| `src/vault.rs` | A | Path-traversal guard, init/member/secret flows, **atomic write** (no temp leftover; shared `write_atomic`), **encrypted descriptions**, and the **hostile-content hardening** (symlink-safe reads *and* writes, member files skipped unless plain/valid/unambiguous, invalid enumerated names skipped, non-minting vault id) all tested. |
| `src/main.rs` | A− | Covered by end-to-end CLI tests (`tests/cli.rs`: core flow + connect/`--vault`/disconnect + **descriptions** + the **security-review scenarios**: no-launder membership, `member sign` review/no-hijack, cross-vault refusal, legacy migrate gate, committed-symlink refusal). Gap: `~/.ssh` default-key resolution still has no direct test (tests pass explicit `--key`/`--identity`). |
| `src/registry.rs` | A | Connected-vault registry; `connect`/`disconnect`/lookup/idempotency/invalid-name/missing-file all unit-tested (via `load_from(tempdir)`), plus the e2e `connect`→`--vault`→`disconnect` path. |
| `src/sign.rs` | A | SSHSIG over the member set; sole `ssh-key` importer. Exposes a pre-loadable `Signer` (key decrypted before the vault is mutated). Unit-tested: sign/verify round-trip, fingerprint match, tamper → fail, garbage → fail, `pubkey_fingerprint`. |
| `src/trust.rs` | A | TOFU pin store; pin/lookup/re-pin/missing-file unit-tested, plus the e2e tamper-rejection and second-machine `trust accept` paths. |
| `src/git.rs` | A | System-`git` wrapper (autocommit + passthrough); sole git shell-out. Unit-tested (repo detect, scoped commit, no-op-when-clean) + e2e (autocommit, `git log` passthrough, `SSHARE_NO_AUTOCOMMIT`). |
| `src/test_keys.rs` | n/a | Test-only fixtures (`#[cfg(test)]`). |
| `.github/workflows/*` | B | CI + release work and are exercised (shipped through v0.2.0). Gaps: actions pinned by major tag not SHA; Node 20 deprecation warnings; no build-provenance/signing. |

## Top gaps to close next

1. Supply-chain hardening: build-provenance attestation + signed tags.
2. Direct tests for `~/.ssh` default-key resolution and the passphrase-prompt path
   (both `crypto::decrypt` and `sign`).
3. Multi-maintainer (N-of-M) signing authorities — signed members is single-authority today.

See [exec-plans/tech-debt-tracker.md](exec-plans/tech-debt-tracker.md) for the full list.
