# Quality Score

Per-module quality grade and known gaps. Update on a recurring cadence and whenever a
module changes materially. Grades: A (solid, tested, legible) → D (fragile, untested).

_Last reviewed: 2026-06-25 (post v0.6.0: encrypted secret descriptions)._

| Module | Grade | Notes |
|---|---|---|
| `src/crypto.rs` | A | `age` isolated here; round-trip, wrong-key, multi-recipient, and unreadable-key (legacy-PEM / `.pub`) paths tested. Gap: the `PassphrasePrompt` callback (encrypted-key path) is not unit-tested. |
| `src/vault.rs` | A | Path-traversal guard, init/member/secret flows, **atomic write** (no temp leftover; shared `write_atomic`), and **encrypted descriptions** (round-trip, not-a-secret, `rm` cascade, idempotent remove) all tested. |
| `src/main.rs` | A− | Covered by end-to-end CLI tests (`tests/cli.rs`: core flow + connect/`--vault`/disconnect + **descriptions** encrypt/list/rekey/clear/degrade). Gap: `~/.ssh` default-key resolution still has no direct test (tests pass explicit `--key`/`--identity`). |
| `src/registry.rs` | A | Connected-vault registry; `connect`/`disconnect`/lookup/idempotency/invalid-name/missing-file all unit-tested (via `load_from(tempdir)`), plus the e2e `connect`→`--vault`→`disconnect` path. |
| `src/sign.rs` | A | SSHSIG over the member set; sole `ssh-key` importer. Unit-tested: sign/verify round-trip, fingerprint match, tamper → fail, garbage → fail. |
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
