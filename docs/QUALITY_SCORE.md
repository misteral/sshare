# Quality Score

Per-module quality grade and known gaps. Update on a recurring cadence and whenever a
module changes materially. Grades: A (solid, tested, legible) → D (fragile, untested).

_Last reviewed: 2026-06-22 (post v0.1.1)._

| Module | Grade | Notes |
|---|---|---|
| `src/crypto.rs` | A | `age` isolated here; round-trip, wrong-key, multi-recipient, and unreadable-key (legacy-PEM / `.pub`) paths tested. Gap: the `PassphrasePrompt` callback (encrypted-key path) is not unit-tested. |
| `src/vault.rs` | A | Path-traversal guard, init/member/secret flows, and **atomic write** (no temp leftover) all tested. |
| `src/main.rs` | A− | Now covered by an end-to-end CLI test (`tests/cli.rs`: `init → member add → add → get → ls`). Gap: `~/.ssh` default-key resolution still has no direct test (the e2e test passes explicit `--key`/`--identity`). |
| `src/test_keys.rs` | n/a | Test-only fixtures (`#[cfg(test)]`). |
| `.github/workflows/*` | B | CI + release work and are exercised (v0.1.0/v0.1.1 shipped). Gaps: actions pinned by major tag not SHA; Node 20 deprecation warnings; no build-provenance/signing. |

## Top gaps to close next

1. Supply-chain hardening: build-provenance attestation + signed tags.
2. Direct tests for `~/.ssh` default-key resolution and the passphrase-prompt path.
3. Tamper-resistance: a maintainer-signed members list (see [SECURITY.md](SECURITY.md)).

See [exec-plans/tech-debt-tracker.md](exec-plans/tech-debt-tracker.md) for the full list.
