# Quality Score

Per-module quality grade and known gaps. Update on a recurring cadence and whenever a
module changes materially. Grades: A (solid, tested, legible) → D (fragile, untested).

_Last reviewed: 2026-06-21 (v0.1.0)._

| Module | Grade | Notes |
|---|---|---|
| `src/crypto.rs` | A | `age` isolated here; round-trip, wrong-key, and multi-recipient paths tested. Gap: the `PassphrasePrompt` callback (encrypted-key path) is not unit-tested. |
| `src/vault.rs` | A− | Path-traversal guard tested; init/member/secret flows tested. Gap: `write_secret` is non-atomic (`fs::write`) — see [RELIABILITY.md](RELIABILITY.md). |
| `src/main.rs` | B | Thin CLI glue, but `cmd_*` functions and `~/.ssh` default-key resolution have no direct tests; there is no end-to-end CLI test. |
| `src/test_keys.rs` | n/a | Test-only fixtures (`#[cfg(test)]`). |
| `.github/workflows/*` | B | CI + release work and are exercised (v0.1.0 shipped). Gaps: actions pinned by major tag not SHA; Node 20 deprecation warnings; no build-provenance/signing. |

## Top gaps to close next

1. End-to-end CLI test covering `init → member add → add → get` in a tempdir (raises
   `main.rs` to A−).
2. Atomic secret writes (temp-file + rename) in `vault.rs`.
3. Supply-chain hardening: build-provenance attestation + signed tags.

See [exec-plans/tech-debt-tracker.md](exec-plans/tech-debt-tracker.md) for the full list.
