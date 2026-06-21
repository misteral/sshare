# AGENTS.md

`sshare` is a single-binary Rust CLI that shares team secrets by encrypting them to
members' SSH **public** keys (embedded `age` format) and storing the ciphertext in a git
repo. Only a matching SSH **private** key can decrypt — that *is* the access control. No
server, no accounts, no external `age`/`gpg`.

This file is a map. Full documentation lives in `docs/`. **Read the relevant doc before
starting a task** — every rule below is expanded there.

## Commands

```sh
cargo build --release          # -> target/release/sshare
cargo test --locked            # all unit tests (inline in src; no tests/ dir)
cargo test wrong_key_cannot_decrypt   # single test by name
cargo clippy --all-targets --locked -- -D warnings   # CI gate: pedantic lints fail
cargo fmt --all -- --check     # CI gate: formatting
```

Run the three CI gates (test, clippy, fmt) before pushing — a clean local run = green CI.
Rust edition 2024 (≥ 1.85). See [docs/TESTING.md](docs/TESTING.md).

## Documentation index

| File | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module map, `main → vault → crypto` layering, on-disk layout, data flows |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, access-control-is-crypto, boundary rules, revocation caveat |
| [docs/CODING_STANDARDS.md](docs/CODING_STANDARDS.md) | Edition, lints-as-gates, error handling, forbidden patterns |
| [docs/TESTING.md](docs/TESTING.md) | Running checks/tests, single test, test layout, manual E2E |
| [docs/RELEASING.md](docs/RELEASING.md) | Tag → cross-build → GitHub Release → Homebrew formula; versioning, changelog |
| [docs/RELIABILITY.md](docs/RELIABILITY.md) | Error handling, atomicity gaps, performance properties |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | PR/branch/commit workflow, git rules, GitHub |
| [docs/QUALITY_SCORE.md](docs/QUALITY_SCORE.md) | Per-module grades and top gaps |
| [docs/design-docs/core-beliefs.md](docs/design-docs/core-beliefs.md) | Agent-first operating principles |
| [docs/design-docs/index.md](docs/design-docs/index.md) | Design decisions; built vs planned |
| [docs/product-specs/index.md](docs/product-specs/index.md) | Pointer to [PRD.md](PRD.md) |
| [docs/exec-plans/tech-debt-tracker.md](docs/exec-plans/tech-debt-tracker.md) | Prioritized known debt |

## First message

If the first message has no concrete task: read [README.md](README.md), then ask which
area to work on. Based on the answer, read the relevant `docs/` file before acting.

## Critical rules

- **Secrets never leak.** Plaintext exits only via `get`'s stdout — never in logs, errors,
  or `anyhow` context. ([docs/SECURITY.md](docs/SECURITY.md))
- **`age` types stay in `crypto.rs`** (sole exception: the `Recipient` return type in
  `vault.rs`). Don't add a second encryption path. ([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md))
- **All user-supplied names go through `validate_name`/`validate_component`** before any
  path is built (path-traversal guard).
- **Access control is the crypto** — express authorization as recipient membership +
  re-encryption, never a role/flag gate.
- **Lints are gates.** `clippy --pedantic -D warnings` must stay clean; keep `Cargo.lock`
  committed (the `--locked` gates need it).
- **`Formula/sshare.rb` is generated** by `release.yml` — edit the workflow heredoc, not
  the formula. Don't hand-edit GitHub Releases.
- **Don't commit/push unless asked.** Branch off `main` for non-trivial work.
