# Tech Debt Tracker

Prioritized, known debt. Link an item to an execution plan in `active/` when work starts.

| Item | Priority | Area | Notes |
|---|---|---|---|
| Release bot pushes formula to `main` | High (before branch protection) | CI/release | When `main` is protected, allow the `github-actions` bot to push or switch the step to open a PR — otherwise releases break. See [../RELEASING.md](../RELEASING.md). |
| Build-provenance attestation + signed tags | Medium | supply chain | `actions/attest-build-provenance` in `release.yml` + `git tag -s`; verifiable with `gh attestation verify`. |
| Per-secret recipients / groups (`grant`/`revoke`) | Medium | feature | v0.1 encrypts every secret to all members. PRD §7/§10.1. |
| Bump GitHub Actions off Node 20 | Low | CI/release | `actions/checkout`, `upload-artifact`, `download-artifact` log Node 20 deprecation; bump to v5 when stable. |
| Pin actions by commit SHA | Low | supply chain | Currently pinned by major tag (`@v4`). SHA-pin for tamper resistance. |
| `homebrew-core` submission | Low | distribution | Once notable; needs a from-source formula + PR. See [../RELEASING.md](../RELEASING.md). |
| Decide `ssh-rsa` support | Low | feature | PRD §10.5 — `ssh-ed25519` works today; decide whether to accept RSA keys. |
| `sshare exec` / `--clip` / `.env` import-export | Low | feature | PRD §10.4 convenience features. |

## Resolved

- **Atomic secret writes** — `write_secret` now writes a temp file + renames (2026-06-22).
- **End-to-end CLI test** — `tests/cli.rs` drives the built binary (2026-06-22).
- **Signed members list** — SSHSIG signing + TOFU pinning + verify-before-encrypt makes the
  member set tamper-evident (2026-06-23, ships in v0.2.0). Follow-up: multi-maintainer (N-of-M).
