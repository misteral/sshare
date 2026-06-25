# Design Docs Index

Design decisions and the beliefs behind them.

| Title | Status | Date | File |
|---|---|---|---|
| Core Beliefs | Active | 2026-06-21 | [core-beliefs.md](core-beliefs.md) |
| Connected Vaults | Implemented | 2026-06-22 | [connected-vaults.md](connected-vaults.md) |
| Signed Members List (TOFU) | Implemented | 2026-06-23 | [signed-members-list.md](signed-members-list.md) |
| Git Integration (autocommit + passthrough) | Implemented | 2026-06-23 | [git-integration.md](git-integration.md) |
| Encrypted Secret Descriptions | Implemented | 2026-06-25 | [descriptions.md](descriptions.md) |

## Decisions captured elsewhere (and where)

| Decision | Where | Summary |
|---|---|---|
| `age` over GPG; embedded crate | [../../PRD.md](../../PRD.md) §9, [../ARCHITECTURE.md](../ARCHITECTURE.md) | Single static binary, no external crypto install, encrypts to SSH keys. |
| Access control = recipient set, no permission code | [../SECURITY.md](../SECURITY.md) | Decryption failure is the access boundary. |
| CLI does **no** git operations | [../ARCHITECTURE.md](../ARCHITECTURE.md) | User commits/pushes manually; PRD §5 "then commits" is aspirational, not implemented. |
| This repo is its own Homebrew tap | [../RELEASING.md](../RELEASING.md) | Binary-download formula regenerated per release; `homebrew-core` deferred until notable. |
| v0.1: every secret → all members | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../../PRD.md](../../PRD.md) §10 | Per-secret recipients/groups (`grant`/`revoke`) are roadmap, not built. |

## Open design questions (from PRD §10)

1. Recipient granularity: per-secret vs groups vs whole-vault (proposed: groups + overrides) — **still open**.
2. ~~Tamper-resistance of the members list~~ — **resolved** via the signed members list (TOFU); see [signed-members-list.md](signed-members-list.md).
3. Bootstrapping/admin: who may add members — **addressed** for v1: the first signer becomes the single maintainer/authority; multi-maintainer (N-of-M) is a future extension.
4. Convenience: `sshare exec -- <cmd>`, `.env` import/export, clipboard auto-clear — **still open**.
5. ~~Key types `ssh-rsa`~~ — **resolved**: both `ed25519` and `rsa` already work (verified in v0.1.1); `ecdsa`/`dsa` are not supported.
