# Design Docs Index

Design decisions and the beliefs behind them.

| Title | Status | Date | File |
|---|---|---|---|
| Core Beliefs | Active | 2026-06-21 | [core-beliefs.md](core-beliefs.md) |

## Decisions captured elsewhere (and where)

| Decision | Where | Summary |
|---|---|---|
| `age` over GPG; embedded crate | [../../PRD.md](../../PRD.md) §9, [../ARCHITECTURE.md](../ARCHITECTURE.md) | Single static binary, no external crypto install, encrypts to SSH keys. |
| Access control = recipient set, no permission code | [../SECURITY.md](../SECURITY.md) | Decryption failure is the access boundary. |
| CLI does **no** git operations | [../ARCHITECTURE.md](../ARCHITECTURE.md) | User commits/pushes manually; PRD §5 "then commits" is aspirational, not implemented. |
| This repo is its own Homebrew tap | [../RELEASING.md](../RELEASING.md) | Binary-download formula regenerated per release; `homebrew-core` deferred until notable. |
| v0.1: every secret → all members | [../ARCHITECTURE.md](../ARCHITECTURE.md), [../../PRD.md](../../PRD.md) §10 | Per-secret recipients/groups (`grant`/`revoke`) are roadmap, not built. |

## Open design questions (from PRD §10)

1. Recipient granularity: per-secret vs groups vs whole-vault (proposed: groups + overrides).
2. Tamper-resistance of the members list (signed members file).
3. Bootstrapping/admin: who may add members.
4. Convenience: `sshare exec -- <cmd>`, `.env` import/export, clipboard auto-clear.
5. Key types: `ssh-ed25519` first; whether to allow `ssh-rsa`.
