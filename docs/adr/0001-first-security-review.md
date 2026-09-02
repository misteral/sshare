# ADR-0001: First security review — internal and adversarial; no third-party audit claimed

**Status:** Accepted — 2026-09-02 (findings fixed in v0.7.0)

## Context

sshare's security *is* the product: confidentiality comes entirely from `age` encryption to
SSH keys, and "who can grant decryption" is protected by a signed, TOFU-pinned member list.
Before v0.7.0 the tool had never had a dedicated security review. Two things prompted one:

- The README described the `age` format as **"audited."** That was inaccurate — neither the
  age spec, the Rust `age` crate, nor sshare itself has a published third-party audit — and
  the word was removed.
- The trust root had grown (encrypted descriptions, connected vaults, signed members) without
  an adversarial pass, and it concentrates in a few modules (`crypto.rs`, `vault.rs`,
  `sign.rs`, `trust.rs`) plus the release pipeline.

We ran the first structured review — threat model → per-dimension research → adversarial
per-finding verification — treating a **git committer who is not a recipient** as the primary
attacker (the model in [SECURITY.md](../SECURITY.md)). It found two real issues, and a
follow-up review of the fixes found that the fixes' own trust root leaned on file, name, and
encoding handling that same committer controls.

## Decision

1. **Internal adversarial review is our bar, and we describe it honestly.** We make **no
   claim** of a third-party audit of age or of sshare. Changes to `crypto.rs`, `vault.rs`,
   `sign.rs`, `trust.rs`, and the release workflow are security-sensitive and get a review
   pass with matching tests. An external audit, if it ever happens, earns its own ADR — it is
   not implied by this one.

2. **Findings are fixed at the trust root, not papered over.** Implemented in v0.7.0 and
   pinned by tests:
   - **Verify before mutate.** `member add`/`member rm` verify the signed member set *before*
     changing it; re-signing whatever is on disk would launder an injected `.pub`. The only
     path that signs an unverified set is the explicit, reviewed `member sign`.
   - **Vault-bound ciphertext.** Every secret carries its vault id inside the encrypted
     payload (`sshare/1\n<vault-id>\n…`), so `rekey` can no longer be used as a cross-vault
     decryption oracle. See [design-docs/vault-bound-ciphertext.md](../design-docs/vault-bound-ciphertext.md).
   - **Hostile-content hardening.** Symlink-safe reads *and* writes; member files ignored
     unless they are plain files with valid names and keys free of NUL/newline (so the signed
     `name\0pubkey` encoding is injective); untrusted ids and names are terminal-escaped; the
     vault id is read-only (never minted on read).

3. **Residual risks stay surfaced, not hidden.** TOFU is weakest on first use (verify the
   authority fingerprint out-of-band); revocation requires **rotation**, not just `rekey`;
   authority is a single maintainer. All documented in [SECURITY.md](../SECURITY.md).

## Consequences

- **Positive:** the signed-members and vault-binding guarantees now hold against a committer
  who controls repo contents; the posture is documented and testable (44 unit + 17 e2e,
  including the exact attack sequences); user-facing security claims are accurate.
- **Costs / limits:** an internal review is **not** a substitute for an independent audit; the
  v0.7.0 on-disk format change is breaking (clients upgrade together, one-time
  `rekey --migrate-legacy`).
- **Follow-ups** (see [exec-plans/tech-debt-tracker.md](../exec-plans/tech-debt-tracker.md)):
  a signed secrets manifest (per-secret provenance), multi-maintainer (N-of-M) signing,
  build-provenance + signed tags, and an external audit if adoption warrants it.

## References

- Threat model & boundary rules: [SECURITY.md](../SECURITY.md)
- Designs: [signed-members-list.md](../design-docs/signed-members-list.md),
  [vault-bound-ciphertext.md](../design-docs/vault-bound-ciphertext.md)
- Shipped changes: [CHANGELOG.md](../../CHANGELOG.md) `[0.7.0]`
