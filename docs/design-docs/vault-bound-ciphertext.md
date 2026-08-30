# Vault-Bound Ciphertext

**Status:** Implemented — 2026-08-29 (ships in the next minor) · **Date:** 2026-08-29

## Problem

`rekey` re-encrypts every `secrets/*.age` to the current member set: decrypt with the
operator's SSH key, encrypt to all members, write back. Before this change a secret blob was
a bare `age` file — nothing said *which vault* it belonged to. Combined with the fact that a
vault's files come from git (i.e. from any committer), that made `rekey` a **decryption
oracle**:

1. Alice is a recipient in vault **A** (tight membership, e.g. production) and in vault **B**
   (looser, e.g. a project with contractors). Both use her one SSH key — that is the whole
   point of the tool.
2. Mallory is a member of B with push access to B's repo, and can read A's repo (the threat
   model explicitly allows that: "GitHub only ever sees ciphertext").
3. Mallory copies `A/secrets/db-prod.age` into B as `secrets/db-prod.age` — or overwrites an
   existing B secret's blob so `ls` and the "Re-encrypted N" count show nothing new.
4. Alice runs `sshare rekey` in B (the tool tells her to after every membership change).
   `age` happily decrypts A's blob with her key; sshare re-encrypts the plaintext to B's
   members. Mallory pulls and runs `sshare get db-prod`.

Found in the 2026-08 security review. Without a second source of ciphertext the attack
yields nothing (every same-vault blob is already encrypted to all members), which is why
multi-vault use with overlapping recipients is the load-bearing precondition — and why the
fix must make blobs from different vaults distinguishable *to the tool*.

## Decision: bind the payload to the vault id, inside the ciphertext

Every blob sshare writes now encrypts

```text
sshare/1\n<vault-id>\n<secret bytes>
```

rather than the bare secret bytes. `<vault-id>` is the stable random id in `.sshare/id`
(the same one the signed member set already includes). On decrypt, `crypto::decrypt`
strips the header and reports the binding:

| Payload | Result |
|---|---|
| header with **this** vault's id | `Binding::Bound` — normal case |
| header with **another** vault's id | **error** ("bound to a different vault") — `get`, `rekey`, and `ls --descriptions` all refuse |
| no header | `Binding::Legacy` — a pre-0.7 blob (or one from another age tool); caller decides |

Why *inside* the ciphertext: `age` has no associated data, so a header outside the payload
could simply be rewritten by whoever plants the blob. Inside, forging this vault's id onto
foreign ciphertext requires the plaintext — which is exactly what the attacker lacks.

### Alternatives weighed

| Option | Why not |
|---|---|
| **Signed manifest of secrets** (paths + hashes, signed like the member list) | Every `add` would need the maintainer's signature, breaking "any member can store a secret". Might still come as an *additional* layer (see tech-debt tracker). |
| **Detection only** (`rekey` prints the names it will re-encrypt) | Does nothing against overwriting an existing secret's blob; relies on the operator noticing. Kept as a *complement* for legacy blobs (below), not as the fix. |
| **Trust git history** (only re-encrypt blobs whose last commit is by a member) | Author fields are forgeable; sshare does not embed git and never verifies commits. |
| **Bind via age recipients** (e.g. a per-vault key) | Changes the whole key model; members' SSH keys are the product. |

## Legacy blobs and `--migrate-legacy`

A blob with no header cannot be told apart from planted foreign ciphertext produced by any
other age tool, so re-encrypting it is precisely the risky step. `rekey` therefore:

1. **Decrypts everything first** (phase 1), aborting the whole run on the first blob that is
   undecryptable or bound elsewhere — no half-rekeyed vault.
2. If any blob is unbound and `--migrate-legacy` was **not** given, **stops and lists them**
   (secret names, and `<name> (description)` for descriptions), telling the operator to check
   that every name is one they expect and to `sshare rm` any that is not.
3. With `--migrate-legacy`, re-encrypts them too, so they come out bound (phase 2). After one
   such run a vault has no legacy blobs left, and any unbound blob that appears later is
   suspicious by construction.

`get` accepts legacy blobs without ceremony: decrypting to the operator's own stdout gives
an attacker nothing, and locking people out of their pre-0.7 secrets would be pure
breakage.

## Compatibility

- **Reading old vaults:** works unchanged (legacy = accepted by `get`/`ls -d`; `rekey`
  needs the one-time flag).
- **Old clients reading new blobs:** a pre-0.7 `sshare get` prints the header bytes along
  with the value. Teams must **upgrade clients together** before the first `add`/`rekey`
  with the new version; this is a MINOR bump per [../RELEASING.md](../RELEASING.md) and is
  called out in the CHANGELOG. There are no wild-format consumers besides sshare itself.
- `.sshare/id` is now validated to be a single printable token, since it is embedded in
  both the signed member set and every payload header.

## Invariants preserved

- **`get` is byte-exact** — the header is stripped; the value is written raw as before.
- **`age` stays confined to `crypto.rs`** — the framing is part of the payload format, so it
  lives there too (`encrypt`/`decrypt` take the vault id; `vault.rs`/`main.rs` never see
  `age` types).
- **No new dependency**, no network, single binary.
- **Access control is still the crypto** — the binding does not gate *who* may decrypt; it
  only lets the tool refuse to *act on* ciphertext that was never this vault's.

## Related

The same review fixed a second gap in the signed-members flow (re-signing without
verifying first); see the 2026-08-29 amendment in
[signed-members-list.md](signed-members-list.md). Together: membership can only be changed
from a verified signed set, and `rekey` only ever re-encrypts this vault's own secrets.
