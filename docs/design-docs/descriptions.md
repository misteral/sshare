# Encrypted Secret Descriptions

**Status:** Implemented — 2026-06-25 (ships in v0.6.0) · **Date:** 2026-06-25

## Problem

A secret was just a name (`secrets/<name>.age`) — there was nowhere to record *what it is
for*, *where it came from*, or *how to rotate it*. `prod/api-token` doesn't say "Stripe
live key, rotate quarterly, owner: payments". Teams worked around this with out-of-band
notes (Slack, a wiki) that drift from the vault. We want an optional human-readable note
attached to each secret, without weakening the core promise: **the git host only ever sees
ciphertext.**

## Decision: an encrypted sidecar blob

A description is stored as **its own `age` blob, encrypted to the same members as the
secret**, in a separate tree:

```
<root>/.sshare/descriptions/<name>.age   # optional; same recipients as secrets/<name>.age
```

Alternatives weighed (and why rejected):

| Option | Why not |
|---|---|
| **Plaintext sidecar** (`descriptions/<name>.txt`) | Leaks the note to anyone with repo access — exactly the context ("key for the PII export job") most worth protecting. Defeats the point. |
| **In-blob envelope** (CBOR/JSON `{value, description}` inside the secret's `age` blob) | Makes `get` fallible and **no longer byte-exact** (it would have to parse + strip the envelope), breaks every pre-0.6 secret, and adds a serialization dependency. `get` staying a raw passthrough is a hard requirement. |
| **Encrypted sidecar blob** (chosen) | Same confidentiality and revocation story as the value; `get` is untouched and byte-exact; no new dependency (reuses `crypto.rs`); old secrets simply have no sidecar. |

### Why a separate `descriptions/` tree, not `secrets/<name>.desc.age`

Putting the note beside the secret (`secrets/<name>.desc.age`) collides with a secret
literally named `<name>.desc`, and would force `secret_names()` to filter `.desc.age` out of
its walk. A dedicated `.sshare/descriptions/` tree keeps the two namespaces disjoint:
`secret_names()` stays a plain walk of `secrets/`, and a description can never be mistaken
for (or shadow) a secret.

## Lifecycle — handled everywhere a secret is

| Command | Behavior |
|---|---|
| `add <name> --description <text>` | Encrypts the note to the current members. Omit the flag → keep any existing note; `--description ""` → clear it (idempotent: clearing a missing one is fine). |
| `ls --descriptions` (`-d`) `[--identity]` | Decrypts and shows each note. Plain `ls` is unchanged (name-only, needs no key, can't fail). The identity is resolved **lazily** — a vault with no descriptions never prompts for a key. |
| `rekey` | Re-encrypts each description alongside its secret, so a newly added member can read it and a removed one cannot — revocation applies to notes too. |
| `rm` | Cascades to the description blob, so removing a secret leaves nothing orphaned (this also closed a latent orphan-file gap). |
| `get` | **Untouched** — still a raw, byte-exact passthrough of the value blob. |

### Robustness of `ls --descriptions`

A single undecryptable note (e.g. a stale blob not yet `rekey`ed to your key) **degrades
per-secret** rather than aborting the whole listing: the name is still printed, a warning
goes to **stderr**, and the listing continues. This mirrors how `get` fails one fetch
without affecting others, and avoids the worst case of printing a partial list and then
erroring. Newlines in a note are collapsed to spaces so one secret stays one row in the
aligned table.

## Security properties

- **Confidentiality:** a description gets the same protection as the value — the repo holds
  only `age` ciphertext. Reading it requires a recipient private key.
- **Revocation:** `rekey` re-encrypts descriptions to the current member set, so removing a
  member (then `rekey`) revokes their access to notes exactly as it does to values.
- **What leaks:** only a description's **existence and length** (a file in
  `descriptions/`). As with secret values, the same "already-copied" rotation caveat
  applies. See [../SECURITY.md](../SECURITY.md).

## Invariants preserved

- **No git, no network** — descriptions are local files committed like any other.
- **Single self-contained binary** — no new dependency; encryption reuses `crypto.rs`, the
  sole `age` importer.
- **Access control is still the crypto** — a description is readable iff your key is a
  recipient; no permission flag is introduced.
- **`get` is byte-exact** — the value blob is never touched by this feature.

## Migration / backwards compatibility

None needed. A pre-0.6 secret simply has no `descriptions/<name>.age`; `read_description`
returns `None` and `ls --descriptions` prints the name alone. Descriptions are purely
additive and optional.

## Out of scope

Structured metadata or tags, full-text search over descriptions, and per-field recipients
(a description always shares the secret's recipient set). Per-secret recipients/groups
remain a separate roadmap item (see [index.md](index.md) and the tech-debt tracker).
