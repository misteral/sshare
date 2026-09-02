# Signed Members List (TOFU)

**Status:** Implemented — 2026-06-23 (ships in v0.2.0); amended 2026-08-29 (verify before
mutate, `member sign`) · **Date:** 2026-06-23

## Problem

Decryption is protected by cryptography (you need a recipient private key). **Membership is
not** — `add`/`rekey` encrypt to every `*.pub` in `.sshare/members/`, and sshare trusts
whatever files are there. So anyone with **git write access** can add/swap a recipient:

```sh
cp ~/.ssh/id_ed25519.pub .sshare/members/mallory.pub
git commit -am "…" && git push      # now every future add/rekey encrypts to Mallory too
```

"Can decrypt" requires a private key (high bar); "can grant decryption" requires only a
commit (low bar). This closes that gap by making the member set **tamper-evident**.

## Trust model: Trust On First Use (TOFU)

Mirrors SSH host keys / `known_hosts`:

1. A **maintainer** signs the member set with their SSH key. The signature is committed to
   the repo (`.sshare/members.sig`).
2. On the **first** interaction with a vault, sshare records ("pins") the maintainer's key
   fingerprint **locally, in the user's config dir — outside the repo**.
3. On every later interaction, sshare verifies the member set is signed by the **pinned**
   key. If the signer differs, it refuses loudly (like SSH's "host identification has
   changed") until the user explicitly re-pins.

**Why the pin must live outside the repo:** if it lived in `.sshare/`, a committer could
change the manifest *and* the pin together. Pinning in `~/.config/sshare/` (where the
connected-vault registry already lives) means a repo committer cannot touch it — that
separation is the whole protection.

## Artifacts

In the repo (public, committed):

```
.sshare/members/<name>.pub      # unchanged — the human-readable source of truth
.sshare/members.sig             # detached SSHSIG over the canonical member set + the
                                #   signer's public key (so verifiers know who signed)
```

On the host (per-user, never in the repo):

```
~/.config/sshare/trust          # vault-id -> pinned authority key fingerprint
                                #   (honors $SSHARE_CONFIG_HOME / $XDG_CONFIG_HOME)
```

Vault-id: a stable identifier independent of path/clone location (a random id written to
the plain-text file `.sshare/id` at init), so the pin follows the vault across
clones/renames.

## What gets signed

A deterministic, canonical serialization of the member set:

- sorted by name, each entry `name \0 pubkey-line`, joined with `\n`;
- prefixed with a context/version tag and the vault-id (prevents replaying a signature from
  another vault or another sshare feature).

The signature uses **SSHSIG** (the `ssh-keygen -Y sign` format) with a fixed namespace
`sshare-members`, so it can never be confused with any other SSH signature the maintainer
makes.

## Flows

- **`init`** — generate the vault-id; the initializer becomes the first authority. The first
  `member add` (signed with the initializer's private key) produces `members.sig` and pins
  that key locally.
- **`member add` / `member rm`** — must be performed by a maintainer, and (since
  2026-08-29) **verify before they mutate**: the current `members.sig` must be valid over
  the current `.sshare/members/` and signed by this machine's pinned authority, and the
  caller's key must be that authority. Only then: update `.sshare/members/`, regenerate the
  canonical set, re-sign, and print the signed set (name + key fingerprint). A tampered or
  unsigned list is refused with nothing written. The sole exception is bootstrap — no
  signature *and* no members (fresh `init`) — where the caller becomes the authority.
- **`member sign [--yes]`** — the one path that signs an *unverified* list, for a vault that
  predates signing or whose `members.sig` was removed. It reports what the current signature
  says (valid / INVALID / none), prints every member with their key fingerprint, and asks
  for confirmation (or `--yes`). Refused for a key other than the pinned authority. On a
  machine with **no** pin yet (a fresh clone), it will not re-sign a list that is *already
  validly signed* by an unrelated key — it directs you to `sshare trust accept` that signer
  instead — so it can't silently hand authority to whoever runs it; only when there is no
  valid signature to adopt (true legacy/recovery) does it sign and TOFU-pin the caller, which
  it says out loud.
- **`add` / `rekey` (encrypt-time — the critical enforcement point)** — **verify**
  `members.sig` against the pinned authority *before* encrypting to the recipient set.
  Refuse if the signature is missing, invalid, or by a non-pinned key. This is what stops
  secrets from ever being encrypted to an injected key.
- **`get` (decrypt)** — does not use the member set, so it's not blocked; but if the vault's
  trust is broken, print a prominent warning.
- **First use** — no local pin yet → TOFU: record the signer's fingerprint, print it, and
  suggest verifying it out-of-band (Slack/in person), exactly like accepting an SSH host key.
- **Authority change / rotation** — a changed signer triggers a hard error; the user
  re-pins explicitly with `sshare trust accept <fingerprint>` after confirming out-of-band.

## New commands

- `sshare trust` — show the vault's authority fingerprint, whether it's pinned, and match
  status.
- `sshare trust accept [<fingerprint>]` — pin (first use) or re-pin (rotation), with an
  explicit confirmation step.

## Signing implementation (decided: `ssh-key` crate)

`age` gives us encryption but **not** signing, so we need SSH-key sign/verify. The options
weighed were:

| Option | Pros | Cons |
|---|---|---|
| **`ssh-key` crate (RustCrypto)** — *recommended* | Pure-Rust SSHSIG sign+verify; keeps the single self-contained binary; same ecosystem as `age` | Adds a dependency (and transitive ed25519/rsa crates) |
| Shell out to `ssh-keygen -Y sign/verify` | No new Rust dep | Requires `ssh-keygen` present (breaks "self-contained, no external tools"); manage an allowed-signers file |

Recommendation: the `ssh-key` crate — it preserves the "single static binary, no external
crypto tooling" property, which is a core selling point. Passphrase-protected maintainer
keys reuse the existing `rpassword` prompt path.

## Invariants preserved

- **No git, no network** — signing/verifying is local crypto. The `.sig` is just a file the
  user commits like any other.
- **Single self-contained binary** — if we use the `ssh-key` crate (no external tools).
- **Access control is still the crypto** — this doesn't add a "permission gate"; it
  authenticates *which recipient set* is legitimate before encryption.

## Migration / backwards compatibility

**None needed — there are no vaults in the wild yet** (sshare is pre-1.0 and single-user).
So signing is **mandatory**: `add`/`rekey` hard-fail on a vault whose member set is missing
a valid signature by the pinned authority. This is a breaking change for any vault created
before v0.2.0 — re-`init` or run a one-time `sshare trust accept` after the first signed
`member add`. No warn-and-continue path.

## Risks & limits (be honest about these)

- **TOFU's weak moment is the first fetch.** If Mallory tampered *before* your very first
  use, you'd pin his key. Mitigation: out-of-band fingerprint verification — documented, not
  enforceable in software.
- **Single authority = single point of trust/failure.** If the maintainer leaves or their
  key is lost, membership can't be re-signed without a coordinated re-pin. A *set* of
  allowed signers (any one of N) is a natural v2 extension; v1 proposes a single authority
  for simplicity.
- **Doesn't retroactively protect already-leaked secrets** — same rotation caveat as member
  removal (see SECURITY.md).

## Decisions (locked 2026-06-23)

1. **Signing impl:** the **`ssh-key` crate** (pure Rust) — the sole importer of `ssh-key`,
   mirroring how `age` is isolated in `crypto.rs`. Keeps the single self-contained binary.
2. **Authority count:** **single maintainer** for v1 (one pinned authority key). N-of-M is a
   future extension.
3. **Enforcement:** **mandatory / hard-fail** — no legacy vaults to support.
4. **Signing key:** **reuse the maintainer's SSH key** (the `--identity` key, default
   `~/.ssh/id_ed25519`). SSHSIG is built for signing arbitrary data with an SSH key.

Implementation notes that follow from these:
- New module `src/sign.rs` is the only place `ssh-key` is imported.
- Vault id lives in a dedicated plain-text file `.sshare/id` (not `config.toml`) to avoid
  introducing a TOML parser; generated with the small `getrandom` crate at `init`.
- The trust pin store lives in the config dir (`src/trust.rs`), keyed by vault id.

## Amendment 2026-08-29: verify before mutate

The original flow above said a non-authority's change is "caught downstream" by `add`/
`rekey`. The 2026-08 security review found the gap in that reasoning: `member add`/`rm`
mutated `.sshare/members/` first and then signed **whatever was on disk**, without checking
the *existing* signature. So a committer could drop `mallory.pub` into the repo — refused by
everyone's `add`/`rekey`, as designed — and simply wait: the maintainer's next routine
`member add carol` or `member rm bob` re-signed the whole listing, Mallory included, with
the authority key. The `rekey` the tool then prompts for encrypted every secret to Mallory.
No test covered the sequence *inject → maintainer membership change → rekey*.

The fix moves verification to the front of the membership path (`authorize_membership_change`
in `main.rs`): verify the signed set exactly as `add`/`rekey` do, check the caller is the
authority, and only then touch the filesystem and re-sign. Refusal writes nothing, so a
failed attempt no longer leaves a stray `.pub` that desynchronizes the list. The signed set
is printed with key fingerprints so what was signed is visible. Because a non-empty unsigned
list can no longer be signed implicitly, `member sign` exists as the explicit, reviewed way
to do it. `tests/cli.rs` now pins the laundering sequence.

## Out of scope (v1)

Per-secret recipients/groups (separate item), multi-maintainer thresholds, key-transparency
logs, automatic rotation.
