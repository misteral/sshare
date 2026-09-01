# Security

`sshare` is a secret-sharing tool: security *is* the product. Treat every change in
`crypto.rs`, `vault.rs`, `sign.rs`, and the release pipeline as security-sensitive.

## Threat model

| Protects against | Does **not** protect against |
|---|---|
| Repo/host leaks (GitHub etc. only ever see ciphertext) | A compromised endpoint that already holds a valid private key |
| Accidental plaintext commits (secrets are always encrypted before write) | Someone who already read/cached a secret before being revoked |
| Teammates without a recipient key reading a secret | A forged authority key accepted on a *first* TOFU pin (verify fingerprints out-of-band) |
| A malicious committer silently adding their own key as a recipient (signed members list + TOFU — see below) | |
| A committer planting ciphertext from *another* vault so `rekey` re-encrypts it to them (vault-bound payloads — see below) | A blob written before 0.7 has no binding: `rekey` lists such blobs and needs `--migrate-legacy` — the operator must check the names |
| A committed symlink redirecting where a secret is written or what `rekey` reads | |

## Access control is the crypto

There are **no permission checks in code**. Confidentiality comes entirely from `age`
encryption to SSH public keys; decryption succeeds only for a holder of a matching private
key. Any future authorization feature MUST be expressed as "who is a recipient", enforced
by re-encryption — never as a role/flag gate that could be bypassed by editing files.

## Boundary rules (parse, don't validate)

- **Every secret name** passes `validate_name` and **every member name** passes
  `validate_component` *before* touching the filesystem. These reject empty names, `.`,
  `..`, leading/trailing `/`, and any character outside `[A-Za-z0-9._-]`. This is the
  path-traversal guard — any new code that builds a path from user input must route
  through them (`vault.rs`).
- **SSH public keys are validated at `member add` time** (`crypto::parse_recipient`), so a
  bad key fails immediately rather than silently at encrypt time.
- **Ciphertext is parsed by `age`** on `get`/`rekey`; a non-age blob produces a clear
  error, never a panic.
- **Neither reads nor writes follow a symlink inside the vault** (`reject_symlinks_under`
  inspects every component below the root with `symlink_metadata`), and **symlinked entries
  are never listed or counted**. Lexical name validation cannot see a committed
  `secrets/prod -> /elsewhere` or a symlinked `members/x.pub`; only the filesystem can, so it
  is checked on every read and write. This keeps `rekey`'s "decrypt everything before writing
  anything" atomicity honest — a symlinked blob aborts the run before any secret is rewritten.
- **The signed member encoding is unambiguous.** A `members/<name>.pub` counts only if it is
  a plain file with an `add`-legal name and a key carrying no NUL or newline byte; otherwise
  it is skipped. Without this, `canonical_members` (`name\0pubkey\n`, no escaping) would be
  non-injective — one signature could cover two different parsed member sets — and a symlink
  or odd filename could diverge the bytes per machine or brick every membership command.
- **Untrusted text is escaped before printing** (`crypto::sanitize_for_display`): a foreign
  vault id in an error, a committed secret or member name in a listing. A planted name or
  blob therefore cannot inject terminal escape sequences or forge rows in the `member sign`
  review list.
- **`.sshare/id` must be one printable token** — it is embedded in the signed member set and
  in every encrypted payload header. It is read-only: a missing id is never silently minted
  (that would diverge clones), and a corrupt id does not block reading a legacy secret.

## Vault-bound ciphertext (`rekey` is not a decryption oracle)

`rekey` decrypts every secret with the operator's key and re-encrypts it to the members. If
blobs were bare `age` files, a committer in vault B could plant ciphertext from vault A —
any blob encrypted to a key that is a member of both — and B's next `rekey` would hand them
A's plaintext. So every payload sshare writes starts with `sshare/1\n<vault-id>\n` *inside*
the ciphertext (age has no associated data; inside is the only place it cannot be
rewritten without the plaintext):

- `get`, `ls --descriptions`, and `rekey` **refuse** a blob bound to a different vault.
- A blob with **no header** (pre-0.7, or from another age tool) still `get`s — printing to
  the operator's own stdout leaks nothing — but `rekey` **stops and lists** every such blob,
  and only re-encrypts them with `--migrate-legacy`. Re-encrypting is the dangerous step, so
  it happens only after the operator has seen the names; an unexpected one should be removed.
- `rekey` decrypts everything *before* writing anything, so one bad blob aborts the run
  without a half-rekeyed vault.

Design and trade-offs: [design-docs/vault-bound-ciphertext.md](design-docs/vault-bound-ciphertext.md).

## Secret handling

- **Plaintext leaves the process only via `get`'s raw stdout.** Never `print!`/`eprintln!`
  /`log` secret bytes, and never include them in error messages or `anyhow` context.
- **Private keys are read only inside `crypto::decrypt`.** Passphrases are read via
  `rpassword` (never echoed, never stored) through the `PassphrasePrompt` callback.
- **Prefer stdin** for input; `--value` is visible in shell history and the process list
  and is documented as discouraged.
- Secret *names* and the *set of member public keys* are visible to anyone with repo
  access — only secret *values* are protected. Do not put sensitive data in secret names.
- **Secret descriptions are encrypted** to the same members as the secret, stored as their
  own `age` blob under `.sshare/descriptions/<name>.age` — never plaintext in the repo. This
  is deliberate: a free-form note ("key for the PII export job") is exactly where sensitive
  context lands, so it gets the same confidentiality as the value (the git host only ever
  sees ciphertext). Consequences: reading a description requires a recipient key
  (`ls --descriptions` decrypts), `rekey` re-encrypts descriptions to the current member set
  so revocation applies to them too, and only a description's *existence and length* leak.

## Tamper-evidence: signed members list (TOFU)

The member set is the recipient set, so "who can grant decryption" must be as protected as
"who can decrypt." It is, via signing:

- A maintainer signs the canonical member set with their SSH key (SSHSIG, `sign.rs`); the
  signature lives in `.sshare/members.sig`.
- Each machine **pins** the authority's fingerprint on first use (TOFU) in the config dir
  (`trust.rs`), **outside the repo** — so a committer can't change both the members and the
  pin. `add`/`rekey` **verify** the signature against the pin before encrypting and
  hard-fail on mismatch; only the pinned maintainer may change membership.
- **Membership changes verify first, then mutate, then re-sign.** `member add`/`rm` run the
  same verification as `add`/`rekey` *before* touching `.sshare/members/`. Signing whatever
  is on disk would launder an injected `.pub` into a legitimately signed set the next time the
  maintainer adds or removes anyone — so a tampered or unsigned list is refused, nothing is
  written on refusal, and the signed set is printed (name + key fingerprint). The one
  exception is bootstrap: an unsigned vault with **no** members (fresh `init`).
- **The only way to sign an unverified list is `member sign`**, which is explicit by design:
  it prints every member with their key fingerprint and asks for confirmation (`--yes` for
  scripts). Use it for a vault that predates signing or whose `members.sig` was removed —
  after checking the list against what teammates actually sent.
- Design + trust model: [design-docs/signed-members-list.md](design-docs/signed-members-list.md).
- Residual risk: the **first** pin is trust-on-first-use — verify the authority fingerprint
  out-of-band (it can't be enforced in code). Decryption (`get`) is intentionally not gated
  (it doesn't use the member set); the protection is at encrypt time.

## Revocation caveat (must stay surfaced to users)

Removing a member and running `rekey` stops *future* access, but the revoked member may
already hold copies of secrets they could previously read. The `member rm` command prints
this warning; keep that warning whenever the revocation flow changes. Truly sensitive
secrets must be **rotated** after revocation.

## Supply chain

- Releases ship a `sha256` for every artifact, and the Homebrew formula pins those
  checksums (see [RELEASING.md](RELEASING.md)).
- The dependency set is pure-Rust (no `ring`/OpenSSL), which is why cross-compilation needs
  only a linker. `age`/`ssh-key`/`getrandom`/`rpassword`/`clap`. Adding a dependency that
  pulls in C/`openssl` is a notable change — flag it in review.
- **Open hardening items** (tracked in
  [exec-plans/tech-debt-tracker.md](exec-plans/tech-debt-tracker.md)): build-provenance
  attestation + signed tags for releases; multi-maintainer (N-of-M) signing authorities.
