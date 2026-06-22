# Reliability

## Error handling

- The program never panics on user input or I/O. Every fallible path returns
  `anyhow::Result` with `.context(...)`; `main` returns `Result<()>` so failures print a
  message and exit non-zero. See [CODING_STANDARDS.md](CODING_STANDARDS.md).
- Destructive-sounding operations are guarded: `init` refuses to overwrite an existing
  vault, `member rm` errors on an unknown member, `get`/`read_secret` errors on a missing
  secret. Preserve these guards.
- `rekey` decrypts each secret with the caller's key before re-encrypting; if the caller is
  not a recipient of some secret it fails with a clear, secret-named error rather than
  producing a corrupt blob.
- **Secret writes are atomic.** `Vault::write_secret` writes to a same-directory temp file
  and renames it over the target, so a reader (or an interrupted `add`/`rekey`) never
  observes a half-written `.age` file.

## Known reliability gaps

- **`rekey` is not transactional** across secrets — a failure midway leaves some secrets
  re-encrypted and some not. It is idempotent (safe to re-run), which is the current
  mitigation.

## Performance constraints

Performance is not a primary concern at this scale (a vault holds tens of small secrets),
but keep these properties:

- **Single self-contained binary**, no runtime dependency on an external `age`/`gpg`.
  Release profile uses `strip = true` + `lto = true` (binary ≈ 1.3 MB).
- Startup is dominated by `clap` parsing and one `age` operation per secret — effectively
  instant. Do not add network calls or background work; the CLI is offline by design (the
  network boundary is the user's own `git push`/`pull`).
- `secret_names` walks the `secrets/` tree recursively; fine for realistic vault sizes.
