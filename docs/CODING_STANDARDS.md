# Coding Standards

## Language & toolchain

- **Rust edition 2024** (requires Rust ≥ 1.85; developed on 1.96). CI uses
  `dtolnay/rust-toolchain@stable`.
- The dependency set is intentionally small and pure-Rust: `age` (ssh feature), `ssh-key`
  (SSHSIG signing), `getrandom`, `anyhow`, `clap` (derive), `rpassword`, plus `tempfile` for
  tests. **Adding a dependency is a reviewable decision** — especially anything pulling in
  C/`openssl` (breaks the single-static-binary, linker-only cross-compile property).

## Lints are gates, not suggestions

`Cargo.toml` enables `clippy::all` + `clippy::pedantic` (and rust lints
`missing_debug_implementations`, `unsafe_op_in_unsafe_fn`) as warnings. CI runs
`cargo clippy --all-targets --locked -- -D warnings`, so **every pedantic lint fails the
build**. Keep the tree warning-free; do not `#[allow(...)]` to silence a lint without a
one-line justification comment.

## Error handling

- Return `anyhow::Result<T>`; `main` returns `Result<()>`.
- Attach a user-actionable message with `.context(...)` / `.with_context(...)` at every
  fallible boundary (file open, parse, etc.). The error text is shown to the user — make
  it tell them what to do (e.g. "is your SSH key a recipient?").
- Use `bail!` for validation failures. **Never `unwrap`/`expect`/`panic!` on user input or
  I/O.** The one `unreachable!` in `cmd_add` is justified by a clap `conflicts_with`.

## Forbidden / discouraged patterns

- **No secret plaintext in logs or errors** (see [SECURITY.md](SECURITY.md)).
- **No filesystem path built from user input without `validate_name`/`validate_component`.**
- **No `age` types outside `crypto.rs`** (the single allowed exception is the
  `age::ssh::Recipient` return type in `vault.rs`), and **no `ssh-key` types outside
  `sign.rs`**. Each crypto library stays isolated to one module. See
  [ARCHITECTURE.md](ARCHITECTURE.md).
- No `println!`-as-logging for diagnostics; `stdout` is reserved for command output (and
  for `get`, raw secret bytes). Diagnostics go to `stderr`.

## Style & conventions

- Run `cargo fmt --all` before committing; CI enforces `cargo fmt -- --check`.
- Items are `pub(crate)` by default — this is a binary, nothing is a public API.
- Every `pub(crate)` fn that can fail carries a `# Errors` doc section (existing code does
  this consistently — match it).
- Module-level `//!` doc comments explain the *why* of each file; keep them current when
  behavior changes.
- Naming: secret/member identifiers are validated path components; the file stem is the
  member name; the `.age`/`.pub` extensions are constants in `vault.rs` — reuse them, don't
  hardcode the strings.
