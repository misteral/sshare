# Contributing

## Workflow

1. Read the relevant `docs/` file before starting (this repo is the system of record).
2. Branch off `main` for any non-trivial change.
3. Make the change with a matching test (see [TESTING.md](TESTING.md)).
4. Run the three CI gates locally: `cargo fmt -- --check`, `cargo clippy --all-targets
   --locked -- -D warnings`, `cargo test --locked`.
5. Open a PR; CI must be green before merge.

## Branch strategy

- `main` is the release line and the default branch. Tags `v*` are cut from it (see
  [RELEASING.md](RELEASING.md)).
- Use short-lived feature branches: `feat/...`, `fix/...`, `docs/...`, `chore/...`.
- **Do not commit or push unless asked.** When asked to commit while on `main`, prefer a
  branch + PR unless the change is explicitly main-line (the owner sometimes commits docs
  and chores directly to `main` on this personal repo — follow the instruction given).

## Commit conventions

- Conventional-commit-style prefixes (`feat:`, `fix:`, `docs:`, `chore:`) — already in use
  in history. Subject in the imperative, ≤ ~72 chars; body explains *why* when non-obvious.
- The release bot commits `chore: update Homebrew formula for vX.Y.Z [skip ci]` to `main` —
  `[skip ci]` in a commit message skips CI; use it only for no-op-to-code changes.

## GitHub

- `gh` is authenticated as `misteral`; the remote is
  `git@github.com:misteral/sshare.git`.
- Releases and the in-repo Homebrew tap are automated — never hand-edit a GitHub Release or
  `Formula/sshare.rb` (regenerated on each tag).
- Use `gh run watch <id> --exit-status` to follow a workflow run.

## Git rules

- Never force-push `main`. Never rewrite published tags.
- Keep `Cargo.lock` committed and current (the `--locked` gates depend on it).
- Before deleting or overwriting a file you did not create, inspect it first.

## Plans & tech debt as repo artifacts

Larger efforts get an execution plan in
[exec-plans/active/](exec-plans/active/); finished ones move to
[exec-plans/completed/](exec-plans/completed/). Known debt lives in
[exec-plans/tech-debt-tracker.md](exec-plans/tech-debt-tracker.md). Planning state lives in
the repo, not in external trackers.
