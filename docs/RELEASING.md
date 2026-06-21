# Releasing

Releases are fully automated from a git tag. The pipeline lives in
`.github/workflows/release.yml`.

## Versioning

Semantic versioning (`MAJOR.MINOR.PATCH`). The crate is pre-1.0, so breaking changes bump
MINOR. The version of record is `version` in `Cargo.toml`; the git tag is `v<version>`
(e.g. `v0.1.0`).

## Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/):

- Keep an `## [Unreleased]` section at the top; add entries there as you work.
- On release, rename `[Unreleased]` to `## [x.y.z] - YYYY-MM-DD` and start a fresh empty
  `[Unreleased]`. **Released sections are immutable** — never edit a shipped version's
  entries.
- Update the link references at the bottom (`[Unreleased]` compare link + the new tag link).
- The release workflow extracts the section whose heading is `## [x.y.z]` verbatim and uses
  it as the GitHub Release notes, so write entries for humans.

## Cutting a release

1. Move `[Unreleased]` entries into a new `## [x.y.z] - <date>` section in `CHANGELOG.md`.
2. Bump `version` in `Cargo.toml` (and run `cargo build` so `Cargo.lock` updates; commit it).
3. Run the CI gates locally (see [TESTING.md](TESTING.md)).
4. Commit, then tag and push:
   ```sh
   git tag -a vX.Y.Z -m "sshare vX.Y.Z"
   git push origin main
   git push origin vX.Y.Z
   ```

## What the pipeline does (on a `v*` tag)

1. **build** (matrix): cross-compiles four targets — `x86_64`/`aarch64` × macOS/Linux.
   `aarch64-unknown-linux-gnu` uses the `gcc-aarch64-linux-gnu` cross linker; the pure-Rust
   dependency set makes this work without C toolchains. Each build is packaged as
   `sshare-<version>-<target>.tar.gz` with a sibling `.sha256`.
2. **publish**: downloads all artifacts, creates the GitHub Release with the changelog
   section as notes and all tarballs + checksums attached, then **regenerates
   `Formula/sshare.rb`** with the real per-platform sha256 values and commits it back to
   `main` (`[skip ci]`).

`Formula/sshare.rb` is a **generated artifact** — to change its shape, edit the heredoc in
`release.yml`, not the formula file. Its committed checksums are placeholders until a tag
fills them in.

## Homebrew install (this repo is its own tap)

```sh
brew tap misteral/sshare https://github.com/misteral/sshare
brew trust misteral/sshare    # Homebrew 6+ requires trusting third-party taps
brew install sshare
```

`brew trust` is a *local* trust the end user grants to a third-party tap; it is not a
Homebrew-org verification. Becoming an unprefixed `brew install sshare` (no tap) requires
acceptance into `homebrew-core`, which needs project notability and a from-source formula —
tracked as a future item in
[exec-plans/tech-debt-tracker.md](exec-plans/tech-debt-tracker.md).

## Caveat: release bot pushes to `main`

The publish job commits the formula bump directly to `main`. Once `main` gains branch
protection, allow the `github-actions` bot to push (or switch the step to open a PR) or the
release will fail at that step.
