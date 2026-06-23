//! Thin wrapper around the system `git` — the only module that shells out to it.
//!
//! Powers the optional autocommit-on-change and the `sshare git` passthrough. No git library
//! and no network stack are embedded; the network is touched only when the user explicitly
//! runs `sshare git push` (or `pull`/`fetch`). See `design-docs/git-integration.md`.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Paths (relative to the vault root) that sshare owns and may auto-commit.
const SSHARE_PATHS: [&str; 2] = [".sshare", "secrets"];

fn git(root: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(root);
    cmd
}

/// Returns true if `root` is inside a git work tree (false if git is missing).
pub(crate) fn is_repo(root: &Path) -> bool {
    git(root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Stages sshare's files under `root` and commits them with `message`. A no-op if nothing
/// sshare-owned changed. **Local only** — never touches the network.
///
/// # Errors
///
/// Returns an error if a git invocation fails (e.g. no commit identity configured), with
/// git's stderr included.
pub(crate) fn autocommit(root: &Path, message: &str) -> Result<()> {
    run(root, &["add", "--", SSHARE_PATHS[0], SSHARE_PATHS[1]])?;

    // `git diff --cached --quiet` exits non-zero iff something is staged.
    let nothing_staged = git(root)
        .args([
            "diff",
            "--cached",
            "--quiet",
            "--",
            SSHARE_PATHS[0],
            SSHARE_PATHS[1],
        ])
        .output()
        .context("failed to run git")?
        .status
        .success();
    if nothing_staged {
        return Ok(());
    }

    // Only sshare's paths were staged above, so an unscoped commit records exactly those —
    // and avoids "pathspec did not match" when e.g. `secrets/` is still empty.
    run(root, &["commit", "-m", message])
}

/// Runs `git <args>` inside `root`, inheriting stdio (so pagers and auth prompts work).
/// Returns the child's exit code.
///
/// # Errors
///
/// Returns an error if `git` cannot be launched (e.g. not installed).
pub(crate) fn passthrough(root: &Path, args: &[String]) -> Result<i32> {
    let status = git(root)
        .args(args)
        .status()
        .context("failed to run git — is it installed and on PATH?")?;
    Ok(status.code().unwrap_or(1))
}

/// Runs a git subcommand quietly, surfacing git's stderr on failure.
fn run(root: &Path, args: &[&str]) -> Result<()> {
    let out = git(root)
        .args(args)
        .output()
        .context("failed to run git — is it installed and on PATH?")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{autocommit, is_repo};
    use std::path::Path;
    use std::process::Command;

    fn git_ok(root: &Path, args: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .output()
                .unwrap()
                .status
                .success(),
            "git {args:?} failed"
        );
    }

    fn git_out(root: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn init_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        git_ok(p, &["init", "-q"]);
        git_ok(p, &["config", "user.email", "t@test"]);
        git_ok(p, &["config", "user.name", "test"]);
        std::fs::create_dir_all(p.join(".sshare")).unwrap();
        std::fs::create_dir_all(p.join("secrets")).unwrap();
        dir
    }

    #[test]
    fn is_repo_detects_git() {
        let repo = init_repo();
        assert!(is_repo(repo.path()));
        let plain = tempfile::tempdir().unwrap();
        assert!(!is_repo(plain.path()));
    }

    #[test]
    fn autocommit_commits_only_sshare_files() {
        let repo = init_repo();
        let p = repo.path();
        std::fs::write(p.join(".sshare/config.toml"), "x").unwrap();
        std::fs::write(p.join("unrelated.txt"), "y").unwrap();

        autocommit(p, "sshare: test").unwrap();

        assert!(git_out(p, &["log", "--oneline"]).contains("sshare: test"));
        // The unrelated file must remain uncommitted (untracked).
        assert!(
            git_out(p, &["status", "--porcelain"]).contains("unrelated.txt"),
            "unrelated file should not be committed"
        );
    }

    #[test]
    fn autocommit_is_a_noop_when_nothing_changed() {
        let repo = init_repo();
        let p = repo.path();
        std::fs::write(p.join(".sshare/config.toml"), "x").unwrap();
        autocommit(p, "first").unwrap();
        autocommit(p, "second").unwrap(); // nothing new staged
        assert_eq!(git_out(p, &["rev-list", "--count", "HEAD"]).trim(), "1");
    }
}
