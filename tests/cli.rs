//! End-to-end tests: drive the built `sshare` binary through the real CLI, including the
//! connected-vault registry. Every command runs with `SSHARE_CONFIG_HOME` pointed at a
//! temp dir, so the tests never touch the developer's real `~/.config`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

// Throwaway ed25519 keypair used only by these tests (not a real credential).
const ALICE_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB/gfpInCKMN/BmzA072GUXsrebu/hcAWYakfr6QKlqu alice@sshare-test";
const ALICE_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAf4H6SJwijDfwZswNO9hlF7K3m7v4XAFmGpH6+kCpargAAAJjjtb/F47W/
xQAAAAtzc2gtZWQyNTUxOQAAACAf4H6SJwijDfwZswNO9hlF7K3m7v4XAFmGpH6+kCparg
AAAED+3UMPiQr96qPd+I8NwZbIq+LILeFzVGhafO649Y9GqB/gfpInCKMN/BmzA072GUXs
rebu/hcAWYakfr6QKlquAAAAEWFsaWNlQHNzaGFyZS10ZXN0AQIDBA==
-----END OPENSSH PRIVATE KEY-----
";

fn sshare(cwd: &Path, cfg: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sshare"));
    cmd.current_dir(cwd).env("SSHARE_CONFIG_HOME", cfg);
    cmd
}

/// Runs a command, asserts success, and returns stdout.
fn run_ok(cwd: &Path, cfg: &Path, args: &[&str]) -> String {
    let out = sshare(cwd, cfg).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "`sshare {args:?}` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Stores a secret by piping the value on stdin.
fn add_secret(cwd: &Path, cfg: &Path, name: &str, value: &[u8]) {
    let mut child = sshare(cwd, cfg)
        .args(["add", name])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(value).unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn init_add_member_store_and_retrieve() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let cfg = dir.path().join("cfg");
    std::fs::create_dir(&vault).unwrap();
    let pub_path = vault.join("alice.pub");
    let key_path = vault.join("alice.key");
    std::fs::write(&pub_path, ALICE_PUB).unwrap();
    std::fs::write(&key_path, ALICE_KEY).unwrap();

    run_ok(&vault, &cfg, &["init"]);
    run_ok(
        &vault,
        &cfg,
        &[
            "member",
            "add",
            "alice",
            "--key",
            pub_path.to_str().unwrap(),
        ],
    );
    add_secret(&vault, &cfg, "db-prod", b"hunter2");

    let out = sshare(&vault, &cfg)
        .args(["get", "db-prod", "--identity", key_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "get failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"hunter2");

    assert!(run_ok(&vault, &cfg, &["ls"]).contains("db-prod"));
}

#[test]
fn get_with_wrong_path_fails_with_actionable_message() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let cfg = dir.path().join("cfg");
    std::fs::create_dir(&vault).unwrap();
    let pub_path = vault.join("alice.pub");
    std::fs::write(&pub_path, ALICE_PUB).unwrap();

    run_ok(&vault, &cfg, &["init"]);
    run_ok(
        &vault,
        &cfg,
        &[
            "member",
            "add",
            "alice",
            "--key",
            pub_path.to_str().unwrap(),
        ],
    );
    add_secret(&vault, &cfg, "s1", b"x");

    // Pointing --identity at the public key is a common mistake; expect a clear hint.
    let out = sshare(&vault, &cfg)
        .args(["get", "s1", "--identity", pub_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(".pub"), "stderr was: {stderr}");
}

#[test]
fn connect_use_by_name_from_outside_then_disconnect() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path(); // a directory that is NOT inside the vault
    let vault = dir.path().join("team");
    let cfg = dir.path().join("cfg");
    std::fs::create_dir(&vault).unwrap();
    let pub_path = vault.join("alice.pub");
    let key_path = vault.join("alice.key");
    std::fs::write(&pub_path, ALICE_PUB).unwrap();
    std::fs::write(&key_path, ALICE_KEY).unwrap();

    // `init` auto-connects the vault under its directory name ("team").
    run_ok(&vault, &cfg, &["init"]);
    run_ok(
        &vault,
        &cfg,
        &[
            "member",
            "add",
            "alice",
            "--key",
            pub_path.to_str().unwrap(),
        ],
    );
    add_secret(&vault, &cfg, "db-prod", b"hunter2");

    // From outside the vault, it shows up in `vaults` ...
    let listed = run_ok(outside, &cfg, &["vaults"]);
    assert!(listed.contains("team"), "vaults output: {listed}");

    // ... and can be read by name without being inside it.
    let out = sshare(outside, &cfg)
        .args([
            "get",
            "db-prod",
            "--vault",
            "team",
            "--identity",
            key_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "get --vault failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"hunter2");

    // Disconnect removes it from the registry (the vault files remain).
    run_ok(outside, &cfg, &["disconnect", "team"]);
    let after = run_ok(outside, &cfg, &["vaults"]);
    assert!(!after.contains("team"), "still listed: {after}");
    assert!(
        vault.join(".sshare/config.toml").is_file(),
        "files deleted!"
    );

    // A name that isn't connected gives a clear error.
    let out = sshare(outside, &cfg)
        .args(["get", "db-prod", "--vault", "team"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no connected vault"));
}
