//! End-to-end test: drives the built `sshare` binary through the core flow
//! (`init → member add → add → get → ls`) in a throwaway vault, exercising the CLI
//! plumbing in `main.rs` that the in-crate unit tests don't reach.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

// Throwaway ed25519 keypair used only by this test (not a real credential).
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

fn sshare(vault: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sshare"));
    cmd.current_dir(vault);
    cmd
}

#[test]
fn init_add_member_store_and_retrieve() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path();
    let pub_path = vault.join("alice.pub");
    let key_path = vault.join("alice.key");
    std::fs::write(&pub_path, ALICE_PUB).unwrap();
    std::fs::write(&key_path, ALICE_KEY).unwrap();

    assert!(sshare(vault).arg("init").status().unwrap().success());

    assert!(
        sshare(vault)
            .args(["member", "add", "alice", "--key"])
            .arg(&pub_path)
            .status()
            .unwrap()
            .success()
    );

    // Store a secret via stdin (the documented, history-safe path).
    let mut child = sshare(vault)
        .args(["add", "db-prod"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hunter2").unwrap();
    assert!(child.wait().unwrap().success());

    // Retrieve it back with the matching private key.
    let out = sshare(vault)
        .args(["get", "db-prod", "--identity"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "get failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"hunter2");

    // It shows up in `ls`.
    let out = sshare(vault).arg("ls").output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("db-prod"));
}

#[test]
fn get_with_wrong_path_fails_with_actionable_message() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path();
    let pub_path = vault.join("alice.pub");
    std::fs::write(&pub_path, ALICE_PUB).unwrap();

    assert!(sshare(vault).arg("init").status().unwrap().success());
    assert!(
        sshare(vault)
            .args(["member", "add", "alice", "--key"])
            .arg(&pub_path)
            .status()
            .unwrap()
            .success()
    );
    let mut child = sshare(vault)
        .args(["add", "s1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    assert!(child.wait().unwrap().success());

    // Pointing --identity at the public key is a common mistake; expect a clear hint.
    let out = sshare(vault)
        .args(["get", "s1", "--identity"])
        .arg(&pub_path)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(".pub"), "stderr was: {stderr}");
}
