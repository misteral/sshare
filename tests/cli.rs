//! End-to-end tests: drive the built `sshare` binary through the real CLI, including the
//! connected-vault registry and the signed-members (TOFU) flow. Every command runs with an
//! explicit `--identity`/`--key` and `SSHARE_CONFIG_HOME` pointed at a temp dir, so the
//! tests are hermetic — they never touch the developer's real `~/.ssh` or `~/.config`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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

fn run_ok(cwd: &Path, cfg: &Path, args: &[&str]) -> String {
    let out = sshare(cwd, cfg).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "`sshare {args:?}` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Stores a secret by piping the value on stdin; captures stdout/stderr.
fn add_secret(cwd: &Path, cfg: &Path, name: &str, value: &[u8]) -> Output {
    let mut child = sshare(cwd, cfg)
        .args(["add", name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(value).unwrap();
    child.wait_with_output().unwrap()
}

/// A throwaway vault initialized and signed by "alice" (the maintainer).
struct Fixture {
    dir: tempfile::TempDir,
    root: PathBuf,
    cfg: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn setup() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("team");
        let cfg = dir.path().join("cfg");
        std::fs::create_dir(&root).unwrap();
        let pubp = root.join("alice.pub");
        let key = root.join("alice.key");
        std::fs::write(&pubp, ALICE_PUB).unwrap();
        std::fs::write(&key, ALICE_KEY).unwrap();

        run_ok(&root, &cfg, &["init"]);
        run_ok(
            &root,
            &cfg,
            &[
                "member",
                "add",
                "alice",
                "--key",
                pubp.to_str().unwrap(),
                "--identity",
                key.to_str().unwrap(),
            ],
        );
        Self {
            dir,
            root,
            cfg,
            key,
        }
    }
}

#[test]
fn signed_happy_path_store_and_retrieve() {
    let f = Fixture::setup();
    assert!(
        add_secret(&f.root, &f.cfg, "db-prod", b"hunter2")
            .status
            .success()
    );

    let out = sshare(&f.root, &f.cfg)
        .args(["get", "db-prod", "--identity", f.key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "get failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"hunter2");
    assert!(run_ok(&f.root, &f.cfg, &["ls"]).contains("db-prod"));
}

#[test]
fn get_with_pubkey_path_fails_with_actionable_message() {
    let f = Fixture::setup();
    assert!(add_secret(&f.root, &f.cfg, "s1", b"x").status.success());

    // Pointing --identity at the public key is a common mistake; expect a clear hint.
    let out = sshare(&f.root, &f.cfg)
        .args([
            "get",
            "s1",
            "--identity",
            f.root.join("alice.pub").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains(".pub"));
}

#[test]
fn tampering_with_members_is_rejected_on_encrypt() {
    let f = Fixture::setup();
    assert!(add_secret(&f.root, &f.cfg, "s1", b"x").status.success());

    // Attacker injects an extra recipient directly (a git commit), without re-signing.
    std::fs::write(f.root.join(".sshare/members/intruder.pub"), ALICE_PUB).unwrap();

    let out = add_secret(&f.root, &f.cfg, "s2", b"y");
    assert!(
        !out.status.success(),
        "add should refuse a tampered member list"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tamper") || stderr.contains("signature"),
        "stderr was: {stderr}"
    );
}

#[test]
fn second_machine_must_accept_authority_tofu() {
    let f = Fixture::setup();
    // A second machine = a fresh config home with no pins yet.
    let cfg2 = f.dir.path().join("cfg2");

    // Before accepting, encrypting refuses because the authority isn't trusted here.
    let out = add_secret(&f.root, &cfg2, "s1", b"x");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not yet trusted"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Accept (TOFU) — derives the authority from the current signature — then it works.
    run_ok(&f.root, &cfg2, &["trust", "accept"]);
    assert!(add_secret(&f.root, &cfg2, "s1", b"x").status.success());
}

#[test]
fn non_maintainer_cannot_change_membership() {
    let f = Fixture::setup();
    // A second, different key tries to add itself as a member.
    let intruder_pub = f.root.join("intruder.pub");
    let intruder_key = f.root.join("intruder.key");
    // Reuse alice's *public* key under a different name but a DIFFERENT signing key:
    // generate a distinct keypair would be ideal, but a mismatched identity is enough —
    // the maintainer pin is alice, so signing with mallory must be refused.
    std::fs::write(&intruder_pub, MALLORY_PUB).unwrap();
    std::fs::write(&intruder_key, MALLORY_KEY).unwrap();

    let out = sshare(&f.root, &f.cfg)
        .args([
            "member",
            "add",
            "intruder",
            "--key",
            intruder_pub.to_str().unwrap(),
            "--identity",
            intruder_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("maintainer"));
}

#[test]
fn connect_use_by_name_from_outside_then_disconnect() {
    let f = Fixture::setup();
    let outside = f.dir.path(); // not inside the vault
    add_secret(&f.root, &f.cfg, "db-prod", b"hunter2");

    let listed = run_ok(outside, &f.cfg, &["vaults"]);
    assert!(listed.contains("team"), "vaults output: {listed}");

    let out = sshare(outside, &f.cfg)
        .args([
            "get",
            "db-prod",
            "--vault",
            "team",
            "--identity",
            f.key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"hunter2");

    run_ok(outside, &f.cfg, &["disconnect", "team"]);
    assert!(!run_ok(outside, &f.cfg, &["vaults"]).contains("team"));
    assert!(
        f.root.join(".sshare/config.toml").is_file(),
        "files deleted!"
    );
}

// Second throwaway keypair for the non-maintainer test.
const MALLORY_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOzxHqUFE7nQV4hAGBe4RGkxZkdsvpzZhmDViwK/HW+z mallory@sshare-test";
const MALLORY_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDs8R6lBRO50FeIQBgXuERpMWZHbL6c2YZg1YsCvx1vswAAAJg/gTMFP4Ez
BQAAAAtzc2gtZWQyNTUxOQAAACDs8R6lBRO50FeIQBgXuERpMWZHbL6c2YZg1YsCvx1vsw
AAAEBVsdeSzRdkkd8fr14IWBArsCgW7t08rPO18bSF+pzFf+zxHqUFE7nQV4hAGBe4RGkx
ZkdsvpzZhmDViwK/HW+zAAAAE21hbGxvcnlAc3NoYXJlLXRlc3QBAg==
-----END OPENSSH PRIVATE KEY-----
";
