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
    add_secret_with(cwd, cfg, name, value, &[])
}

/// Like [`add_secret`], but appends `extra` flags (e.g. `--description`) to the `add` call.
fn add_secret_with(cwd: &Path, cfg: &Path, name: &str, value: &[u8], extra: &[&str]) -> Output {
    let mut args = vec!["add", name];
    args.extend_from_slice(extra);
    let mut child = sshare(cwd, cfg)
        .args(&args)
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
fn remove_secret() {
    let f = Fixture::setup();
    assert!(add_secret(&f.root, &f.cfg, "tmp", b"x").status.success());
    assert!(run_ok(&f.root, &f.cfg, &["ls"]).contains("tmp"));

    run_ok(&f.root, &f.cfg, &["rm", "tmp"]);
    assert!(!run_ok(&f.root, &f.cfg, &["ls"]).contains("tmp"));

    // Removing a missing secret errors clearly.
    let out = sshare(&f.root, &f.cfg)
        .args(["rm", "nope"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no such secret"));
}

#[test]
fn description_is_encrypted_listed_and_survives_rekey() {
    let f = Fixture::setup();
    let alice = f.key.to_str().unwrap();

    assert!(
        add_secret_with(
            &f.root,
            &f.cfg,
            "db-prod",
            b"hunter2",
            &["--description", "prod read replica"],
        )
        .status
        .success()
    );

    // Plain `ls` shows only the name — the description must not leak into the listing.
    let plain = run_ok(&f.root, &f.cfg, &["ls"]);
    assert!(plain.contains("db-prod"));
    assert!(
        !plain.contains("prod read replica"),
        "plain `ls` leaked the description: {plain}"
    );

    // `ls --descriptions` decrypts and shows it.
    let listed = run_ok(
        &f.root,
        &f.cfg,
        &["ls", "--descriptions", "--identity", alice],
    );
    assert!(
        listed.contains("db-prod") && listed.contains("prod read replica"),
        "ls --descriptions: {listed}"
    );

    // The value rode in a separate blob, so `get` is byte-for-byte unchanged.
    let val = sshare(&f.root, &f.cfg)
        .args(["get", "db-prod", "--identity", alice])
        .output()
        .unwrap();
    assert_eq!(val.stdout, b"hunter2");

    // Add a second member and rekey; the description is re-encrypted for them too.
    let mpub = f.root.join("mallory.pub");
    let mkey = f.root.join("mallory.key");
    std::fs::write(&mpub, MALLORY_PUB).unwrap();
    std::fs::write(&mkey, MALLORY_KEY).unwrap();
    run_ok(
        &f.root,
        &f.cfg,
        &[
            "member",
            "add",
            "mallory",
            "--key",
            mpub.to_str().unwrap(),
            "--identity",
            alice,
        ],
    );
    run_ok(&f.root, &f.cfg, &["rekey", "--identity", alice]);

    // Mallory — who wasn't a recipient when the description was written — can now read it.
    let listed_m = run_ok(
        &f.root,
        &f.cfg,
        &["ls", "--descriptions", "--identity", mkey.to_str().unwrap()],
    );
    assert!(
        listed_m.contains("prod read replica"),
        "mallory could not read the description after rekey: {listed_m}"
    );

    // Removing the secret drops its description blob too (no orphan left behind).
    run_ok(&f.root, &f.cfg, &["rm", "db-prod"]);
    assert!(
        !f.root.join(".sshare/descriptions/db-prod.age").exists(),
        "description blob orphaned after rm"
    );
}

#[test]
fn description_set_keep_and_clear_semantics() {
    let f = Fixture::setup();
    let alice = f.key.to_str().unwrap();
    let list = |f: &Fixture| {
        run_ok(
            &f.root,
            &f.cfg,
            &["ls", "--descriptions", "--identity", alice],
        )
    };

    // Set a description.
    assert!(
        add_secret_with(
            &f.root,
            &f.cfg,
            "svc",
            b"v1",
            &["--description", "first note"]
        )
        .status
        .success()
    );
    assert!(list(&f).contains("first note"));

    // Re-storing the value WITHOUT --description keeps the existing note.
    assert!(
        add_secret_with(&f.root, &f.cfg, "svc", b"v2", &[])
            .status
            .success()
    );
    assert!(
        list(&f).contains("first note"),
        "description should persist across a plain update"
    );

    // An empty --description clears it, leaving the secret itself in place.
    assert!(
        add_secret_with(&f.root, &f.cfg, "svc", b"v3", &["--description", ""])
            .status
            .success()
    );
    let cleared = list(&f);
    assert!(
        !cleared.contains("first note"),
        "description not cleared: {cleared}"
    );
    assert!(cleared.contains("svc"), "secret vanished: {cleared}");
}

#[test]
fn ls_descriptions_degrades_when_one_cannot_be_decrypted() {
    let f = Fixture::setup();
    let alice = f.key.to_str().unwrap();

    // A described secret, encrypted to alice only, plus a plain one.
    assert!(
        add_secret_with(
            &f.root,
            &f.cfg,
            "noted",
            b"v",
            &["--description", "alice-only note"]
        )
        .status
        .success()
    );
    assert!(add_secret(&f.root, &f.cfg, "plain", b"v").status.success());
    // Alice (a recipient) still reads everything fine.
    assert!(
        run_ok(
            &f.root,
            &f.cfg,
            &["ls", "--descriptions", "--identity", alice]
        )
        .contains("alice-only note")
    );

    // Mallory holds a valid key but was never a recipient, so "noted" won't decrypt.
    let mkey = f.root.join("mallory.key");
    std::fs::write(&mkey, MALLORY_KEY).unwrap();
    let out = sshare(&f.root, &f.cfg)
        .args(["ls", "--descriptions", "--identity", mkey.to_str().unwrap()])
        .output()
        .unwrap();

    // One undecryptable note must not abort the listing: it still succeeds and names every
    // secret, reporting the failure on stderr rather than swallowing the rest of the list.
    assert!(
        out.status.success(),
        "ls --descriptions aborted on one bad note: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("noted"), "missing 'noted': {stdout}");
    assert!(
        stdout.contains("plain"),
        "missing 'plain' after the bad note: {stdout}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("cannot decrypt the description for 'noted'"),
        "no warning for the undecryptable description: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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

#[test]
fn autocommit_and_git_passthrough() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("team");
    let cfg = dir.path().join("cfg");
    std::fs::create_dir(&root).unwrap();
    // Keys live OUTSIDE the vault so the repo holds only sshare's own files.
    let pubp = dir.path().join("alice.pub");
    let key = dir.path().join("alice.key");
    std::fs::write(&pubp, ALICE_PUB).unwrap();
    std::fs::write(&key, ALICE_KEY).unwrap();

    let run_git = |args: &[&str]| {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .output()
                .unwrap()
                .status
                .success(),
            "git {args:?} failed"
        );
    };
    run_git(&["init", "-q"]);
    run_git(&["config", "user.email", "t@test"]);
    run_git(&["config", "user.name", "test"]);

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
    assert!(
        add_secret(&root, &cfg, "db-prod", b"hunter2")
            .status
            .success()
    );

    // Mutations auto-committed; visible through the `git` passthrough.
    let log = run_ok(&root, &cfg, &["git", "log", "--oneline"]);
    assert!(log.contains("add member alice"), "log: {log}");
    assert!(log.contains("add secret db-prod"), "log: {log}");
    // Everything sshare owns is committed → clean tree.
    let status = run_ok(&root, &cfg, &["git", "status", "--porcelain"]);
    assert!(
        status.trim().is_empty(),
        "expected clean tree, got: {status}"
    );

    // SSHARE_NO_AUTOCOMMIT=1 leaves the change uncommitted.
    let mut child = sshare(&root, &cfg)
        .env("SSHARE_NO_AUTOCOMMIT", "1")
        .args(["add", "db2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"z").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    let status2 = run_ok(&root, &cfg, &["git", "status", "--porcelain"]);
    assert!(
        status2.contains("secrets/"),
        "expected uncommitted secret: {status2}"
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
