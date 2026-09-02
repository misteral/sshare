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

/// Encrypts `plaintext` to `pubkey` as a bare age blob with **no** sshare vault header — what
/// every secret written before 0.7 looks like, and what a blob from any other age tool looks
/// like. Test-only: outside this fixture, `age` is confined to `src/crypto.rs`.
fn legacy_blob(plaintext: &[u8], pubkey: &str) -> Vec<u8> {
    let recipient: age::ssh::Recipient = pubkey.parse().unwrap();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .unwrap();
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    out
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

#[test]
fn maintainer_membership_change_does_not_launder_an_injected_key() {
    let f = Fixture::setup();
    let alice = f.key.to_str().unwrap();
    let alice_pub = f.root.join("alice.pub");
    assert!(add_secret(&f.root, &f.cfg, "s1", b"x").status.success());

    // A committer drops an unsigned key into the member directory (a plain git commit).
    std::fs::write(f.root.join(".sshare/members/intruder.pub"), MALLORY_PUB).unwrap();

    // The maintainer's next routine membership change must refuse — not re-sign whatever
    // is on disk — and must leave nothing behind.
    let out = sshare(&f.root, &f.cfg)
        .args([
            "member",
            "add",
            "alice2",
            "--key",
            alice_pub.to_str().unwrap(),
            "--identity",
            alice,
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "member add re-signed a tampered member list"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tamper") || stderr.contains("signature"),
        "stderr: {stderr}"
    );
    assert!(
        !f.root.join(".sshare/members/alice2.pub").exists(),
        "a stray .pub was written before the check"
    );

    let out = sshare(&f.root, &f.cfg)
        .args(["member", "rm", "alice", "--identity", alice])
        .output()
        .unwrap();
    assert!(!out.status.success(), "member rm re-signed a tampered list");
    assert!(
        f.root.join(".sshare/members/alice.pub").exists(),
        "a member was removed before the check"
    );

    // And encrypt paths still refuse, so the intruder never becomes a recipient.
    let out = sshare(&f.root, &f.cfg)
        .args(["rekey", "--identity", alice])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!add_secret(&f.root, &f.cfg, "s2", b"y").status.success());
}

#[test]
fn member_sign_is_explicit_and_shows_the_set() {
    let f = Fixture::setup();
    let alice = f.key.to_str().unwrap();
    let alice_pub = f.root.join("alice.pub");
    // A vault from before signing — or one whose signature a committer deleted.
    std::fs::remove_file(f.root.join(".sshare/members.sig")).unwrap();

    // Membership changes refuse and point at the explicit command.
    let out = sshare(&f.root, &f.cfg)
        .args([
            "member",
            "add",
            "bob",
            "--key",
            alice_pub.to_str().unwrap(),
            "--identity",
            alice,
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "member add bootstrapped a non-empty unsigned list"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("member sign"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!f.root.join(".sshare/members/bob.pub").exists());

    // Without a terminal, `member sign` needs --yes and signs nothing otherwise.
    let out = sshare(&f.root, &f.cfg)
        .args(["member", "sign", "--identity", alice])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--yes"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!f.root.join(".sshare/members.sig").exists());

    // With --yes it lists every member with a key fingerprint, then signs.
    let shown = run_ok(
        &f.root,
        &f.cfg,
        &["member", "sign", "--yes", "--identity", alice],
    );
    assert!(
        shown.contains("alice") && shown.contains("SHA256:"),
        "sign output: {shown}"
    );
    assert!(f.root.join(".sshare/members.sig").exists());
    assert!(add_secret(&f.root, &f.cfg, "s1", b"x").status.success());
}

#[test]
fn rekey_refuses_ciphertext_planted_from_another_vault() {
    // Alice is a recipient in two vaults; a committer in B copies A's ciphertext into B,
    // hoping Alice's next `rekey` in B re-encrypts it to B's members.
    let a = Fixture::setup();
    let b = Fixture::setup();
    let alice_b = b.key.to_str().unwrap();
    assert!(
        add_secret(&a.root, &a.cfg, "db-prod", b"prod-password")
            .status
            .success()
    );
    assert!(
        add_secret(&b.root, &b.cfg, "own", b"own-value")
            .status
            .success()
    );
    std::fs::copy(
        a.root.join("secrets/db-prod.age"),
        b.root.join("secrets/planted.age"),
    )
    .unwrap();

    let out = sshare(&b.root, &b.cfg)
        .args(["rekey", "--identity", alice_b])
        .output()
        .unwrap();
    assert!(!out.status.success(), "rekey re-encrypted a foreign blob");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("different vault"), "stderr: {stderr}");
    assert!(
        !stderr.contains("prod-password"),
        "leaked plaintext: {stderr}"
    );

    let out = sshare(&b.root, &b.cfg)
        .args(["get", "planted", "--identity", alice_b])
        .output()
        .unwrap();
    assert!(!out.status.success(), "get printed a foreign blob");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("prod-password"));

    // Removing the planted blob is the way out; everything else still works.
    run_ok(&b.root, &b.cfg, &["rm", "planted"]);
    run_ok(&b.root, &b.cfg, &["rekey", "--identity", alice_b]);
    let out = sshare(&b.root, &b.cfg)
        .args(["get", "own", "--identity", alice_b])
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"own-value");
}

#[test]
fn rekey_migrates_legacy_blobs_only_when_asked() {
    let f = Fixture::setup();
    let alice = f.key.to_str().unwrap();
    assert!(
        add_secret(&f.root, &f.cfg, "new", b"bound")
            .status
            .success()
    );
    // A pre-0.7 secret: bare age output with no vault header.
    std::fs::write(
        f.root.join("secrets/old.age"),
        legacy_blob(b"legacy-value", ALICE_PUB),
    )
    .unwrap();

    // Reading it still works — legacy blobs are not locked out.
    let out = sshare(&f.root, &f.cfg)
        .args(["get", "old", "--identity", alice])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "get failed on a legacy blob: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"legacy-value");

    // A plain rekey stops and names the unbound blobs instead of re-encrypting them.
    let out = sshare(&f.root, &f.cfg)
        .args(["rekey", "--identity", alice])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "rekey silently re-encrypted an unbound blob"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--migrate-legacy") && stderr.contains("old"),
        "stderr: {stderr}"
    );

    // With the flag it migrates; afterwards a plain rekey is clean and the value is intact.
    let migrated = run_ok(
        &f.root,
        &f.cfg,
        &["rekey", "--migrate-legacy", "--identity", alice],
    );
    assert!(migrated.contains("Migrated 1"), "rekey output: {migrated}");
    run_ok(&f.root, &f.cfg, &["rekey", "--identity", alice]);
    let out = sshare(&f.root, &f.cfg)
        .args(["get", "old", "--identity", alice])
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"legacy-value");
}

#[cfg(unix)]
#[test]
fn add_refuses_to_write_through_a_committed_symlink() {
    let f = Fixture::setup();
    let outside = f.dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    // What a committer could plant: secrets/prod -> somewhere outside the vault.
    std::os::unix::fs::symlink(&outside, f.root.join("secrets/prod")).unwrap();

    let out = add_secret(&f.root, &f.cfg, "prod/token", b"x");
    assert!(!out.status.success(), "add wrote through a symlink");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("symlink"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        std::fs::read_dir(&outside).unwrap().next().is_none(),
        "the secret escaped the vault"
    );
}

#[test]
fn member_sign_wont_hijack_an_already_signed_vault_on_a_fresh_machine() {
    let f = Fixture::setup(); // validly signed by alice
    let alice = f.key.to_str().unwrap();
    // A fresh machine = a config home with no pins yet.
    let cfg2 = f.dir.path().join("cfg2");
    let mkey = f.root.join("mallory.key");
    std::fs::write(&mkey, MALLORY_KEY).unwrap();

    // A non-authority who freshly cloned must NOT be able to re-sign the good list and pin
    // themselves as authority.
    let out = sshare(&f.root, &cfg2)
        .args([
            "member",
            "sign",
            "--yes",
            "--identity",
            mkey.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "member sign hijacked a signed vault");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("already validly signed"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The real authority (alice) adopting the vault on the new machine is fine.
    let out = sshare(&f.root, &cfg2)
        .args(["member", "sign", "--yes", "--identity", alice])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the real maintainer could not sign: {}",
        String::from_utf8_lossy(&out.stderr)
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
