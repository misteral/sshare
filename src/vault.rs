//! On-disk layout of an `sshare` vault: members and encrypted secrets.
//!
//! A vault is any directory containing a `.sshare/` metadata folder:
//!
//! ```text
//! <root>/
//!   .sshare/
//!     config.toml             # marks the vault root
//!     members/<name>.pub      # one SSH public key per member
//!     descriptions/<name>.age # optional, encrypted secret descriptions
//!   secrets/<name>.age        # age-encrypted secret blobs
//! ```
//!
//! A secret's optional human-readable description is stored as its own age blob, encrypted
//! to the same members as the secret. It lives in a separate `descriptions/` tree (rather
//! than beside the secret) so a description can never collide with a secret name, and so
//! `secret_names` stays a plain walk of `secrets/`.
//!
//! Everything under the vault arrives via git, i.e. from other committers, so file contents
//! are treated as hostile. Names are validated lexically (`validate_name`); on top of that
//! neither reads nor writes follow a symlink inside the vault, symlinked or oddly-named
//! entries are never listed or counted (as secrets or as members), and the signed member
//! set only ever contains well-formed `name\0pubkey` pairs — a committed
//! `secrets/prod -> /elsewhere`, a symlinked `members/x.pub`, or a key with an embedded
//! newline must not redirect a write, be read through, diverge the canonical bytes, or
//! reach the terminal unescaped.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::crypto;

const VAULT_DIR: &str = ".sshare";
const MEMBERS_DIR: &str = "members";
const DESCRIPTIONS_DIR: &str = "descriptions";
const SECRETS_DIR: &str = "secrets";
const CONFIG_FILE: &str = "config.toml";
const VAULT_ID_FILE: &str = "id";
const MEMBERS_SIG_FILE: &str = "members.sig";
const SECRET_EXT: &str = "age";
const PUBKEY_EXT: &str = "pub";

/// A team member identified by an SSH public key.
#[derive(Debug, Clone)]
pub(crate) struct Member {
    /// Member name (the public key file stem).
    pub(crate) name: String,
    /// The member's SSH public key line.
    pub(crate) pubkey: String,
}

/// A secret vault rooted at a directory that contains a `.sshare/` folder.
#[derive(Debug, Clone)]
pub(crate) struct Vault {
    root: PathBuf,
}

impl Vault {
    /// Creates a new, empty vault rooted at `dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if a vault already exists at `dir`, or directories cannot
    /// be created.
    pub(crate) fn init(dir: &Path) -> Result<Self> {
        let vault_dir = dir.join(VAULT_DIR);
        if vault_dir.exists() {
            bail!("a vault already exists at {}", vault_dir.display());
        }
        fs::create_dir_all(vault_dir.join(MEMBERS_DIR))
            .with_context(|| format!("cannot create {}", vault_dir.display()))?;
        fs::create_dir_all(dir.join(SECRETS_DIR))?;
        fs::write(vault_dir.join(CONFIG_FILE), "# sshare vault\nversion = 1\n")?;
        fs::write(vault_dir.join(VAULT_ID_FILE), format!("{}\n", random_id()?))?;
        Ok(Self {
            root: dir.to_path_buf(),
        })
    }

    /// Finds the vault containing the current directory by walking up parents.
    ///
    /// # Errors
    ///
    /// Returns an error if no `.sshare/` folder is found in any ancestor directory.
    pub(crate) fn discover() -> Result<Self> {
        let start = std::env::current_dir().context("cannot determine current directory")?;
        Self::find_from(&start)
    }

    /// Finds the vault containing `start` by walking up parent directories.
    ///
    /// # Errors
    ///
    /// Returns an error if no `.sshare/` folder is found in any ancestor of `start`.
    pub(crate) fn find_from(start: &Path) -> Result<Self> {
        let mut dir = start;
        loop {
            if dir.join(VAULT_DIR).join(CONFIG_FILE).is_file() {
                return Ok(Self {
                    root: dir.to_path_buf(),
                });
            }
            match dir.parent() {
                Some(parent) => dir = parent,
                None => bail!("not inside an sshare vault; run 'sshare init' first"),
            }
        }
    }

    /// Opens the vault rooted exactly at `dir` (no walking up).
    ///
    /// # Errors
    ///
    /// Returns an error if `dir` is not an sshare vault.
    pub(crate) fn open(dir: &Path) -> Result<Self> {
        if !dir.join(VAULT_DIR).join(CONFIG_FILE).is_file() {
            bail!(
                "{} is not an sshare vault (no {VAULT_DIR}/{CONFIG_FILE})",
                dir.display()
            );
        }
        Ok(Self {
            root: dir.to_path_buf(),
        })
    }

    /// Returns the vault root directory.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    fn members_dir(&self) -> PathBuf {
        self.sshare_dir().join(MEMBERS_DIR)
    }

    fn secrets_dir(&self) -> PathBuf {
        self.root.join(SECRETS_DIR)
    }

    /// Lists all members, sorted by name.
    ///
    /// # Errors
    ///
    /// Returns an error if the members directory cannot be read.
    pub(crate) fn members(&self) -> Result<Vec<Member>> {
        let dir = self.members_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
        };

        let mut members = Vec::new();
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some(PUBKEY_EXT) {
                continue;
            }
            // The member set is signed and printed for review, and every committer can drop
            // files here, so only well-formed plain files count. `file_type()` does not
            // follow symlinks: a symlinked `*.pub` could resolve differently per machine
            // (diverging the canonical bytes), and a directory named `*.pub` would raise a
            // read error that bricks every membership command — skip both.
            let file_type = entry
                .file_type()
                .with_context(|| format!("cannot inspect {}", path.display()))?;
            if !file_type.is_file() {
                continue;
            }
            // The name is the signed identifier and is printed for review; hold it to the
            // same charset `add_member` enforces, so a committed odd filename can neither
            // diverge the canonical encoding nor inject terminal escapes into the listing.
            let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if validate_component(name).is_err() {
                continue;
            }
            let pubkey = fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?
                .trim()
                .to_owned();
            // canonical_members joins entries as `name\0pubkey\n`; a NUL or newline inside
            // the pubkey would make that ambiguous — one signature covering two different
            // parsed member sets — so a key carrying either byte is not a member.
            if pubkey.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
                continue;
            }
            members.push(Member {
                name: name.to_owned(),
                pubkey,
            });
        }
        members.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(members)
    }

    /// Parses every member's public key into an age recipient.
    ///
    /// # Errors
    ///
    /// Returns an error if any stored public key cannot be parsed.
    pub(crate) fn recipients(&self) -> Result<Vec<age::ssh::Recipient>> {
        self.members()?
            .iter()
            .map(|m| {
                crypto::parse_recipient(&m.pubkey)
                    .with_context(|| format!("member '{}' has an invalid public key", m.name))
            })
            .collect()
    }

    /// Registers a member from an SSH public key line.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is invalid, `pubkey` is unusable, or the file
    /// cannot be written.
    pub(crate) fn add_member(&self, name: &str, pubkey: &str) -> Result<()> {
        validate_component(name).context("invalid member name")?;
        // Reject keys age cannot use, so the failure surfaces now rather than at encrypt time.
        crypto::parse_recipient(pubkey).context("not a usable SSH public key")?;

        let dir = self.members_dir();
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{name}.{PUBKEY_EXT}"));
        // Route through the atomic writer so this write, like secret writes, refuses to
        // follow a committed symlink out of the vault.
        write_atomic(&self.root, &path, format!("{}\n", pubkey.trim()).as_bytes())
    }

    /// Removes a member by name.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is invalid, the member does not exist, or the file
    /// cannot be removed.
    pub(crate) fn remove_member(&self, name: &str) -> Result<()> {
        validate_component(name).context("invalid member name")?;
        let path = self.members_dir().join(format!("{name}.{PUBKEY_EXT}"));
        if !path.exists() {
            bail!("no such member '{name}'");
        }
        fs::remove_file(&path).with_context(|| format!("cannot remove {}", path.display()))?;
        Ok(())
    }

    /// Lists secret names (without the `.age` extension), sorted.
    ///
    /// # Errors
    ///
    /// Returns an error if the secrets directory cannot be traversed.
    pub(crate) fn secret_names(&self) -> Result<Vec<String>> {
        let base = self.secrets_dir();
        let mut names = Vec::new();
        collect_secrets(&base, &base, &mut names)?;
        names.sort();
        Ok(names)
    }

    fn secret_path(&self, name: &str) -> PathBuf {
        self.secrets_dir().join(format!("{name}.{SECRET_EXT}"))
    }

    fn descriptions_dir(&self) -> PathBuf {
        self.sshare_dir().join(DESCRIPTIONS_DIR)
    }

    fn desc_path(&self, name: &str) -> PathBuf {
        self.descriptions_dir().join(format!("{name}.{SECRET_EXT}"))
    }

    /// Writes an encrypted blob for `name`, creating parent directories as needed.
    ///
    /// The write is atomic (see [`write_atomic`]), so a reader (or an interrupted run) never
    /// observes a half-written secret.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is invalid or the file cannot be written.
    pub(crate) fn write_secret(&self, name: &str, blob: &[u8]) -> Result<()> {
        validate_name(name)?;
        write_atomic(&self.root, &self.secret_path(name), blob)
    }

    /// Writes the encrypted description blob for `name` (atomic, like [`Self::write_secret`]).
    ///
    /// The blob is the description ciphertext, encrypted to the same members as the secret.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is invalid or the file cannot be written.
    pub(crate) fn write_description(&self, name: &str, blob: &[u8]) -> Result<()> {
        validate_name(name)?;
        write_atomic(&self.root, &self.desc_path(name), blob)
    }

    /// Reads the encrypted description blob for `name`, or `None` if the secret has no
    /// description (the common case, and every pre-0.6 secret).
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is invalid or the file exists but cannot be read.
    pub(crate) fn read_description(&self, name: &str) -> Result<Option<Vec<u8>>> {
        validate_name(name)?;
        let path = self.desc_path(name);
        // Symmetric with writes: never read a description *through* a committed symlink, so
        // rekey's phase 1 aborts on one before phase 2 has re-encrypted any earlier item.
        reject_symlinks_under(&self.root, &path)?;
        match fs::read(&path) {
            Ok(blob) => Ok(Some(blob)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    /// Removes the description for `name` if present; succeeds if there was none.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is invalid or an existing file cannot be removed.
    pub(crate) fn remove_description(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let path = self.desc_path(name);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("cannot remove {}", path.display())),
        }
    }

    /// Reads the encrypted blob for `name`.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is invalid or the secret does not exist.
    pub(crate) fn read_secret(&self, name: &str) -> Result<Vec<u8>> {
        validate_name(name)?;
        let path = self.secret_path(name);
        // Symmetric with writes: refuse a secret reached through a committed symlink.
        reject_symlinks_under(&self.root, &path)?;
        if !path.exists() {
            bail!("no such secret '{name}'");
        }
        fs::read(&path).with_context(|| format!("cannot read {}", path.display()))
    }

    /// Removes the secret named `name`.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is invalid or the secret does not exist.
    pub(crate) fn remove_secret(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let path = self.secret_path(name);
        if !path.exists() {
            bail!("no such secret '{name}'");
        }
        fs::remove_file(&path).with_context(|| format!("cannot remove {}", path.display()))?;
        // Drop the description sidecar too, so removing a secret leaves nothing orphaned.
        self.remove_description(name)?;
        Ok(())
    }

    /// Returns true if a secret named `name` already exists.
    pub(crate) fn has_secret(&self, name: &str) -> bool {
        validate_name(name).is_ok() && self.secret_path(name).exists()
    }

    /// Returns the `.sshare/` metadata directory.
    fn sshare_dir(&self) -> PathBuf {
        self.root.join(VAULT_DIR)
    }

    /// Returns the vault's stable id, read from `.sshare/id` (written once at `init`).
    ///
    /// Never mints one on read: a missing id means corruption or a pre-signing vault, and
    /// silently minting a fresh random id would make each clone diverge (every bound blob
    /// then reads as "another vault" and the signed member set stops matching).
    ///
    /// # Errors
    ///
    /// Returns an error if the id file is missing, unreadable, or not a single printable
    /// token.
    pub(crate) fn vault_id(&self) -> Result<String> {
        let path = self.sshare_dir().join(VAULT_ID_FILE);
        let contents = fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow!(
                    "{} is missing — this vault is corrupt or predates vault ids; \
                     restore it from git history",
                    path.display()
                )
            } else {
                anyhow::Error::new(e).context(format!("cannot read {}", path.display()))
            }
        })?;
        let id = contents.trim().to_owned();
        validate_vault_id(&id).with_context(|| format!("cannot use {}", path.display()))?;
        Ok(id)
    }

    /// The canonical bytes of the member set that get signed: a versioned header, the vault
    /// id, then each `name\0pubkey` (members are already sorted by name).
    ///
    /// # Errors
    ///
    /// Returns an error if the id or members cannot be read.
    pub(crate) fn canonical_members(&self) -> Result<Vec<u8>> {
        let mut out = format!("sshare-members-v1\n{}\n", self.vault_id()?).into_bytes();
        for member in self.members()? {
            out.extend_from_slice(member.name.as_bytes());
            out.push(0);
            out.extend_from_slice(member.pubkey.as_bytes());
            out.push(b'\n');
        }
        Ok(out)
    }

    /// Reads the members-list signature (`.sshare/members.sig`), if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read.
    pub(crate) fn read_members_sig(&self) -> Result<Option<String>> {
        let path = self.sshare_dir().join(MEMBERS_SIG_FILE);
        match fs::read_to_string(&path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    /// Writes the members-list signature to `.sshare/members.sig`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub(crate) fn write_members_sig(&self, armored: &str) -> Result<()> {
        let path = self.sshare_dir().join(MEMBERS_SIG_FILE);
        // Atomic + symlink-guarded: a committer must not be able to redirect this write
        // through a symlinked members.sig to clobber a file outside the vault.
        write_atomic(&self.root, &path, armored.as_bytes())
    }
}

/// Atomically writes `blob` to `path` (which must lie under `root`), creating parent
/// directories as needed.
///
/// The blob is written to a temporary file in the same directory and then renamed over the
/// target, so a reader (or an interrupted run) never observes a half-written file. The write
/// refuses to go through any symlink below `root` — see [`reject_symlinks_under`].
fn write_atomic(root: &Path, path: &Path, blob: &[u8]) -> Result<()> {
    reject_symlinks_under(root, path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Same-directory temp keeps the rename on one filesystem (atomic on Unix); the pid
    // suffix avoids collisions between concurrent writers.
    let tmp = path.with_extension(format!("{SECRET_EXT}.tmp.{}", std::process::id()));
    fs::write(&tmp, blob).with_context(|| format!("cannot write {}", tmp.display()))?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("cannot write {}", path.display()));
    }
    Ok(())
}

/// Refuses to write through a symlink anywhere between `root` and `path` (inclusive).
///
/// Vault contents come from git, so a committer can plant a symlink such as
/// `secrets/prod -> /somewhere/else`; following it would put a secret outside the vault —
/// and silently outside the repo. Lexical name validation cannot see that, only the
/// filesystem can, so every component that already exists below the root is inspected.
fn reject_symlinks_under(root: &Path, path: &Path) -> Result<()> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| anyhow!("internal error: {} is outside the vault", path.display()))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => bail!(
                "refusing to write through symlink {} — remove it from the vault first",
                current.display()
            ),
            Ok(_) => {}
            // Nothing below this point exists yet, so there is nothing left to inspect.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err(e).with_context(|| format!("cannot inspect {}", current.display()));
            }
        }
    }
    Ok(())
}

/// Checks a vault id is one printable token: it is embedded in the signed member set and in
/// every encrypted payload header, where whitespace or control characters would corrupt them.
fn validate_vault_id(id: &str) -> Result<()> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("corrupt vault id — it must be a single printable token");
    }
    Ok(())
}

/// Generates a random 128-bit hex id for a new vault.
fn random_id() -> Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow!("cannot generate a vault id ({e})"))?;
    let mut id = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        id.push(HEX[(b >> 4) as usize] as char);
        id.push(HEX[(b & 0x0f) as usize] as char);
    }
    Ok(id)
}

/// Recursively collects `.age` files under `dir`, naming them relative to `base`.
fn collect_secrets(base: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("cannot inspect {}", path.display()))?;
        // `file_type()` does not follow symlinks. A committed symlink could point anywhere on
        // the reader's disk; whatever it resolves to is not this vault's secret.
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_secrets(base, &path, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some(SECRET_EXT) {
            let relative = path.strip_prefix(base).unwrap_or(&path).with_extension("");
            if let Some(name) = relative.to_str() {
                // Only enumerate names a real `add` could have produced. A committed blob
                // with an out-of-charset name (or terminal-escape bytes) must not wedge
                // rekey with 'invalid secret name' before its legacy-review gate, nor reach
                // the terminal unescaped — report it and skip.
                if validate_name(name).is_ok() {
                    out.push(name.to_owned());
                } else {
                    eprintln!(
                        "warning: ignoring '{}' under secrets/ — not a valid secret name; \
                         remove it from the repo if unexpected",
                        crypto::sanitize_for_display(name)
                    );
                }
            }
        }
    }
    Ok(())
}

/// Validates a single path component (a member name or one secret segment).
fn validate_component(component: &str) -> Result<()> {
    if component.is_empty() || component == "." || component == ".." {
        bail!("'{component}' is not a valid name");
    }
    if !component
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("'{component}' may only contain letters, digits, '-', '_', and '.'");
    }
    Ok(())
}

/// Validates a (possibly nested) secret name, guarding against path traversal.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("secret name cannot be empty");
    }
    if name.starts_with('/') || name.ends_with('/') {
        bail!("secret name '{name}' cannot start or end with '/'");
    }
    for component in name.split('/') {
        validate_component(component).with_context(|| format!("invalid secret name '{name}'"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Vault, validate_name};
    use crate::test_keys;

    #[test]
    fn init_creates_layout_and_rejects_double_init() {
        let dir = tempfile::tempdir().unwrap();
        Vault::init(dir.path()).unwrap();
        assert!(dir.path().join(".sshare/config.toml").is_file());
        assert!(dir.path().join(".sshare/members").is_dir());
        assert!(dir.path().join("secrets").is_dir());
        assert!(Vault::init(dir.path()).is_err());
    }

    #[test]
    fn open_requires_a_vault_at_the_exact_path() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Vault::open(dir.path()).is_err()); // empty dir is not a vault
        Vault::init(dir.path()).unwrap();
        assert!(Vault::open(dir.path()).is_ok());
    }

    #[test]
    fn member_add_list_remove() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        vault.add_member("alice", test_keys::ALICE_PUB).unwrap();
        vault.add_member("mallory", test_keys::MALLORY_PUB).unwrap();

        let members = vault.members().unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name, "alice"); // sorted by name

        vault.remove_member("alice").unwrap();
        assert_eq!(vault.members().unwrap().len(), 1);
        assert!(vault.remove_member("ghost").is_err());
    }

    #[test]
    fn add_member_rejects_invalid_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        assert!(vault.add_member("eve", "not-a-key").is_err());
    }

    #[test]
    fn secrets_are_nested_and_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        vault.write_secret("z-top", b"a").unwrap();
        vault.write_secret("prod/api-token", b"b").unwrap();

        assert_eq!(
            vault.secret_names().unwrap(),
            vec!["prod/api-token".to_owned(), "z-top".to_owned()]
        );
        assert_eq!(vault.read_secret("prod/api-token").unwrap(), b"b");
        assert!(vault.read_secret("missing").is_err());
    }

    #[test]
    fn remove_secret_deletes_and_errors_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        vault.write_secret("tmp", b"x").unwrap();
        assert!(vault.has_secret("tmp"));
        vault.remove_secret("tmp").unwrap();
        assert!(!vault.has_secret("tmp"));
        assert!(vault.remove_secret("tmp").is_err());
    }

    #[test]
    fn description_round_trips_and_is_not_a_secret() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        vault.write_secret("db", b"cipher").unwrap();

        // No description by default.
        assert!(vault.read_description("db").unwrap().is_none());

        // A nested name works and round-trips its (here, opaque) blob.
        vault.write_secret("prod/api", b"cipher2").unwrap();
        vault.write_description("prod/api", b"desc-cipher").unwrap();
        assert_eq!(
            vault.read_description("prod/api").unwrap().unwrap(),
            b"desc-cipher"
        );

        // Descriptions live outside secrets/, so they never show up as secrets.
        assert_eq!(
            vault.secret_names().unwrap(),
            vec!["db".to_owned(), "prod/api".to_owned()]
        );
    }

    #[test]
    fn removing_a_secret_cascades_to_its_description() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        vault.write_secret("db", b"cipher").unwrap();
        vault.write_description("db", b"desc-cipher").unwrap();

        vault.remove_secret("db").unwrap();
        assert!(!vault.has_secret("db"));
        assert!(vault.read_description("db").unwrap().is_none());

        // remove_description is idempotent — removing an absent one is fine.
        vault.remove_description("db").unwrap();
    }

    #[test]
    fn write_secret_overwrites_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        vault.write_secret("api", b"v1").unwrap();
        vault.write_secret("api", b"v2").unwrap(); // atomic overwrite
        assert_eq!(vault.read_secret("api").unwrap(), b"v2");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("secrets"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_name("../escape").is_err());
        assert!(validate_name("/abs").is_err());
        assert!(validate_name("a/../b").is_err());
        assert!(validate_name("ok/nested-name").is_ok());
    }

    #[test]
    fn corrupt_vault_id_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        assert_eq!(vault.vault_id().unwrap().len(), 32);
        std::fs::write(dir.path().join(".sshare/id"), "two words\n").unwrap();
        assert!(vault.vault_id().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_write_through_a_symlinked_directory() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        // What a committer could plant: secrets/prod -> somewhere outside the vault.
        std::os::unix::fs::symlink(&outside, dir.path().join("secrets/prod")).unwrap();

        let msg = vault
            .write_secret("prod/token", b"cipher")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("symlink"), "got: {msg}");
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "the secret escaped the vault"
        );

        // Nor are blobs behind the symlink ever treated as this vault's secrets.
        std::fs::write(outside.join("foreign.age"), b"x").unwrap();
        assert!(vault.secret_names().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_replace_a_symlinked_secret_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        let victim = dir.path().join("victim.age");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("secrets/link.age")).unwrap();

        assert!(vault.write_secret("link", b"cipher").is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }

    #[test]
    fn missing_vault_id_errors_instead_of_minting() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        let id_path = dir.path().join(".sshare/id");
        std::fs::remove_file(&id_path).unwrap();
        // A read must not silently write a fresh id (which would diverge across clones).
        assert!(vault.vault_id().is_err());
        assert!(!id_path.exists(), "vault_id minted a new id on read");
    }

    #[test]
    fn members_ignores_odd_and_ambiguous_files() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        let members = dir.path().join(".sshare/members");
        vault.add_member("alice", test_keys::ALICE_PUB).unwrap();
        // An out-of-charset name, and a key whose bytes carry a newline (which would make
        // the signed `name\0pubkey\n` encoding ambiguous) — both must be skipped.
        std::fs::write(members.join("bad name.pub"), test_keys::MALLORY_PUB).unwrap();
        std::fs::write(
            members.join("sneaky.pub"),
            format!(
                "{}\nmallory\0{}",
                test_keys::ALICE_PUB,
                test_keys::MALLORY_PUB
            ),
        )
        .unwrap();
        // A directory named like a member file must not raise an error either.
        std::fs::create_dir(members.join("adir.pub")).unwrap();

        let names: Vec<_> = vault
            .members()
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert_eq!(names, vec!["alice".to_owned()]);
    }

    #[cfg(unix)]
    #[test]
    fn members_ignores_symlinked_pub_files() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        vault.add_member("alice", test_keys::ALICE_PUB).unwrap();
        let outside = dir.path().join("evil");
        std::fs::write(&outside, test_keys::MALLORY_PUB).unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join(".sshare/members/evil.pub")).unwrap();

        let names: Vec<_> = vault
            .members()
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert_eq!(names, vec!["alice".to_owned()]);
    }

    #[cfg(unix)]
    #[test]
    fn read_refuses_a_symlinked_description() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join(".sshare/descriptions")).unwrap();
        let outside = dir.path().join("secret-note");
        std::fs::write(&outside, b"leak me").unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join(".sshare/descriptions/db.age"))
            .unwrap();
        assert!(vault.read_description("db").is_err());
    }

    #[test]
    fn secret_names_skips_invalid_names() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path()).unwrap();
        vault.write_secret("ok", b"x").unwrap();
        // A committed blob with a name no `add` could produce (a space) must be skipped, not
        // wedge enumeration.
        std::fs::write(dir.path().join("secrets/bad name.age"), b"y").unwrap();
        assert_eq!(vault.secret_names().unwrap(), vec!["ok".to_owned()]);
    }
}
