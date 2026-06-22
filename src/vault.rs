//! On-disk layout of an `sshare` vault: members and encrypted secrets.
//!
//! A vault is any directory containing a `.sshare/` metadata folder:
//!
//! ```text
//! <root>/
//!   .sshare/
//!     config.toml          # marks the vault root
//!     members/<name>.pub   # one SSH public key per member
//!   secrets/<name>.age     # age-encrypted secret blobs
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::crypto;

const VAULT_DIR: &str = ".sshare";
const MEMBERS_DIR: &str = "members";
const SECRETS_DIR: &str = "secrets";
const CONFIG_FILE: &str = "config.toml";
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
        let mut dir = start.as_path();
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

    /// Returns the vault root directory.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    fn members_dir(&self) -> PathBuf {
        self.root.join(VAULT_DIR).join(MEMBERS_DIR)
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
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some(PUBKEY_EXT) {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned();
            let pubkey = fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?
                .trim()
                .to_owned();
            members.push(Member { name, pubkey });
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
        fs::write(&path, format!("{}\n", pubkey.trim()))
            .with_context(|| format!("cannot write {}", path.display()))?;
        Ok(())
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

    /// Writes an encrypted blob for `name`, creating parent directories as needed.
    ///
    /// The write is atomic: the blob is written to a temporary file in the same directory
    /// and then renamed over the target, so a reader (or an interrupted run) never observes
    /// a half-written secret.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is invalid or the file cannot be written.
    pub(crate) fn write_secret(&self, name: &str, blob: &[u8]) -> Result<()> {
        validate_name(name)?;
        let path = self.secret_path(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Same-directory temp keeps the rename on one filesystem (atomic on Unix); the pid
        // suffix avoids collisions between concurrent writers.
        let tmp = path.with_extension(format!("{SECRET_EXT}.tmp.{}", std::process::id()));
        fs::write(&tmp, blob).with_context(|| format!("cannot write {}", tmp.display()))?;
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("cannot write {}", path.display()));
        }
        Ok(())
    }

    /// Reads the encrypted blob for `name`.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is invalid or the secret does not exist.
    pub(crate) fn read_secret(&self, name: &str) -> Result<Vec<u8>> {
        validate_name(name)?;
        let path = self.secret_path(name);
        if !path.exists() {
            bail!("no such secret '{name}'");
        }
        fs::read(&path).with_context(|| format!("cannot read {}", path.display()))
    }
}

/// Recursively collects `.age` files under `dir`, naming them relative to `base`.
fn collect_secrets(base: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
    };
    for entry in entries {
        let path = entry?.path();
        if path.is_dir() {
            collect_secrets(base, &path, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some(SECRET_EXT) {
            let relative = path.strip_prefix(base).unwrap_or(&path).with_extension("");
            if let Some(name) = relative.to_str() {
                out.push(name.to_owned());
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
}
