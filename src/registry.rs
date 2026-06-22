//! A global registry of *connected* vaults, so commands can target a vault by name from
//! anywhere instead of relying on the current directory.
//!
//! The registry lives in the user's config directory (`$SSHARE_CONFIG_HOME`, else
//! `$XDG_CONFIG_HOME/sshare`, else `~/.config/sshare`) in a file named `vaults`, with one
//! `name<TAB>absolute-path` line per vault. It stores **only names and local paths** — no
//! secrets, no remotes, no git state. `connect` records an already-present local vault; it
//! never clones or touches the network.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const REGISTRY_FILE: &str = "vaults";

/// A vault the user has connected: a short name and its local path.
#[derive(Debug, Clone)]
pub(crate) struct ConnectedVault {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
}

/// The set of connected vaults, loaded from (and saved back to) the config directory.
#[derive(Debug)]
pub(crate) struct Registry {
    dir: PathBuf,
    vaults: Vec<ConnectedVault>,
}

impl Registry {
    /// Loads the registry from the resolved config directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be resolved or the file cannot be
    /// read (a missing file is not an error — it yields an empty registry).
    pub(crate) fn load() -> Result<Self> {
        Self::load_from(config_dir()?)
    }

    /// Loads the registry from an explicit directory (used by tests).
    ///
    /// # Errors
    ///
    /// Returns an error if the registry file exists but cannot be read.
    pub(crate) fn load_from(dir: PathBuf) -> Result<Self> {
        let path = dir.join(REGISTRY_FILE);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };

        let mut vaults = Vec::new();
        for line in text.lines() {
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((name, p)) = line.split_once('\t') {
                vaults.push(ConnectedVault {
                    name: name.to_owned(),
                    path: PathBuf::from(p),
                });
            }
        }
        Ok(Self { dir, vaults })
    }

    /// Returns the connected vaults, sorted by name.
    pub(crate) fn list(&self) -> &[ConnectedVault] {
        &self.vaults
    }

    /// Returns the path registered under `name`, if any.
    pub(crate) fn path_of(&self, name: &str) -> Option<&Path> {
        self.vaults
            .iter()
            .find(|v| v.name == name)
            .map(|v| v.path.as_path())
    }

    /// Registers `path` under `name`, replacing any existing entry with that name.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is invalid, `path` cannot be canonicalized or is not
    /// representable in the registry file, or the file cannot be written.
    pub(crate) fn connect(&mut self, name: &str, path: &Path) -> Result<()> {
        validate_vault_name(name)?;
        let abs = path
            .canonicalize()
            .with_context(|| format!("cannot resolve path {}", path.display()))?;
        let as_str = abs
            .to_str()
            .with_context(|| format!("vault path {} is not valid UTF-8", abs.display()))?;
        if as_str.contains('\t') || as_str.contains('\n') {
            bail!(
                "vault path {} contains a tab or newline, which cannot be registered",
                abs.display()
            );
        }

        self.vaults.retain(|v| v.name != name);
        self.vaults.push(ConnectedVault {
            name: name.to_owned(),
            path: abs,
        });
        self.vaults.sort_by(|a, b| a.name.cmp(&b.name));
        self.save()
    }

    /// Removes the entry named `name`.
    ///
    /// # Errors
    ///
    /// Returns an error if no such entry exists or the file cannot be written.
    pub(crate) fn disconnect(&mut self, name: &str) -> Result<()> {
        let before = self.vaults.len();
        self.vaults.retain(|v| v.name != name);
        if self.vaults.len() == before {
            bail!("no connected vault named '{name}'");
        }
        self.save()
    }

    /// Writes the registry atomically (temp file + rename).
    fn save(&self) -> Result<()> {
        fs::create_dir_all(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))?;
        let mut out = String::from(
            "# sshare connected vaults — <name>\\t<path> per line. No secrets stored.\n",
        );
        for v in &self.vaults {
            out.push_str(&v.name);
            out.push('\t');
            out.push_str(&v.path.to_string_lossy());
            out.push('\n');
        }
        let path = self.dir.join(REGISTRY_FILE);
        let tmp = self
            .dir
            .join(format!("{REGISTRY_FILE}.tmp.{}", std::process::id()));
        fs::write(&tmp, out.as_bytes())
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("cannot write {}", path.display()));
        }
        Ok(())
    }
}

/// Resolves the config directory: `$SSHARE_CONFIG_HOME`, else `$XDG_CONFIG_HOME/sshare`,
/// else `~/.config/sshare`.
fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("SSHARE_CONFIG_HOME").filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(dir).join("sshare"));
    }
    let home = std::env::var_os("HOME").context("HOME environment variable is not set")?;
    Ok(PathBuf::from(home).join(".config").join("sshare"))
}

/// Validates a vault registry name: non-empty, not `.`/`..`, ASCII alphanumerics plus
/// `-`, `_`, `.` (so it never contains a tab/newline and stays an unambiguous key).
fn validate_vault_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." {
        bail!("'{name}' is not a valid vault name");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("vault name '{name}' may only contain letters, digits, '-', '_', and '.'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Registry;

    #[test]
    fn connect_list_and_lookup_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();

        let mut reg = Registry::load_from(dir.path().to_path_buf()).unwrap();
        reg.connect("team", vault.path()).unwrap();

        // Reload from disk to prove persistence.
        let reg = Registry::load_from(dir.path().to_path_buf()).unwrap();
        assert_eq!(reg.list().len(), 1);
        let canonical = vault.path().canonicalize().unwrap();
        assert_eq!(reg.path_of("team"), Some(canonical.as_path()));
        assert_eq!(reg.path_of("nope"), None);
    }

    #[test]
    fn connect_is_idempotent_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();

        let mut reg = Registry::load_from(dir.path().to_path_buf()).unwrap();
        reg.connect("team", a.path()).unwrap();
        reg.connect("team", b.path()).unwrap(); // same name, new path
        assert_eq!(reg.list().len(), 1);
        assert_eq!(
            reg.path_of("team"),
            Some(b.path().canonicalize().unwrap().as_path())
        );
    }

    #[test]
    fn disconnect_removes_and_errors_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let mut reg = Registry::load_from(dir.path().to_path_buf()).unwrap();
        reg.connect("team", vault.path()).unwrap();
        reg.disconnect("team").unwrap();
        assert!(reg.list().is_empty());
        assert!(reg.disconnect("team").is_err());
    }

    #[test]
    fn rejects_invalid_name() {
        let dir = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let mut reg = Registry::load_from(dir.path().to_path_buf()).unwrap();
        assert!(reg.connect("bad name", vault.path()).is_err());
        assert!(reg.connect("..", vault.path()).is_err());
    }

    #[test]
    fn missing_registry_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::load_from(dir.path().join("nonexistent")).unwrap();
        assert!(reg.list().is_empty());
    }
}
