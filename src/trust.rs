//! Trust-On-First-Use pin store: maps a vault id to the fingerprint of the SSH key allowed
//! to sign that vault's member list. Lives in the user's config dir, **outside any vault**,
//! so a repo committer cannot tamper with it. See `design-docs/signed-members-list.md`.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::registry::config_dir;

const TRUST_FILE: &str = "trust";

/// Per-user pinned authorities, one `vault-id<TAB>fingerprint` line per vault.
#[derive(Debug)]
pub(crate) struct TrustStore {
    dir: PathBuf,
    pins: Vec<(String, String)>,
}

impl TrustStore {
    /// Loads the pin store from the resolved config directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the config dir cannot be resolved or the file cannot be read.
    pub(crate) fn load() -> Result<Self> {
        Self::load_from(config_dir()?)
    }

    /// Loads the pin store from an explicit directory (used by tests).
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read.
    pub(crate) fn load_from(dir: PathBuf) -> Result<Self> {
        let path = dir.join(TRUST_FILE);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        let mut pins = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((id, fp)) = line.split_once('\t') {
                pins.push((id.to_owned(), fp.to_owned()));
            }
        }
        Ok(Self { dir, pins })
    }

    /// Returns the pinned authority fingerprint for `vault_id`, if any.
    pub(crate) fn pinned(&self, vault_id: &str) -> Option<&str> {
        self.pins
            .iter()
            .find(|(id, _)| id == vault_id)
            .map(|(_, fp)| fp.as_str())
    }

    /// Pins (or re-pins) `vault_id` to `fingerprint`.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be written.
    pub(crate) fn pin(&mut self, vault_id: &str, fingerprint: &str) -> Result<()> {
        self.pins.retain(|(id, _)| id != vault_id);
        self.pins
            .push((vault_id.to_owned(), fingerprint.to_owned()));
        self.pins.sort();
        self.save()
    }

    /// Writes the store atomically (temp file + rename).
    fn save(&self) -> Result<()> {
        fs::create_dir_all(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))?;
        let mut out = String::from(
            "# sshare TOFU trust pins — <vault-id>\\t<authority-fingerprint>. No secrets.\n",
        );
        for (id, fp) in &self.pins {
            out.push_str(id);
            out.push('\t');
            out.push_str(fp);
            out.push('\n');
        }
        let path = self.dir.join(TRUST_FILE);
        let tmp = self
            .dir
            .join(format!("{TRUST_FILE}.tmp.{}", std::process::id()));
        fs::write(&tmp, out.as_bytes())
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("cannot write {}", path.display()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::TrustStore;

    #[test]
    fn pin_lookup_and_repin_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::load_from(dir.path().to_path_buf()).unwrap();
        assert_eq!(store.pinned("vault-a"), None);
        store.pin("vault-a", "SHA256:aaa").unwrap();

        // reload from disk
        let mut store = TrustStore::load_from(dir.path().to_path_buf()).unwrap();
        assert_eq!(store.pinned("vault-a"), Some("SHA256:aaa"));

        store.pin("vault-a", "SHA256:bbb").unwrap(); // re-pin
        let store = TrustStore::load_from(dir.path().to_path_buf()).unwrap();
        assert_eq!(store.pinned("vault-a"), Some("SHA256:bbb"));
        assert_eq!(store.pinned("other"), None);
    }
}
