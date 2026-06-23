//! SSH-key signatures over the member set (SSHSIG) — the **only** module that imports
//! `ssh-key`, mirroring how `crypto.rs` is the sole importer of `age`.
//!
//! A maintainer signs the canonical member set with their SSH private key; verifiers
//! recover the signer's fingerprint to compare against a pinned authority (see `trust.rs`).

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

/// SSHSIG namespace — domain-separates these from any other SSH signature the key makes.
const NAMESPACE: &str = "sshare-members";

/// Signs `message` with the SSH private key at `identity_path`, returning an armored
/// (`-----BEGIN SSH SIGNATURE-----`) detached signature. Prompts on the terminal if the
/// key is passphrase-protected.
///
/// # Errors
///
/// Returns an error if the key cannot be read, parsed, or decrypted, or signing fails.
pub(crate) fn sign(message: &[u8], identity_path: &Path) -> Result<String> {
    let key = load_private_key(identity_path)?;
    let sig = key
        .sign(NAMESPACE, HashAlg::Sha512, message)
        .map_err(|e| anyhow!("failed to sign members list ({e})"))?;
    sig.to_pem(LineEnding::LF)
        .map_err(|e| anyhow!("failed to encode signature ({e})"))
}

/// Verifies an armored SSHSIG over `message` and returns the signer's SHA-256 fingerprint
/// (e.g. `SHA256:…`) — what callers compare against the pinned authority.
///
/// # Errors
///
/// Returns an error if the signature is malformed, in the wrong namespace, or not a valid
/// signature by its embedded key over `message`.
pub(crate) fn verify(message: &[u8], armored_sig: &str) -> Result<String> {
    let sig = SshSig::from_pem(armored_sig.as_bytes())
        .map_err(|e| anyhow!("malformed members signature ({e})"))?;
    if sig.namespace() != NAMESPACE {
        bail!("members signature has an unexpected namespace");
    }
    let signer = PublicKey::new(sig.public_key().clone(), "");
    signer
        .verify(NAMESPACE, message, &sig)
        .map_err(|e| anyhow!("members signature is not valid ({e})"))?;
    Ok(signer.fingerprint(HashAlg::Sha256).to_string())
}

/// Returns the SHA-256 fingerprint of the public half of the SSH key at `identity_path`
/// (does not require a passphrase — the public key is stored in the clear).
///
/// # Errors
///
/// Returns an error if the key cannot be read or parsed.
pub(crate) fn fingerprint_of(identity_path: &Path) -> Result<String> {
    let key = PrivateKey::read_openssh_file(identity_path)
        .with_context(|| format!("cannot read SSH key {}", identity_path.display()))?;
    Ok(key.public_key().fingerprint(HashAlg::Sha256).to_string())
}

/// Reads an SSH private key, decrypting it with a terminal passphrase prompt if needed.
fn load_private_key(identity_path: &Path) -> Result<PrivateKey> {
    let key = PrivateKey::read_openssh_file(identity_path)
        .with_context(|| format!("cannot read SSH key {}", identity_path.display()))?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    let passphrase = rpassword::prompt_password(format!(
        "Enter passphrase for {}: ",
        identity_path.display()
    ))
    .context("failed to read passphrase")?;
    key.decrypt(passphrase)
        .map_err(|_| anyhow!("wrong passphrase for {}", identity_path.display()))
}

#[cfg(test)]
mod tests {
    use super::{fingerprint_of, sign, verify};
    use crate::test_keys;
    use std::io::Write;
    use std::path::PathBuf;

    fn key_file(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        (dir, path)
    }

    #[test]
    fn sign_verify_roundtrip_and_fingerprint() {
        let (_d, key) = key_file(test_keys::ALICE_KEY);
        let sig = sign(b"the members", &key).unwrap();
        let fp = verify(b"the members", &sig).unwrap();
        assert!(fp.starts_with("SHA256:"), "got {fp}");
        assert_eq!(fp, fingerprint_of(&key).unwrap());
    }

    #[test]
    fn tampered_message_fails() {
        let (_d, key) = key_file(test_keys::ALICE_KEY);
        let sig = sign(b"the members", &key).unwrap();
        assert!(verify(b"the MEMBERS", &sig).is_err());
    }

    #[test]
    fn different_signers_have_different_fingerprints() {
        let (_a, alice) = key_file(test_keys::ALICE_KEY);
        let (_m, mallory) = key_file(test_keys::MALLORY_KEY);
        assert_ne!(
            fingerprint_of(&alice).unwrap(),
            fingerprint_of(&mallory).unwrap()
        );
    }

    #[test]
    fn garbage_signature_fails() {
        assert!(verify(b"x", "not a signature").is_err());
    }
}
