//! Encryption and decryption built on the `age` format using SSH keys.
//!
//! A secret is encrypted to one or more SSH public keys (recipients). Only a holder
//! of a matching SSH private key (identity) can decrypt it.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::iter;
use std::path::Path;

use age::secrecy::SecretString;
use anyhow::{Context, Result, anyhow, bail};

/// Parses an SSH public key line (e.g. `ssh-ed25519 AAAA... comment`) into a recipient.
///
/// # Errors
///
/// Returns an error if the line is not a supported SSH public key.
pub(crate) fn parse_recipient(pubkey: &str) -> Result<age::ssh::Recipient> {
    pubkey
        .trim()
        .parse::<age::ssh::Recipient>()
        .map_err(|e| anyhow!("unsupported or invalid SSH public key ({e:?})"))
}

/// Encrypts `plaintext` so that any one of `recipients` can decrypt it.
///
/// # Errors
///
/// Returns an error if `recipients` is empty or the age stream cannot be written.
pub(crate) fn encrypt(plaintext: &[u8], recipients: &[age::ssh::Recipient]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        bail!("cannot encrypt: no recipients");
    }
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .context("failed to build encryptor")?;

    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .context("failed to start age stream")?;
    writer.write_all(plaintext)?;
    writer.finish().context("failed to finalize age stream")?;
    Ok(encrypted)
}

/// Decrypts an age blob using the SSH private key at `identity_path`.
///
/// Prompts on the terminal if the key is passphrase-protected.
///
/// # Errors
///
/// Returns an error if the key cannot be read or parsed, the key type is unsupported,
/// or the blob was not encrypted to this key.
pub(crate) fn decrypt(ciphertext: &[u8], identity_path: &Path) -> Result<Vec<u8>> {
    let file = File::open(identity_path)
        .with_context(|| format!("cannot open SSH key {}", identity_path.display()))?;
    let identity = age::ssh::Identity::from_buffer(
        BufReader::new(file),
        Some(identity_path.display().to_string()),
    )
    .with_context(|| format!("cannot parse SSH key {}", identity_path.display()))?;

    if let age::ssh::Identity::Unsupported(kind) = &identity {
        bail!(
            "SSH key {} has an unsupported type ({kind:?})",
            identity_path.display()
        );
    }

    let identity = identity.with_callbacks(PassphrasePrompt);

    let decryptor =
        age::Decryptor::new_buffered(ciphertext).context("not a valid age-encrypted file")?;
    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|e| anyhow!("decryption failed — is your SSH key a recipient? ({e})"))?;

    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

/// Prompts on the terminal for passphrases needed to unlock encrypted SSH keys.
#[derive(Clone, Debug)]
struct PassphrasePrompt;

impl age::Callbacks for PassphrasePrompt {
    fn display_message(&self, message: &str) {
        eprintln!("{message}");
    }

    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, description: &str) -> Option<SecretString> {
        let entered = rpassword::prompt_password(format!("{description}: ")).ok()?;
        Some(SecretString::from(entered))
    }
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt, parse_recipient};
    use crate::test_keys;
    use std::io::Write;
    use std::path::PathBuf;

    fn write_key(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        (dir, path)
    }

    #[test]
    fn round_trip_with_matching_key() {
        let recipient = parse_recipient(test_keys::ALICE_PUB).unwrap();
        let blob = encrypt(b"hunter2", &[recipient]).unwrap();
        let (_dir, key) = write_key(test_keys::ALICE_KEY);
        assert_eq!(decrypt(&blob, &key).unwrap(), b"hunter2");
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let recipient = parse_recipient(test_keys::ALICE_PUB).unwrap();
        let blob = encrypt(b"top secret", &[recipient]).unwrap();
        let (_dir, key) = write_key(test_keys::MALLORY_KEY);
        assert!(decrypt(&blob, &key).is_err());
    }

    #[test]
    fn each_recipient_can_decrypt() {
        let r1 = parse_recipient(test_keys::ALICE_PUB).unwrap();
        let r2 = parse_recipient(test_keys::MALLORY_PUB).unwrap();
        let blob = encrypt(b"shared", &[r1, r2]).unwrap();
        let (_d1, k1) = write_key(test_keys::ALICE_KEY);
        let (_d2, k2) = write_key(test_keys::MALLORY_KEY);
        assert_eq!(decrypt(&blob, &k1).unwrap(), b"shared");
        assert_eq!(decrypt(&blob, &k2).unwrap(), b"shared");
    }

    #[test]
    fn encrypt_requires_recipients() {
        assert!(encrypt(b"x", &[]).is_err());
    }

    #[test]
    fn rejects_invalid_public_key() {
        assert!(parse_recipient("definitely not a key").is_err());
    }
}
