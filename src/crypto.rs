//! Encryption and decryption built on the `age` format using SSH keys.
//!
//! A secret is encrypted to one or more SSH public keys (recipients). Only a holder
//! of a matching SSH private key (identity) can decrypt it.
//!
//! Every payload sshare writes is **bound to its vault**: the encrypted bytes start with a
//! small header naming the vault id (`sshare/1\n<vault-id>\n`). `age` has no associated
//! data, so the binding lives inside the ciphertext where nobody can forge it without the
//! plaintext. It exists so that a blob copied in from *another* vault (or any age file
//! encrypted to a member's SSH key) is recognized and refused, rather than decrypted and
//! re-encrypted to this vault's members by `rekey`. Blobs written before 0.7 have no header
//! and decrypt as [`Binding::Legacy`].

use std::fmt::{self, Display};
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

/// Escapes control characters (newlines, carriage returns, ESC, …) so untrusted text — a
/// foreign vault id, a committed secret or member name — cannot inject terminal escape
/// sequences or forge extra lines when printed. Printable characters pass through unchanged.
///
/// Lives here (the lowest layer) so both `vault.rs` and `main.rs` can reuse the one copy.
pub(crate) fn sanitize_for_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Start of a vault-bound payload: `sshare/1\n<vault-id>\n<secret bytes>`.
const BOUND_MAGIC: &[u8] = b"sshare/1\n";

/// Whether a decrypted payload named this vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Binding {
    /// The payload carried this vault's id — it was encrypted here (0.7+).
    Bound,
    /// No header: written before 0.7, or not by sshare at all.
    Legacy,
}

/// A decrypted payload and how it was bound. `Debug` never shows the bytes.
pub(crate) struct Plaintext {
    /// The secret bytes, header stripped.
    pub(crate) bytes: Vec<u8>,
    /// Whether the payload was bound to this vault.
    pub(crate) binding: Binding,
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plaintext")
            .field("len", &self.bytes.len())
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

/// Encrypts `plaintext` for `recipients`, bound to `vault_id`.
///
/// # Errors
///
/// Returns an error if `recipients` is empty, `vault_id` is not a single printable token,
/// or the age stream cannot be written.
pub(crate) fn encrypt(
    plaintext: &[u8],
    vault_id: &str,
    recipients: &[age::ssh::Recipient],
) -> Result<Vec<u8>> {
    if vault_id.is_empty() || !vault_id.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("cannot encrypt: malformed vault id");
    }
    let mut payload = Vec::with_capacity(BOUND_MAGIC.len() + vault_id.len() + 1 + plaintext.len());
    payload.extend_from_slice(BOUND_MAGIC);
    payload.extend_from_slice(vault_id.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(plaintext);
    encrypt_raw(&payload, recipients)
}

/// Encrypts `payload` as-is (no vault header) so that any one of `recipients` can decrypt it.
fn encrypt_raw(payload: &[u8], recipients: &[age::ssh::Recipient]) -> Result<Vec<u8>> {
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
    writer.write_all(payload)?;
    writer.finish().context("failed to finalize age stream")?;
    Ok(encrypted)
}

/// Decrypts an age blob with the SSH private key at `identity_path` and checks its binding.
///
/// A payload bound to a *different* vault is refused: it was not encrypted here, so
/// printing or re-encrypting it could only serve whoever planted it. A payload with no
/// header is returned as [`Binding::Legacy`] and the caller decides whether to accept it.
///
/// Prompts on the terminal if the key is passphrase-protected.
///
/// # Errors
///
/// Returns an error if the key cannot be read or parsed, the key type is unsupported,
/// the blob was not encrypted to this key, or it is bound to another vault.
pub(crate) fn decrypt(
    ciphertext: &[u8],
    vault_id: &str,
    identity_path: &Path,
) -> Result<Plaintext> {
    let payload = decrypt_raw(ciphertext, identity_path)?;
    let Some(rest) = payload.strip_prefix(BOUND_MAGIC) else {
        return Ok(Plaintext {
            bytes: payload,
            binding: Binding::Legacy,
        });
    };
    let Some(newline) = rest.iter().position(|&b| b == b'\n') else {
        bail!("malformed sshare payload header");
    };
    let (found_id, bytes) = (&rest[..newline], &rest[newline + 1..]);
    if found_id != vault_id.as_bytes() {
        // `found_id` is attacker-controlled decrypted plaintext, so cap it and escape control
        // bytes before it reaches the terminal (a real id is 32 hex chars).
        let head = &found_id[..found_id.len().min(64)];
        let ellipsis = if found_id.len() > head.len() {
            "…"
        } else {
            ""
        };
        bail!(
            "this blob is bound to a different vault ({}{ellipsis}) — it was not encrypted here.\n\
             If it was planted, remove it ('sshare rm <name>'); if this vault's id changed \
             legitimately, restore .sshare/id.",
            sanitize_for_display(&String::from_utf8_lossy(head))
        );
    }
    Ok(Plaintext {
        bytes: bytes.to_vec(),
        binding: Binding::Bound,
    })
}

/// Decrypts an age blob to its raw payload (header included, if any).
fn decrypt_raw(ciphertext: &[u8], identity_path: &Path) -> Result<Vec<u8>> {
    let key = std::fs::read(identity_path)
        .with_context(|| format!("cannot open SSH key {}", identity_path.display()))?;
    let identity = age::ssh::Identity::from_buffer(
        BufReader::new(key.as_slice()),
        Some(identity_path.display().to_string()),
    )
    .map_err(|e| unreadable_key_error(identity_path, &key, &e))?;

    if let age::ssh::Identity::Unsupported(kind) = &identity {
        bail!(
            "SSH key {} has an unsupported type ({kind:?}).\n\
             sshare supports ed25519 and rsa keys.",
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

/// Turns a key-parse failure into an actionable error.
///
/// `age` reads only the modern OpenSSH private-key format
/// (`-----BEGIN OPENSSH PRIVATE KEY-----`). The two common ways to hit this are a legacy
/// PEM key (e.g. an ECDSA/DSA key, or an RSA key written with `-m PEM`) and accidentally
/// passing a `.pub` file. Detect those and say what to do instead of surfacing the opaque
/// underlying error.
fn unreadable_key_error(path: &Path, contents: &[u8], source: &impl Display) -> anyhow::Error {
    let text = String::from_utf8_lossy(contents);
    let has_pem_header = text.contains("-----BEGIN") && text.contains("PRIVATE KEY");
    let is_openssh = text.contains("OPENSSH PRIVATE KEY");

    if has_pem_header && !is_openssh {
        anyhow!(
            "SSH key {p} is in a legacy PEM format that sshare cannot read.\n\
             sshare reads ed25519 and rsa keys in the OpenSSH format; convert yours \
             (back it up first):\n    \
             ssh-keygen -p -f {p}\n\
             rsa and ed25519 keys will then work (ecdsa/dsa keys are not supported).",
            p = path.display()
        )
    } else if has_pem_header {
        // OpenSSH-format header but still unparseable: corrupt or truncated.
        anyhow!("cannot parse SSH key {} ({source})", path.display())
    } else {
        anyhow!(
            "cannot read an SSH private key from {} ({source}).\n\
             Pass --identity a private key such as ~/.ssh/id_ed25519, not a .pub file.",
            path.display()
        )
    }
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
    use super::{Binding, decrypt, encrypt, encrypt_raw, parse_recipient};
    use crate::test_keys;
    use std::io::Write;
    use std::path::PathBuf;

    const VAULT: &str = "vault-a";

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
        let blob = encrypt(b"hunter2", VAULT, &[recipient]).unwrap();
        let (_dir, key) = write_key(test_keys::ALICE_KEY);
        let out = decrypt(&blob, VAULT, &key).unwrap();
        assert_eq!(out.bytes, b"hunter2");
        assert_eq!(out.binding, Binding::Bound);
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let recipient = parse_recipient(test_keys::ALICE_PUB).unwrap();
        let blob = encrypt(b"top secret", VAULT, &[recipient]).unwrap();
        let (_dir, key) = write_key(test_keys::MALLORY_KEY);
        assert!(decrypt(&blob, VAULT, &key).is_err());
    }

    #[test]
    fn each_recipient_can_decrypt() {
        let r1 = parse_recipient(test_keys::ALICE_PUB).unwrap();
        let r2 = parse_recipient(test_keys::MALLORY_PUB).unwrap();
        let blob = encrypt(b"shared", VAULT, &[r1, r2]).unwrap();
        let (_d1, k1) = write_key(test_keys::ALICE_KEY);
        let (_d2, k2) = write_key(test_keys::MALLORY_KEY);
        assert_eq!(decrypt(&blob, VAULT, &k1).unwrap().bytes, b"shared");
        assert_eq!(decrypt(&blob, VAULT, &k2).unwrap().bytes, b"shared");
    }

    #[test]
    fn encrypt_requires_recipients() {
        assert!(encrypt(b"x", VAULT, &[]).is_err());
    }

    #[test]
    fn encrypt_rejects_malformed_vault_id() {
        let recipient = parse_recipient(test_keys::ALICE_PUB).unwrap();
        for bad in ["", "a b", "a\nb", "tab\there"] {
            assert!(
                encrypt(b"x", bad, std::slice::from_ref(&recipient)).is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn blob_bound_to_another_vault_is_refused() {
        // The scenario `rekey` must survive: ciphertext from vault A, encrypted to a key that
        // is also a member of vault B, gets copied into B.
        let recipient = parse_recipient(test_keys::ALICE_PUB).unwrap();
        let blob = encrypt(b"prod password", "vault-a", &[recipient]).unwrap();
        let (_dir, key) = write_key(test_keys::ALICE_KEY);
        let msg = decrypt(&blob, "vault-b", &key).unwrap_err().to_string();
        assert!(msg.contains("different vault"), "got: {msg}");
        assert!(msg.contains("vault-a"), "got: {msg}");
        assert!(!msg.contains("prod password"), "leaked plaintext: {msg}");
    }

    #[test]
    fn unbound_blob_decrypts_as_legacy() {
        // A pre-0.7 secret: bare age output with no vault header.
        let recipient = parse_recipient(test_keys::ALICE_PUB).unwrap();
        let blob = encrypt_raw(b"old value", &[recipient]).unwrap();
        let (_dir, key) = write_key(test_keys::ALICE_KEY);
        let out = decrypt(&blob, VAULT, &key).unwrap();
        assert_eq!(out.bytes, b"old value");
        assert_eq!(out.binding, Binding::Legacy);
    }

    #[test]
    fn empty_and_binary_plaintexts_round_trip_exactly() {
        let recipient = parse_recipient(test_keys::ALICE_PUB).unwrap();
        let (_dir, key) = write_key(test_keys::ALICE_KEY);
        for plaintext in [&b""[..], b"\n", b"\0\xff\n\nsshare/1\n"] {
            let blob = encrypt(plaintext, VAULT, std::slice::from_ref(&recipient)).unwrap();
            assert_eq!(decrypt(&blob, VAULT, &key).unwrap().bytes, plaintext);
        }
    }

    #[test]
    fn plaintext_debug_hides_the_bytes() {
        let recipient = parse_recipient(test_keys::ALICE_PUB).unwrap();
        let blob = encrypt(b"hunter2", VAULT, &[recipient]).unwrap();
        let (_dir, key) = write_key(test_keys::ALICE_KEY);
        let shown = format!("{:?}", decrypt(&blob, VAULT, &key).unwrap());
        assert!(
            !shown.contains("hunter2"),
            "Debug leaked the secret: {shown}"
        );
        assert!(shown.contains("Bound"), "got: {shown}");
    }

    #[test]
    fn rejects_invalid_public_key() {
        assert!(parse_recipient("definitely not a key").is_err());
    }

    #[test]
    fn legacy_pem_key_gives_actionable_error() {
        let recipient = parse_recipient(test_keys::ALICE_PUB).unwrap();
        let blob = encrypt(b"x", VAULT, &[recipient]).unwrap();
        let (_dir, key) = write_key(test_keys::ECDSA_PEM_KEY);
        let msg = decrypt(&blob, VAULT, &key).unwrap_err().to_string();
        assert!(msg.contains("legacy PEM"), "got: {msg}");
        assert!(msg.contains("ssh-keygen -p"), "got: {msg}");
    }

    #[test]
    fn public_key_path_gives_actionable_error() {
        // Pointing --identity at a `.pub` file is a common mistake; the error should say so.
        let recipient = parse_recipient(test_keys::ALICE_PUB).unwrap();
        let blob = encrypt(b"x", VAULT, &[recipient]).unwrap();
        let (_dir, key) = write_key(test_keys::ALICE_PUB);
        let msg = decrypt(&blob, VAULT, &key).unwrap_err().to_string();
        assert!(msg.contains(".pub"), "got: {msg}");
        assert!(msg.contains("private key"), "got: {msg}");
    }
}
