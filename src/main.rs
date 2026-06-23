//! `sshare` — share team secrets with SSH keys.
//!
//! Secrets are encrypted to members' SSH public keys (using the `age` format) and
//! stored in a shared git repository. Only a matching SSH private key can decrypt a
//! secret, so access control is exactly "who holds a recipient key".

mod crypto;
mod registry;
mod sign;
#[cfg(test)]
mod test_keys;
mod trust;
mod vault;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};

use crate::registry::Registry;
use crate::trust::TrustStore;
use crate::vault::Vault;

/// Command-line interface for `sshare`.
#[derive(Debug, Parser)]
#[command(name = "sshare", version, about = "Share team secrets with SSH keys.")]
struct Cli {
    /// Use a connected vault by name (see `sshare vaults`) instead of the one in the
    /// current directory. Also read from the `SSHARE_VAULT` environment variable.
    #[arg(long, global = true, value_name = "NAME")]
    vault: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a new vault in the current directory.
    Init,
    /// Connect (register) an existing local vault so you can use it by name from anywhere.
    Connect {
        /// Path to the vault, or a directory inside it (default: the current directory).
        path: Option<PathBuf>,
        /// Name to register it under (default: the vault directory's name).
        #[arg(long)]
        name: Option<String>,
    },
    /// Disconnect (unregister) a vault by name. Does not delete any files.
    Disconnect {
        /// The connected vault's name.
        name: String,
    },
    /// List connected vaults.
    Vaults,
    /// Show or set the trusted signing authority for a vault (TOFU). With no subcommand,
    /// shows the current status.
    Trust {
        #[command(subcommand)]
        action: Option<TrustCommand>,
    },
    /// Manage members (people identified by an SSH public key).
    #[command(subcommand)]
    Member(MemberCommand),
    /// Store or update a secret, encrypting it for all members.
    Add {
        /// Secret name, e.g. `db-prod` or `prod/api-token`.
        name: String,
        /// Read the value from this file instead of stdin.
        #[arg(long, conflicts_with = "value")]
        file: Option<PathBuf>,
        /// Provide the value inline (avoid: visible in shell history).
        #[arg(long)]
        value: Option<String>,
    },
    /// Decrypt a secret and write it to stdout.
    Get {
        /// Secret name to decrypt.
        name: String,
        /// SSH private key to decrypt with (default: your key in ~/.ssh).
        #[arg(long, short)]
        identity: Option<PathBuf>,
    },
    /// List stored secrets.
    Ls,
    /// Re-encrypt every secret for the current member set.
    Rekey {
        /// SSH private key to decrypt existing secrets with.
        #[arg(long, short)]
        identity: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum MemberCommand {
    /// Register a member from an SSH public key.
    Add {
        /// Member name.
        name: String,
        /// Path to an SSH public key, or `-` for stdin (default: your ~/.ssh/*.pub).
        #[arg(long)]
        key: Option<PathBuf>,
        /// SSH private key to sign the updated member list with (default: your ~/.ssh key).
        #[arg(long, short)]
        identity: Option<PathBuf>,
    },
    /// List members.
    Ls,
    /// Remove a member (run `rekey` afterwards to revoke access to existing secrets).
    Rm {
        /// Member name to remove.
        name: String,
        /// SSH private key to sign the updated member list with (default: your ~/.ssh key).
        #[arg(long, short)]
        identity: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum TrustCommand {
    /// Pin (or re-pin) this machine's trusted signing authority for the vault.
    Accept {
        /// Fingerprint to trust (default: the key that signed the current member list).
        fingerprint: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let sel = cli.vault.as_deref();
    match cli.command {
        Command::Init => cmd_init(),
        Command::Connect { path, name } => cmd_connect(path.as_deref(), name),
        Command::Disconnect { name } => cmd_disconnect(&name),
        Command::Vaults => cmd_vaults(),
        Command::Trust { action } => cmd_trust(sel, action),
        Command::Member(MemberCommand::Add {
            name,
            key,
            identity,
        }) => cmd_member_add(sel, &name, key.as_deref(), identity.as_deref()),
        Command::Member(MemberCommand::Ls) => cmd_member_ls(sel),
        Command::Member(MemberCommand::Rm { name, identity }) => {
            cmd_member_rm(sel, &name, identity.as_deref())
        }
        Command::Add { name, file, value } => cmd_add(sel, &name, file.as_deref(), value),
        Command::Get { name, identity } => cmd_get(sel, &name, identity),
        Command::Ls => cmd_ls(sel),
        Command::Rekey { identity } => cmd_rekey(sel, identity),
    }
}

fn cmd_init() -> Result<()> {
    let vault = Vault::init(&std::env::current_dir()?)?;
    let name = default_vault_name(vault.root());
    Registry::load()?.connect(&name, vault.root())?;
    println!(
        "Initialized empty sshare vault in {}",
        vault.root().display()
    );
    println!("Connected as '{name}' — usable from anywhere with --vault {name}.");
    println!("Next steps:");
    println!("  sshare member add <you> --key ~/.ssh/id_ed25519.pub");
    println!("  printf 's3cret' | sshare add my-secret");
    Ok(())
}

fn cmd_connect(path: Option<&Path>, name: Option<String>) -> Result<()> {
    let vault = match path {
        Some(p) => Vault::find_from(p)
            .with_context(|| format!("no sshare vault at or above {}", p.display()))?,
        None => {
            Vault::discover().context("not inside a vault — pass a PATH, or run 'sshare init'")?
        }
    };
    let root = vault.root();
    let name = name.unwrap_or_else(|| default_vault_name(root));
    Registry::load()?.connect(&name, root)?;
    println!("Connected vault '{name}' -> {}", root.display());
    Ok(())
}

fn cmd_disconnect(name: &str) -> Result<()> {
    Registry::load()?.disconnect(name)?;
    println!("Disconnected '{name}'. No files were deleted.");
    Ok(())
}

fn cmd_vaults() -> Result<()> {
    let registry = Registry::load()?;
    let vaults = registry.list();
    if vaults.is_empty() {
        println!("(no connected vaults — run 'sshare connect' in a vault, or 'sshare init')");
        return Ok(());
    }
    let current = Vault::discover()
        .ok()
        .and_then(|v| v.root().canonicalize().ok());
    for vault in vaults {
        let status = if Vault::open(&vault.path).is_err() {
            "missing"
        } else if current.as_deref() == Some(vault.path.as_path()) {
            "current"
        } else {
            "ok"
        };
        println!("{:<20} {status:<8} {}", vault.name, vault.path.display());
    }
    Ok(())
}

fn cmd_trust(selector: Option<&str>, action: Option<TrustCommand>) -> Result<()> {
    if let Some(TrustCommand::Accept { fingerprint }) = action {
        cmd_trust_accept(selector, fingerprint)
    } else {
        cmd_trust_show(selector)
    }
}

fn cmd_trust_show(selector: Option<&str>) -> Result<()> {
    let vault = resolve_vault(selector)?;
    let vault_id = vault.vault_id()?;
    println!("vault id: {vault_id}");
    if let Some(sig) = vault.read_members_sig()? {
        let status = sign::verify(&vault.canonical_members()?, &sig).map_or_else(
            |e| format!("members signature INVALID: {e}"),
            |fp| format!("members signed by: {fp}"),
        );
        println!("{status}");
    } else {
        println!("members are not signed yet");
    }
    if let Some(fp) = TrustStore::load()?.pinned(&vault_id) {
        println!("pinned authority: {fp}");
    } else {
        println!("pinned authority: (none — run 'sshare trust accept')");
    }
    Ok(())
}

fn cmd_trust_accept(selector: Option<&str>, fingerprint: Option<String>) -> Result<()> {
    let vault = resolve_vault(selector)?;
    let vault_id = vault.vault_id()?;
    let fingerprint = if let Some(fp) = fingerprint {
        fp
    } else {
        let sig = vault
            .read_members_sig()?
            .ok_or_else(|| anyhow!("members are not signed yet — nothing to accept"))?;
        sign::verify(&vault.canonical_members()?, &sig)
            .context("the current member-list signature is invalid; refusing to pin it")?
    };
    TrustStore::load()?.pin(&vault_id, &fingerprint)?;
    println!("Pinned signing authority {fingerprint} for this vault.");
    Ok(())
}

/// Signs the current member set with `identity` and ensures this machine pins that key as
/// the vault's authority. The first signer establishes the authority; afterwards only that
/// key may change membership.
fn sign_and_pin_members(vault: &Vault, identity: Option<&Path>) -> Result<()> {
    let identity = resolve_identity(identity.map(Path::to_path_buf))?;
    let my_fp = sign::fingerprint_of(&identity)?;
    let vault_id = vault.vault_id()?;
    let mut trust = TrustStore::load()?;
    match trust.pinned(&vault_id) {
        Some(pinned) if pinned != my_fp => bail!(
            "only this vault's maintainer ({pinned}) can change membership; your key is {my_fp}"
        ),
        Some(_) => {}
        None => trust.pin(&vault_id, &my_fp)?,
    }
    let canonical = vault.canonical_members()?;
    let sig = sign::sign(&canonical, &identity)?;
    vault.write_members_sig(&sig)
}

/// Verifies the vault's member set is signed by this machine's pinned authority. Hard-fails
/// if the list is unsigned, the signature is invalid, or the signer is not the pinned key.
fn verify_members_trusted(vault: &Vault) -> Result<()> {
    let sig = vault.read_members_sig()?.ok_or_else(|| {
        anyhow!(
            "this vault's member list is not signed — a maintainer must sign it (e.g. 'sshare member add')"
        )
    })?;
    let signer = sign::verify(&vault.canonical_members()?, &sig).context(
        "the member list signature is invalid — the members file may have been tampered with",
    )?;
    let vault_id = vault.vault_id()?;
    match TrustStore::load()?.pinned(&vault_id) {
        Some(pinned) if pinned == signer => Ok(()),
        Some(pinned) => bail!(
            "the member list is signed by {signer}, but this vault's pinned authority is {pinned} — possible tampering.\nIf the maintainer key legitimately changed: 'sshare trust accept {signer}'."
        ),
        None => bail!(
            "this vault's signing authority ({signer}) is not yet trusted on this machine.\nVerify it out-of-band, then run 'sshare trust accept {signer}'."
        ),
    }
}

/// Resolves which vault a command should act on.
///
/// Order: `--vault`/`$SSHARE_VAULT` name → the vault in the current directory → the only
/// connected vault → otherwise an error listing the connected vaults.
fn resolve_vault(selector: Option<&str>) -> Result<Vault> {
    let name = selector
        .map(str::to_owned)
        .or_else(|| std::env::var("SSHARE_VAULT").ok())
        .filter(|s| !s.is_empty());

    if let Some(name) = name {
        let registry = Registry::load()?;
        let path = registry
            .path_of(&name)
            .ok_or_else(|| anyhow!("no connected vault named '{name}' — see 'sshare vaults'"))?
            .to_path_buf();
        return Vault::open(&path).with_context(|| {
            format!(
                "vault '{name}' is registered at {} but is missing — reconnect it",
                path.display()
            )
        });
    }

    match Vault::discover() {
        Ok(vault) => Ok(vault),
        Err(discover_err) => {
            let registry = Registry::load()?;
            match registry.list() {
                [] => Err(discover_err),
                [only] => Vault::open(&only.path).with_context(|| {
                    format!(
                        "the only connected vault '{}' is missing at {} — reconnect it",
                        only.name,
                        only.path.display()
                    )
                }),
                many => {
                    let names: Vec<&str> = many.iter().map(|v| v.name.as_str()).collect();
                    bail!(
                        "not inside a vault — pass --vault <name> (connected: {})",
                        names.join(", ")
                    )
                }
            }
        }
    }
}

/// Derives a default registry name from a vault directory, sanitized to the allowed
/// charset (letters, digits, `-`, `_`, `.`), falling back to `vault`.
fn default_vault_name(root: &Path) -> String {
    let raw = root.file_name().and_then(|s| s.to_str()).unwrap_or("vault");
    let sanitized: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches(['-', '.']);
    if trimmed.is_empty() {
        "vault".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn cmd_member_add(
    selector: Option<&str>,
    name: &str,
    key: Option<&Path>,
    identity: Option<&Path>,
) -> Result<()> {
    let vault = resolve_vault(selector)?;
    let pubkey = match key {
        Some(p) if p == Path::new("-") => read_stdin_string()?,
        Some(p) => read_pubkey_file(p)?,
        None => read_pubkey_file(&default_pubkey()?)?,
    };
    vault.add_member(name, pubkey.trim())?;
    sign_and_pin_members(&vault, identity)?;
    println!("Added member '{name}' and re-signed the member list.");
    println!("Run 'sshare rekey' to grant them access to existing secrets.");
    Ok(())
}

fn cmd_member_ls(selector: Option<&str>) -> Result<()> {
    let members = resolve_vault(selector)?.members()?;
    if members.is_empty() {
        println!("(no members yet — add one with 'sshare member add')");
        return Ok(());
    }
    for member in members {
        let mut fields = member.pubkey.split_whitespace();
        let kind = fields.next().unwrap_or("?");
        let comment = fields.nth(1).unwrap_or("");
        println!("{:<24} {kind} {comment}", member.name);
    }
    Ok(())
}

fn cmd_member_rm(selector: Option<&str>, name: &str, identity: Option<&Path>) -> Result<()> {
    let vault = resolve_vault(selector)?;
    vault.remove_member(name)?;
    sign_and_pin_members(&vault, identity)?;
    println!("Removed member '{name}' and re-signed the member list.");
    println!("Run 'sshare rekey' so existing secrets are no longer encrypted to them.");
    println!("Then rotate any secrets they could read — they may already have copies.");
    Ok(())
}

fn cmd_add(
    selector: Option<&str>,
    name: &str,
    file: Option<&Path>,
    value: Option<String>,
) -> Result<()> {
    let vault = resolve_vault(selector)?;
    verify_members_trusted(&vault)?;
    let recipients = vault.recipients()?;
    if recipients.is_empty() {
        bail!("no members yet — add at least one with 'sshare member add' before storing secrets");
    }
    let plaintext = match (file, value) {
        (Some(path), None) => {
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?
        }
        (None, Some(inline)) => inline.into_bytes(),
        (None, None) => read_stdin_bytes()?,
        (Some(_), Some(_)) => unreachable!("clap marks --file and --value as conflicting"),
    };
    let blob = crypto::encrypt(&plaintext, &recipients)?;
    vault.write_secret(name, &blob)?;
    println!(
        "Stored '{name}', encrypted for {} member(s).",
        recipients.len()
    );
    Ok(())
}

fn cmd_get(selector: Option<&str>, name: &str, identity: Option<PathBuf>) -> Result<()> {
    let vault = resolve_vault(selector)?;
    let blob = vault.read_secret(name)?;
    let identity = resolve_identity(identity)?;
    let plaintext = crypto::decrypt(&blob, &identity)?;
    std::io::stdout().write_all(&plaintext)?;
    Ok(())
}

fn cmd_ls(selector: Option<&str>) -> Result<()> {
    let names = resolve_vault(selector)?.secret_names()?;
    if names.is_empty() {
        println!("(no secrets yet — store one with 'sshare add <name>')");
        return Ok(());
    }
    for name in names {
        println!("{name}");
    }
    Ok(())
}

fn cmd_rekey(selector: Option<&str>, identity: Option<PathBuf>) -> Result<()> {
    let vault = resolve_vault(selector)?;
    verify_members_trusted(&vault)?;
    let recipients = vault.recipients()?;
    if recipients.is_empty() {
        bail!("no members — add at least one before re-keying");
    }
    let identity = resolve_identity(identity)?;
    let names = vault.secret_names()?;
    for name in &names {
        let blob = vault.read_secret(name)?;
        let plaintext = crypto::decrypt(&blob, &identity)
            .with_context(|| format!("cannot decrypt '{name}' — is your key still a recipient?"))?;
        let reencrypted = crypto::encrypt(&plaintext, &recipients)?;
        vault.write_secret(name, &reencrypted)?;
    }
    println!(
        "Re-encrypted {} secret(s) for {} member(s).",
        names.len(),
        recipients.len()
    );
    Ok(())
}

/// Resolves the SSH private key to decrypt with, falling back to a default.
fn resolve_identity(identity: Option<PathBuf>) -> Result<PathBuf> {
    match identity {
        Some(path) => Ok(path),
        None => default_identity(),
    }
}

fn read_pubkey_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("cannot read public key {}", path.display()))
}

fn read_stdin_bytes() -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .context("failed to read stdin")?;
    Ok(buf)
}

fn read_stdin_string() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("failed to read stdin")?;
    Ok(buf)
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME environment variable is not set")
}

/// Returns the first existing default SSH private key in `~/.ssh`.
fn default_identity() -> Result<PathBuf> {
    let ssh = home()?.join(".ssh");
    for name in ["id_ed25519", "id_rsa"] {
        let candidate = ssh.join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    bail!("no SSH key found in ~/.ssh (tried id_ed25519, id_rsa) — pass --identity")
}

/// Returns the first existing default SSH public key in `~/.ssh`.
fn default_pubkey() -> Result<PathBuf> {
    let ssh = home()?.join(".ssh");
    for name in ["id_ed25519.pub", "id_rsa.pub"] {
        let candidate = ssh.join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    bail!("no SSH public key found in ~/.ssh — pass --key")
}
