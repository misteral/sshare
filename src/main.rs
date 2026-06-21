//! `sshare` — share team secrets with SSH keys.
//!
//! Secrets are encrypted to members' SSH public keys (using the `age` format) and
//! stored in a shared git repository. Only a matching SSH private key can decrypt a
//! secret, so access control is exactly "who holds a recipient key".

mod crypto;
#[cfg(test)]
mod test_keys;
mod vault;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use crate::vault::Vault;

/// Command-line interface for `sshare`.
#[derive(Debug, Parser)]
#[command(name = "sshare", version, about = "Share team secrets with SSH keys.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a new vault in the current directory.
    Init,
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
    },
    /// List members.
    Ls,
    /// Remove a member (run `rekey` afterwards to revoke access to existing secrets).
    Rm {
        /// Member name to remove.
        name: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init => cmd_init(),
        Command::Member(MemberCommand::Add { name, key }) => cmd_member_add(&name, key.as_deref()),
        Command::Member(MemberCommand::Ls) => cmd_member_ls(),
        Command::Member(MemberCommand::Rm { name }) => cmd_member_rm(&name),
        Command::Add { name, file, value } => cmd_add(&name, file.as_deref(), value),
        Command::Get { name, identity } => cmd_get(&name, identity),
        Command::Ls => cmd_ls(),
        Command::Rekey { identity } => cmd_rekey(identity),
    }
}

fn cmd_init() -> Result<()> {
    let vault = Vault::init(&std::env::current_dir()?)?;
    println!(
        "Initialized empty sshare vault in {}",
        vault.root().display()
    );
    println!("Next steps:");
    println!("  sshare member add <you> --key ~/.ssh/id_ed25519.pub");
    println!("  printf 's3cret' | sshare add my-secret");
    Ok(())
}

fn cmd_member_add(name: &str, key: Option<&Path>) -> Result<()> {
    let vault = Vault::discover()?;
    let pubkey = match key {
        Some(p) if p == Path::new("-") => read_stdin_string()?,
        Some(p) => read_pubkey_file(p)?,
        None => read_pubkey_file(&default_pubkey()?)?,
    };
    vault.add_member(name, pubkey.trim())?;
    println!("Added member '{name}'.");
    println!("Run 'sshare rekey' to grant them access to existing secrets.");
    Ok(())
}

fn cmd_member_ls() -> Result<()> {
    let members = Vault::discover()?.members()?;
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

fn cmd_member_rm(name: &str) -> Result<()> {
    Vault::discover()?.remove_member(name)?;
    println!("Removed member '{name}'.");
    println!("Run 'sshare rekey' so existing secrets are no longer encrypted to them.");
    println!("Then rotate any secrets they could read — they may already have copies.");
    Ok(())
}

fn cmd_add(name: &str, file: Option<&Path>, value: Option<String>) -> Result<()> {
    let vault = Vault::discover()?;
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

fn cmd_get(name: &str, identity: Option<PathBuf>) -> Result<()> {
    let vault = Vault::discover()?;
    let blob = vault.read_secret(name)?;
    let identity = resolve_identity(identity)?;
    let plaintext = crypto::decrypt(&blob, &identity)?;
    std::io::stdout().write_all(&plaintext)?;
    Ok(())
}

fn cmd_ls() -> Result<()> {
    let names = Vault::discover()?.secret_names()?;
    if names.is_empty() {
        println!("(no secrets yet — store one with 'sshare add <name>')");
        return Ok(());
    }
    for name in names {
        println!("{name}");
    }
    Ok(())
}

fn cmd_rekey(identity: Option<PathBuf>) -> Result<()> {
    let vault = Vault::discover()?;
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
