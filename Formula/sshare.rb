# This file is regenerated on each release by .github/workflows/release.yml.
class Sshare < Formula
  desc "Share team secrets with SSH keys: encrypt to public keys, decrypt with your private key"
  homepage "https://github.com/misteral/sshare"
  version "0.2.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.2.0/sshare-0.2.0-aarch64-apple-darwin.tar.gz"
      sha256 "8c0744f6cce2fa5fbe61fa824a6a5710e951c26292e632cb342de84e62c5d8ef"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.2.0/sshare-0.2.0-x86_64-apple-darwin.tar.gz"
      sha256 "e8b1252b9bc8a740887143a6f01cef504dc6f6260eadf7d524a07aaa0c2e0eae"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.2.0/sshare-0.2.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "08f0a6abcf1fa718caab587a0d3a1ef12c95f81b29e780a22d41ce656864f6e9"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.2.0/sshare-0.2.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "50c008d981ce3790ab3bd454aba289c0055a08a9d0c1cd0378946c7ada331d68"
    end
  end

  def install
    bin.install "sshare"
  end

  test do
    assert_match "sshare", shell_output("#{bin}/sshare --version")
  end
end
