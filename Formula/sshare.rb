# This file is regenerated on each release by .github/workflows/release.yml.
class Sshare < Formula
  desc "Share team secrets with SSH keys: encrypt to public keys, decrypt with your private key"
  homepage "https://github.com/misteral/sshare"
  version "0.6.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.6.0/sshare-0.6.0-aarch64-apple-darwin.tar.gz"
      sha256 "54e9107402ef47393ee4ea78971b15e2c6da3aa8b6c93d07e6de9d859b2274ab"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.6.0/sshare-0.6.0-x86_64-apple-darwin.tar.gz"
      sha256 "b87be225bb6bb2a19e22d18e1949aa5cdaa70814e0b8ccf63426685290b31424"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.6.0/sshare-0.6.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "ede531cf2f4163431df6bf0d036a6971fc384a6a0d8346d69111fbcdb0b389ac"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.6.0/sshare-0.6.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "69c79b6eeb49d0d29472f6335f90faa6e2c698bbc4c8c00253e20e47ef0a74fc"
    end
  end

  def install
    bin.install "sshare"
  end

  test do
    assert_match "sshare", shell_output("#{bin}/sshare --version")
  end
end
