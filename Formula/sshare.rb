# This file is regenerated on each release by .github/workflows/release.yml.
# The sha256 values below are placeholders until the first tagged release fills them in.
class Sshare < Formula
  desc "Share team secrets with SSH keys: encrypt to public keys, decrypt with your private key"
  homepage "https://github.com/misteral/sshare"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.1.0/sshare-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.1.0/sshare-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.1.0/sshare-0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.1.0/sshare-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "sshare"
  end

  test do
    assert_match "sshare", shell_output("#{bin}/sshare --version")
  end
end
