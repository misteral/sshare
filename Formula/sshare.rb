# This file is regenerated on each release by .github/workflows/release.yml.
class Sshare < Formula
  desc "Share team secrets with SSH keys: encrypt to public keys, decrypt with your private key"
  homepage "https://github.com/misteral/sshare"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.1.0/sshare-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "4d86513f4e2dd231d18e13e7dd34e80f7db12ffde88f50a2ace12cb0b27222a0"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.1.0/sshare-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "b05fd8d3c7917de8bdf3aca0d908057a9cae6d94bc3ab08124070e6a687d9984"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.1.0/sshare-0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "eb7d44b98b54b8d67ed4f0da8477c439375017eb24e4ee167bf73f1a7fe2404f"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.1.0/sshare-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "d538de80ea9313715c7ea4d6f5cf99ccc10093127a5d55cec05a91176248ee42"
    end
  end

  def install
    bin.install "sshare"
  end

  test do
    assert_match "sshare", shell_output("#{bin}/sshare --version")
  end
end
