# This file is regenerated on each release by .github/workflows/release.yml.
class Sshare < Formula
  desc "Share team secrets with SSH keys: encrypt to public keys, decrypt with your private key"
  homepage "https://github.com/misteral/sshare"
  version "0.1.3"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.1.3/sshare-0.1.3-aarch64-apple-darwin.tar.gz"
      sha256 "0c8a987fbad0976d6a2c6050c536d752fe4d7d90dffe70adc79bb43975d895ba"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.1.3/sshare-0.1.3-x86_64-apple-darwin.tar.gz"
      sha256 "92f4e8f60d3009374415f36370baf6c5f94cc36c55fdaa44a5bb216e2c35dbf1"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.1.3/sshare-0.1.3-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "8ecec848daf28fe526176965c8f9ffc7ee29c4a7194ba3eb20b59f66694f1686"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.1.3/sshare-0.1.3-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "55452f120b9085a3225d8da624cb1da46dbcd187e44de745dcacbdfbe521469b"
    end
  end

  def install
    bin.install "sshare"
  end

  test do
    assert_match "sshare", shell_output("#{bin}/sshare --version")
  end
end
