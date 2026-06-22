# This file is regenerated on each release by .github/workflows/release.yml.
class Sshare < Formula
  desc "Share team secrets with SSH keys: encrypt to public keys, decrypt with your private key"
  homepage "https://github.com/misteral/sshare"
  version "0.1.2"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.1.2/sshare-0.1.2-aarch64-apple-darwin.tar.gz"
      sha256 "4f9fa5fc6d8b96412f98833af4a15ca909fcd1a5561dd71e0246e6310082edf1"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.1.2/sshare-0.1.2-x86_64-apple-darwin.tar.gz"
      sha256 "443619eeaf1e53eb72c9256e0a0735b0b6a3cba96d4a456d906d36b66262b031"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.1.2/sshare-0.1.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0f024b99bd24eb139e215e8656a536c017003cd2631e55f3ea4f3d91d0a46370"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.1.2/sshare-0.1.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "a9201925795830629f412adce1a8de26bdc771728f2e39d2d498402e0d903e7d"
    end
  end

  def install
    bin.install "sshare"
  end

  test do
    assert_match "sshare", shell_output("#{bin}/sshare --version")
  end
end
