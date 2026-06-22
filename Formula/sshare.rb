# This file is regenerated on each release by .github/workflows/release.yml.
class Sshare < Formula
  desc "Share team secrets with SSH keys: encrypt to public keys, decrypt with your private key"
  homepage "https://github.com/misteral/sshare"
  version "0.1.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.1.1/sshare-0.1.1-aarch64-apple-darwin.tar.gz"
      sha256 "a892528cd0d4198213c9da85c4b3a7b990309fb26f47f03c86aece768de21588"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.1.1/sshare-0.1.1-x86_64-apple-darwin.tar.gz"
      sha256 "e0e823b2ad6f4d3424e73ab32d0fd6ce4b26a5e3dd04cd9011408be41845f1ba"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.1.1/sshare-0.1.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "20ef10dede293838204ef97af98877f8dedd52272385b8fd57c367995477d93b"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.1.1/sshare-0.1.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "1847e7efb55130af568133198aada83c4e8f8abd74a50018aa34a8f82e60884c"
    end
  end

  def install
    bin.install "sshare"
  end

  test do
    assert_match "sshare", shell_output("#{bin}/sshare --version")
  end
end
