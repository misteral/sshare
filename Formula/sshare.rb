# This file is regenerated on each release by .github/workflows/release.yml.
class Sshare < Formula
  desc "Share team secrets with SSH keys: encrypt to public keys, decrypt with your private key"
  homepage "https://github.com/misteral/sshare"
  version "0.3.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.3.0/sshare-0.3.0-aarch64-apple-darwin.tar.gz"
      sha256 "091c5a6cecd061bfe13448bdd6a37ffea4043d697a827db068685f956998b685"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.3.0/sshare-0.3.0-x86_64-apple-darwin.tar.gz"
      sha256 "4cacb4e60fc9f3346f84d6b916fce8b5d84cc3e514c2924fc480f0296b2ac891"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.3.0/sshare-0.3.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "ec33085366cef674d37caf961c58a86af3d6aa7d219bb6e270c582c9fb7048b9"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.3.0/sshare-0.3.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "1e16fa4caf1aa7f1d43bb229cad11ede83eee7ea710ce041e6c819890ddce62a"
    end
  end

  def install
    bin.install "sshare"
  end

  test do
    assert_match "sshare", shell_output("#{bin}/sshare --version")
  end
end
