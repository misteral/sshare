# This file is regenerated on each release by .github/workflows/release.yml.
class Sshare < Formula
  desc "Share team secrets with SSH keys: encrypt to public keys, decrypt with your private key"
  homepage "https://github.com/misteral/sshare"
  version "0.4.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.4.0/sshare-0.4.0-aarch64-apple-darwin.tar.gz"
      sha256 "34dda7e644badff995b398fe95d56ded1a778f57e1ab6760f146d308e0589200"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.4.0/sshare-0.4.0-x86_64-apple-darwin.tar.gz"
      sha256 "9ec43f256d80dac92f72b135f6d966f1a427d729f98d9b8046b3d27ae01e0a47"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.4.0/sshare-0.4.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "e2f829497f280ad48d3a46c25fdb83c4d700bfde6e641bb147953d13d9d50444"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.4.0/sshare-0.4.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "c0269e9221e023b13fa5c7de4483d2bea42159e8c247b5e47f91e8d9d8c7cdb7"
    end
  end

  def install
    bin.install "sshare"
  end

  test do
    assert_match "sshare", shell_output("#{bin}/sshare --version")
  end
end
