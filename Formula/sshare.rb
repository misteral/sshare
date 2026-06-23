# This file is regenerated on each release by .github/workflows/release.yml.
class Sshare < Formula
  desc "Share team secrets with SSH keys: encrypt to public keys, decrypt with your private key"
  homepage "https://github.com/misteral/sshare"
  version "0.5.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.5.0/sshare-0.5.0-aarch64-apple-darwin.tar.gz"
      sha256 "a941feeb01a6539d3b908258c78eb2e1352af12a8545ad98fb5fea56d4121fc4"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.5.0/sshare-0.5.0-x86_64-apple-darwin.tar.gz"
      sha256 "519bac32044ac487f27a4c4f742dea0c71dbcf8aa2138277412181fd8ba447ec"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.5.0/sshare-0.5.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "122a90c6c43a3913e1648877f9ea274a59cba4ee4dedc388338b830c9250b2da"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.5.0/sshare-0.5.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "598cfdc6ab85282b36ffaaeaa881386a9b169a42701b65b9b833d2a7e592a074"
    end
  end

  def install
    bin.install "sshare"
  end

  test do
    assert_match "sshare", shell_output("#{bin}/sshare --version")
  end
end
