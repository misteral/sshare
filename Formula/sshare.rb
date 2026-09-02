# This file is regenerated on each release by .github/workflows/release.yml.
class Sshare < Formula
  desc "Share team secrets with SSH keys: encrypt to public keys, decrypt with your private key"
  homepage "https://github.com/misteral/sshare"
  version "0.7.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.7.0/sshare-0.7.0-aarch64-apple-darwin.tar.gz"
      sha256 "e90d078b620783bb31d237dcf189b9bd0f5fc87f4be01a22235ea92172932050"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.7.0/sshare-0.7.0-x86_64-apple-darwin.tar.gz"
      sha256 "4fdf306522d209049bf595fa661f8bcf4f163f72a9e98291a125555b8dc336ab"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/misteral/sshare/releases/download/v0.7.0/sshare-0.7.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "fa28a07a875d5465f27aeea1db4e81fe117cd866e8311629ddd1c4f4b9f27edc"
    end
    on_intel do
      url "https://github.com/misteral/sshare/releases/download/v0.7.0/sshare-0.7.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "c6714d97872e1aae896c9bbf2a85f6ec7b4dccb6f5db25ec4bf1efb4bb5329fa"
    end
  end

  def install
    bin.install "sshare"
  end

  def caveats
    <<~EOS
      sshare 0.7 changed the on-disk secret format: every encrypted blob is now
      bound to its vault, and membership changes are verified before signing.
      Upgrading a team vault from a pre-0.7 version:

        1. Have every member upgrade to 0.7 first. An older client would print the
           new format header along with a secret's value.
        2. In each vault, review and migrate existing secrets:
             sshare git pull
             sshare rekey
           If it stops and lists "legacy" (unbound) blobs, check every name is one
           you expect (remove an unexpected one with: sshare rm NAME), then:
             sshare rekey --migrate-legacy
             sshare git push
        3. A vault that has members but no signature yet needs: sshare member sign

      Fresh install, or already on 0.7.x: nothing to do.
      Details: https://github.com/misteral/sshare/blob/main/CHANGELOG.md
    EOS
  end

  test do
    assert_match "sshare", shell_output("#{bin}/sshare --version")
  end
end
