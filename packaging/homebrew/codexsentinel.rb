# Homebrew formula for codex-cli, rendered from the template
# packaging/homebrew/codexsentinel.rb in Voskan/codexsentinel by
# scripts/homebrew-formula.sh with the SHA-256 sums from the release's
# checksums.txt. The release workflow commits it to Voskan/homebrew-tap as
# Formula/codexsentinel.rb; change the template, not the tap copy.
class Codexsentinel < Formula
  desc "Security, reliability and supply-chain analyzer for Go code"
  homepage "https://github.com/Voskan/codexsentinel"
  version "@VERSION@"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Voskan/codexsentinel/releases/download/v#{version}/codex-cli-darwin-arm64"
      sha256 "@SHA256_DARWIN_ARM64@"
    end
    on_intel do
      url "https://github.com/Voskan/codexsentinel/releases/download/v#{version}/codex-cli-darwin-amd64"
      sha256 "@SHA256_DARWIN_AMD64@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Voskan/codexsentinel/releases/download/v#{version}/codex-cli-linux-arm64"
      sha256 "@SHA256_LINUX_ARM64@"
    end
    on_intel do
      url "https://github.com/Voskan/codexsentinel/releases/download/v#{version}/codex-cli-linux-amd64"
      sha256 "@SHA256_LINUX_AMD64@"
    end
  end

  livecheck do
    url :stable
    strategy :github_latest
  end

  def install
    os = OS.mac? ? "darwin" : "linux"
    arch = Hardware::CPU.arm? ? "arm64" : "amd64"
    bin.install "codex-cli-#{os}-#{arch}" => "codex-cli"
    generate_completions_from_executable(bin/"codex-cli", "completion")
  end

  test do
    assert_match "CodexSentinel version: v#{version}", shell_output("#{bin}/codex-cli version")
    # Scanning needs a Go toolchain; the rule catalog is compiled in.
    assert_match "sql-injection", shell_output("#{bin}/codex-cli explain sql-injection")
  end
end
