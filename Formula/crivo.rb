# Gerado por scripts/packages.py a cada release; não edite à mão.
class Crivo < Formula
  desc "CLI de acesso a Postgres governado por um arquivo de política"
  homepage "https://github.com/JonathanSantos/crivo"
  version "0.3.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/JonathanSantos/crivo/releases/download/v0.3.0/crivo-macos-arm64"
      sha256 "292ac86b49bc456e38885817333e9aaa6fc93b84eb65e7869399ba8c4d6b7f8f"
    else
      url "https://github.com/JonathanSantos/crivo/releases/download/v0.3.0/crivo-macos-amd64"
      sha256 "57d8775ab39581a3e270273ae149d8dd6c92d7320563e8283a5b01fa6b79668d"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/JonathanSantos/crivo/releases/download/v0.3.0/crivo-linux-arm64"
      sha256 "4ec64ca5f6f65884c00aaa2dbf27d28fa8f624f707f35a7981ac8dae8f3e1a99"
    else
      url "https://github.com/JonathanSantos/crivo/releases/download/v0.3.0/crivo-linux-amd64"
      sha256 "59a6123a43270385a9f6814d0a8a4e2e3dae95a4b143d25732c14f6961fafcb0"
    end
  end

  def install
    bin.install Dir["crivo-*"].first => "crivo"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/crivo version")
  end
end
